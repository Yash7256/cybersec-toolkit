from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from pydantic import BaseModel, Field
from uuid import UUID
import json

from cybersec.database.models import Scan, ScanResult, ToolResult, User
from cybersec.apps.api.deps import get_db, get_current_user
from cybersec.apps.api.tier import check_and_increment_usage
from cybersec.config import settings

from cybersec.integrations.ai.prompts import SCAN_ANALYST_PROMPT
from cybersec.integrations.ai.context_builder import build_scan_context, build_tool_context, select_system_prompt
from cybersec.integrations.ai.groq_client import groq_client
from cybersec.integrations.ai.groq_key_manager import groq_key_manager

router = APIRouter()


class AIChatRequest(BaseModel):
    message: str = Field(min_length=1, max_length=4000)
    scan_id: UUID | None = None
    tool_result_id: UUID | None = None
    tool_result_ids: list[UUID] | None = None
    # Cap history at 50 turns to prevent prompt-injection amplification
    # and runaway Groq API costs from arbitrarily long histories.
    conversation_history: list[dict[str, str]] = Field(default_factory=list, max_length=50)


class AIAnalyzeRequest(BaseModel):
    scan_id: UUID


def _check_groq_keys():
    if not groq_key_manager.keys:
        raise HTTPException(
            status_code=503,
            detail="AI features require at least one GROQ_API_KEY to be configured",
        )


@router.post("/chat")
async def chat(
    body: AIChatRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    _check_groq_keys()
    await check_and_increment_usage(current_user, db, tool_name="ai_chat")

    contexts: list[str] = []
    tool_name = None

    if body.scan_id:
        scan = await db.get(Scan, body.scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        if scan.user_id and str(scan.user_id) != str(current_user.id):
            raise HTTPException(status_code=403, detail="Access denied")
        results = await db.execute(
            select(ScanResult).where(ScanResult.scan_id == body.scan_id)
        )
        contexts.append(build_scan_context(scan, list(results.scalars().all())))

    if body.tool_result_id:
        tool_result = await db.get(ToolResult, body.tool_result_id)
        if not tool_result:
            raise HTTPException(status_code=404, detail="Tool result not found")
        if tool_result.user_id and str(tool_result.user_id) != str(current_user.id):
            raise HTTPException(status_code=403, detail="Access denied")
        tool_name = tool_result.tool_name
        contexts.append(build_tool_context(tool_name, tool_result.result_data))

    if body.tool_result_ids:
        rows = (
            await db.execute(
                select(ToolResult).where(ToolResult.id.in_(body.tool_result_ids))
            )
        ).scalars().all()
        if not rows:
            raise HTTPException(status_code=404, detail="Tool results not found")
        for tr in rows:
            if tr.user_id and str(tr.user_id) != str(current_user.id):
                raise HTTPException(status_code=403, detail="Access denied")
            contexts.append(build_tool_context(tr.tool_name, tr.result_data))
        tool_name = "multiple_tools"

    context = "\n\n".join(contexts)
    system_prompt = select_system_prompt(tool_name, has_scan=bool(body.scan_id))

    messages = list(body.conversation_history)
    user_content = body.message
    if context:
        user_content = f"{context}\n\nUser question: {body.message}"
    messages.append({"role": "user", "content": user_content})

    async def generate():
        async for token in groq_client.stream_chat(messages, system_prompt):
            if token is not None:
                yield f"data: {token}\n\n"
        yield "data: [DONE]\n\n"

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-store, must-revalidate",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
            "Transfer-Encoding": "chunked",
        },
    )


@router.post("/analyze")
async def analyze(
    body: AIAnalyzeRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    _check_groq_keys()
    await check_and_increment_usage(current_user, db, tool_name="ai_analyze")

    scan = await db.get(Scan, body.scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.user_id and str(scan.user_id) != str(current_user.id):
        raise HTTPException(status_code=403, detail="Access denied")

    results = await db.execute(
        select(ScanResult).where(ScanResult.scan_id == body.scan_id)
    )
    scan_results = list(results.scalars().all())
    context = build_scan_context(scan, scan_results)

    messages = [
        {
            "role": "user",
            "content": (
                f"{context}\n\nPlease provide a comprehensive security analysis. "
                "You MUST output ONLY valid JSON matching the exact schema requested "
                "in system instructions. Do not include markdown blocks or any "
                "conversational text. Just raw JSON."
            ),
        }
    ]

    try:
        analysis = await groq_client.chat(
            messages,
            SCAN_ANALYST_PROMPT,
            response_format={"type": "json_object"},
        )
    except Exception as e:
        print(f"[AI] AI analysis failed: {e}, falling back to rule-based analysis")
        scan_data = {
            "target": scan.target,
            "open_ports": [
                {"port": r.port, "service": {"name": r.service or "unknown"}}
                for r in scan_results
            ],
        }
        analysis = groq_client._rule_engine.analyze_scan(scan_data)
        analysis = json.dumps(analysis)

    return {"scan_id": str(body.scan_id), "analysis": analysis}


@router.get("/models")
async def get_models():
    _check_groq_keys()
    return {
        "models": [
            {"id": "llama-3.3-70b-versatile", "name": "Llama 3.3 70B", "default": True},
            {"id": "llama-3.1-8b-instant", "name": "Llama 3.1 8B Instant", "default": False},
            {"id": "mixtral-8x7b-32768", "name": "Mixtral 8x7B", "default": False},
        ]
    }


@router.get("/groq-status")
async def get_groq_status():
    if not settings.APP_DEBUG:
        return {"error": "Dev only endpoint"}
    return groq_key_manager.get_status()
