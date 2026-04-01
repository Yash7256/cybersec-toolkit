from typing import Any, Dict, Optional
from uuid import UUID

from fastapi import APIRouter, HTTPException, status
from fastapi.responses import StreamingResponse
from groq import RateLimitError, APIError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cybersec.api.deps import DBSession, OptionalUser
from cybersec.core.ai import (
    GroqAIClient,
    ContextBuilder,
    SCAN_ANALYST_PROMPT,
    SSL_ANALYST_PROMPT,
    DNS_ANALYST_PROMPT,
    HTTP_HEADERS_ANALYST_PROMPT,
    SUBDOMAIN_ANALYST_PROMPT,
    GENERIC_TOOL_ANALYST_PROMPT,
    CHAT_PROMPT,
)
from cybersec.database.models import Scan, ScanResult, ToolResult

router = APIRouter(prefix="/ai", tags=["ai"])


class ChatRequest(Dict[str, Any]):
    message: str
    scan_id: Optional[str] = None
    tool_name: Optional[str] = None
    tool_result_id: Optional[str] = None
    conversation_history: list[Dict[str, str]] = []


async def fetch_scan_context(
    scan_id: str,
    db: AsyncSession,
) -> tuple[Dict[str, Any], str]:
    try:
        scan_uuid = UUID(scan_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid scan ID format",
        )

    result = await db.execute(select(Scan).where(Scan.id == scan_uuid))
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found",
        )

    scan_dict = {
        "id": str(scan.id),
        "target": scan.target,
        "scan_type": scan.scan_type,
        "status": scan.status,
        "created_at": scan.created_at.isoformat() if scan.created_at else None,
        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
        "scan_duration": None,
    }

    if scan.started_at and scan.completed_at:
        duration = (scan.completed_at - scan.started_at).total_seconds()
        scan_dict["scan_duration"] = duration

    results_result = await db.execute(
        select(ScanResult).where(ScanResult.scan_id == scan_uuid)
    )
    results = results_result.scalars().all()

    results_list = []
    for r in results:
        results_list.append({
            "id": str(r.id),
            "port": r.port,
            "protocol": r.protocol,
            "state": r.state,
            "service": r.service,
            "version": r.version,
            "banner": r.banner,
            "cves": r.cves,
            "risk_score": 0.0,
        })

    context_builder = ContextBuilder()
    context = context_builder.build_scan_context(scan_dict, results_list)

    return scan_dict, context


async def fetch_tool_context(
    tool_result_id: str,
    db: AsyncSession,
) -> tuple[str, str, str]:
    try:
        result_uuid = UUID(tool_result_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid tool result ID format",
        )

    result = await db.execute(select(ToolResult).where(ToolResult.id == result_uuid))
    tool_result = result.scalar_one_or_none()

    if not tool_result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Tool result not found",
        )

    context_builder = ContextBuilder()
    context = context_builder.build_tool_context(
        tool_result.tool_name,
        tool_result.result_data or {},
    )

    return tool_result.tool_name, context


@router.post("/chat")
async def chat(
    request: ChatRequest,
    db: DBSession,
    current_user: OptionalUser,
) -> StreamingResponse:
    from cybersec.config import get_settings
    settings = get_settings()

    if not settings.groq.api_key:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="AI features not configured. Set GROQ_API_KEY in .env",
        )

    scan_context = ""
    tool_context = ""
    system_prompt = CHAT_PROMPT

    if request.scan_id:
        try:
            _, scan_context = await fetch_scan_context(request.scan_id, db)
            system_prompt = SCAN_ANALYST_PROMPT
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to fetch scan data: {str(e)}",
            )

    if request.tool_result_id:
        try:
            tool_name, tool_context = await fetch_tool_context(request.tool_result_id, db)
            if tool_name == "ssl":
                system_prompt = SSL_ANALYST_PROMPT
            elif tool_name == "dns":
                system_prompt = DNS_ANALYST_PROMPT
            elif tool_name == "http_headers":
                system_prompt = HTTP_HEADERS_ANALYST_PROMPT
            elif tool_name == "subdomain":
                system_prompt = SUBDOMAIN_ANALYST_PROMPT
            else:
                system_prompt = GENERIC_TOOL_ANALYST_PROMPT
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to fetch tool result: {str(e)}",
            )

    if scan_context and tool_context:
        combined_context = f"{scan_context}\n\n{tool_context}"
    elif scan_context:
        combined_context = scan_context
    elif tool_context:
        combined_context = tool_context
    else:
        combined_context = ""

    conversation_history = request.conversation_history or []
    _ = combined_context
    current_message = request.message

    async def generate():
        try:
            client = GroqAIClient()

            messages = []
            for msg in conversation_history:
                messages.append({
                    "role": msg.get("role", "user"),
                    "content": msg.get("content", ""),
                })
            messages.append({"role": "user", "content": current_message})

            def on_token(token: str) -> None:
                pass

            async for token in client.stream_chat(messages, system_prompt, on_token):
                yield f"data: {token}\n\n"

            yield "data: [DONE]\n\n"

        except RateLimitError:
            yield "data: Error: Rate limit exceeded. Please wait and try again.\n\n"
            yield "data: [DONE]\n\n"
        except APIError as e:
            yield f"data: Error: AI service error - {str(e)}\n\n"
            yield "data: [DONE]\n\n"
        except ValueError as e:
            yield f"data: Error: {str(e)}\n\n"
            yield "data: [DONE]\n\n"
        except Exception as e:
            yield f"data: Error: Unexpected error - {str(e)}\n\n"
            yield "data: [DONE]\n\n"

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
    )


@router.post("/analyze")
async def analyze_scan(
    scan_id: str,
    db: DBSession,
    current_user: OptionalUser,
) -> Dict[str, Any]:
    from cybersec.config import get_settings
    settings = get_settings()

    if not settings.groq.api_key:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="AI features not configured. Set GROQ_API_KEY in .env",
        )

    scan_dict, context = await fetch_scan_context(scan_id, db)

    client = GroqAIClient()

    messages = [
        {
            "role": "user",
            "content": f"Analyse this scan data and provide security insights:\n\n{context}",
        }
    ]

    try:
        response = await client.chat(
            messages=messages,
            system_prompt=SCAN_ANALYST_PROMPT,
        )

        return {
            "analysis": response,
            "model": settings.groq.model,
            "scan_id": scan_id,
        }

    except RateLimitError:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded. Please wait and try again.",
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e),
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"AI analysis failed: {str(e)}",
        )


@router.get("/models")
async def list_models(
    current_user: OptionalUser,
) -> Dict[str, Any]:
    from cybersec.config import get_settings
    settings = get_settings()

    if not settings.groq.api_key:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Groq API key not configured",
        )

    available_models = [
        "llama-3.3-70b-versatile",
        "llama-3.1-8b-instant",
        "mixtral-8x7b-32768",
        "gemma2-9b-it",
    ]

    return {
        "current_model": settings.groq.model,
        "available_models": available_models,
    }
