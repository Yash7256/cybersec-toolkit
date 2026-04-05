import asyncio
import time
from typing import AsyncGenerator, Optional
from dataclasses import dataclass

try:
    from groq import AsyncGroq, RateLimitError as GroqRateLimitError
except ImportError:
    GroqRateLimitError = Exception
    AsyncGroq = None

try:
    import google.generativeai as genai
    GoogleGenAI = genai
except ImportError:
    GoogleGenAI = None

from cybersec.config import settings
from cybersec.core.ai.groq_key_manager import groq_key_manager


@dataclass
class ProviderStats:
    name: str
    status: str = "active"
    failed_at: Optional[float] = None
    total_requests: int = 0
    success_count: int = 0
    fail_count: int = 0
    last_used: Optional[float] = None
    cooldown_seconds: int = 60


class MultiProviderAIClient:
    COOLDOWN_SECONDS = 60

    def __init__(self):
        self.providers = self._init_providers()
        self._provider_stats: dict[str, ProviderStats] = {}
        self._request_lock = asyncio.Lock()
        self._global_cooldown_until: float = 0

        for provider in self.providers:
            self._provider_stats[provider["name"]] = ProviderStats(name=provider["name"])

        print(f"\n[AI] Multi-Provider Client initialized:")
        for p in self.providers:
            print(f"  - {p['name']} (priority {p['priority']})")

    def _init_providers(self) -> list[dict]:
        providers = []
        if groq_key_manager.keys:
            providers.append({"name": "groq", "priority": 1, "keys": groq_key_manager.keys})
        if settings.GEMINI_API_KEY:
            providers.append({"name": "gemini", "priority": 2, "key": settings.GEMINI_API_KEY})
        return sorted(providers, key=lambda x: x["priority"])

    def _is_cooldown(self, provider: str) -> tuple[bool, int]:
        stats = self._provider_stats.get(provider)
        if not stats:
            return False, 0
        if stats.status == "active":
            return False, 0
        if stats.failed_at:
            elapsed = time.time() - stats.failed_at
            if elapsed < self.COOLDOWN_SECONDS:
                return True, int(self.COOLDOWN_SECONDS - elapsed)
            stats.status = "active"
            stats.failed_at = None
            print(f"[AI] {provider} recovered from cooldown")
        return False, 0

    def _mark_failed(self, provider: str):
        stats = self._provider_stats.get(provider)
        if stats and stats.status != "invalid":
            stats.status = "rate_limited"
            stats.failed_at = time.time()
            stats.fail_count += 1
            print(f"[AI] {provider} marked as rate limited")

    def _mark_invalid(self, provider: str):
        stats = self._provider_stats.get(provider)
        if stats:
            stats.status = "invalid"
            stats.failed_at = None
            stats.fail_count += 1
            print(f"[AI] {provider} marked as INVALID - removing from rotation")

    def _mark_success(self, provider: str):
        stats = self._provider_stats.get(provider)
        if stats:
            stats.status = "active"
            stats.success_count += 1
            stats.failed_at = None

    def get_next_provider(self) -> Optional[dict]:
        for provider in self.providers:
            name = provider["name"]
            in_cooldown, remaining = self._is_cooldown(name)
            if not in_cooldown:
                stats = self._provider_stats[name]
                stats.total_requests += 1
                stats.last_used = time.time()
                return provider
        return None

    async def stream_chat(
        self,
        messages: list[dict],
        system_prompt: str,
        response_format: dict | None = None
    ) -> AsyncGenerator[str, None]:
        async with self._request_lock:
            if self._global_cooldown_until and time.time() < self._global_cooldown_until:
                remaining = int(self._global_cooldown_until - time.time())
                print(f"[AI] Global cooldown active ({remaining}s) - waiting...")
                for i in range(remaining, 0, -10):
                    yield f"[AI] Rate limited. Cooldown: {i}s remaining...\n"
                    await asyncio.sleep(min(10, i))
                yield "\n[AI] Retrying now...\n"

            full_messages = [{"role": "system", "content": system_prompt}] + messages
            last_error = None

            for attempt in range(3):
                provider = self.get_next_provider()
                if not provider:
                    print("[AI] All providers are rate limited")
                    self._global_cooldown_until = time.time() + self.COOLDOWN_SECONDS
                    yield "[AI] All AI providers are currently rate limited. Please wait 60 seconds and try again."
                    return

                provider_name = provider["name"]
                print(f"[AI] Attempt {attempt + 1} using {provider_name}")

                try:
                    if provider_name == "groq":
                        async for token in self._stream_groq(full_messages, response_format):
                            yield token
                        self._mark_success(provider_name)
                        return

                    elif provider_name == "gemini":
                        async for token in self._stream_gemini(full_messages):
                            yield token
                        self._mark_success(provider_name)
                        return

                except Exception as e:
                    error_msg = str(e)
                    print(f"[AI] {provider_name} failed: {error_msg}")
                    
                    # Check for invalid API key (401)
                    if "401" in error_msg or "invalid" in error_msg.lower() or "authentication" in error_msg.lower():
                        self._mark_invalid(provider_name)
                    else:
                        self._mark_failed(provider_name)
                    
                    last_error = error_msg

                    if attempt < 2:
                        await asyncio.sleep(1)

            self._global_cooldown_until = time.time() + self.COOLDOWN_SECONDS
            yield f"[AI] All providers failed. Last error: {last_error}"

    async def _stream_groq(
        self,
        messages: list[dict],
        response_format: dict | None = None
    ) -> AsyncGenerator[str, None]:
        args = {
            "model": settings.GROQ_MODEL or "llama-3.3-70b-versatile",
            "messages": messages,
            "temperature": 0.3,
            "max_tokens": 2048,
            "stream": True
        }
        if response_format:
            args["response_format"] = response_format

        key, stats = groq_key_manager.get_key()
        client = AsyncGroq(api_key=key)

        try:
            stream = await client.chat.completions.create(**args)
            async for chunk in stream:
                token = chunk.choices[0].delta.content
                if token:
                    yield token
        finally:
            groq_key_manager.mark_success(key)

    async def _stream_gemini(
        self,
        messages: list[dict]
    ) -> AsyncGenerator[str, None]:
        if not GoogleGenAI:
            raise Exception("Google GenerativeAI SDK not installed. Run: pip install google-generativeai")

        system_content = None
        user_messages = []
        for msg in messages:
            if msg["role"] == "system":
                system_content = msg["content"]
            else:
                user_messages.append(msg)

        GoogleGenAI.configure(api_key=settings.GEMINI_API_KEY)
        model = GoogleGenAI.GenerativeModel(settings.GEMINI_MODEL or "gemini-2.0-flash")
        
        prompt_parts = []
        if system_content:
            prompt_parts.append(system_content)
        for msg in user_messages:
            prompt_parts.append(msg["content"])
        
        try:
            response = model.generate_content(
                "\n".join(prompt_parts),
                generation_config=GoogleGenAI.types.GenerationConfig(
                    max_output_tokens=2048,
                    temperature=0.3
                ),
                stream=True
            )
            for chunk in response:
                if hasattr(chunk, 'text') and chunk.text:
                    yield chunk.text
        except Exception as e:
            raise Exception(f"Gemini API error: {str(e)}")

    async def chat(
        self,
        messages: list[dict],
        system_prompt: str,
        response_format: dict | None = None
    ) -> str:
        tokens = []
        async for token in self.stream_chat(messages, system_prompt, response_format):
            tokens.append(token)
        return "".join(tokens)

    def get_status(self) -> dict:
        return {
            "providers": [
                {
                    "name": p["name"],
                    "available": True,
                    **self._provider_stats[p["name"]].__dict__
                }
                for p in self.providers
            ],
            "global_cooldown": max(0, int(self._global_cooldown_until - time.time())) if self._global_cooldown_until > time.time() else 0
        }


ai_client = MultiProviderAIClient()
groq_client = ai_client
