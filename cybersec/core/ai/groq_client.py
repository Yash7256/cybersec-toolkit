import asyncio
import logging
from typing import AsyncGenerator, Callable

import groq
from groq import Groq

from cybersec.config import get_settings

logger = logging.getLogger(__name__)


class GroqAIClient:
    def __init__(self) -> None:
        settings = get_settings()
        api_key = settings.groq.api_key or ""

        if not api_key:
            raise ValueError("Groq API key not configured")

        self.client = Groq(api_key=api_key)
        self.model = settings.groq.model or "llama-3.3-70b-versatile"

    async def stream_chat(
        self,
        messages: list[dict],
        system_prompt: str,
        on_token: Callable[[str], None],
    ) -> AsyncGenerator[str, None]:
        all_messages = [{"role": "system", "content": system_prompt}]
        all_messages.extend(messages)

        try:
            stream = self.client.chat.completions.create(
                model=self.model,
                messages=all_messages,
                temperature=0.3,
                max_tokens=2048,
                stream=True,
            )

            for chunk in stream:
                if chunk.choices and chunk.choices[0].delta.content:
                    token = chunk.choices[0].delta.content
                    on_token(token)
                    yield token

        except groq.RateLimitError as e:
            logger.warning(f"Rate limit hit, retrying after 60s: {e}")
            await asyncio.sleep(60)

            stream = self.client.chat.completions.create(
                model=self.model,
                messages=all_messages,
                temperature=0.3,
                max_tokens=2048,
                stream=True,
            )

            for chunk in stream:
                if chunk.choices and chunk.choices[0].delta.content:
                    token = chunk.choices[0].delta.content
                    on_token(token)
                    yield token

        except groq.APIError as e:
            logger.error(f"Groq API error: {e}")
            raise ValueError(f"AI service error: {str(e)}")

        except Exception as e:
            logger.error(f"Unexpected error in stream_chat: {e}")
            raise ValueError(f"AI streaming failed: {str(e)}")

    async def chat(
        self,
        messages: list[dict],
        system_prompt: str,
    ) -> str:
        full_response = ""

        async def capture_token(token: str) -> None:
            nonlocal full_response
            full_response += token

        async for token in self.stream_chat(messages, system_prompt, capture_token):
            pass

        return full_response
