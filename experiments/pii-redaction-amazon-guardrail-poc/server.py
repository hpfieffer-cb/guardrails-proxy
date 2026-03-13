"""
PII Redaction WebSocket Proxy — Bedrock Guardrails v1.1
========================================================
Intended to sit between the client and OpenAI's Realtime API over WebSocket.
Uses AWS Bedrock Guardrails for both prompt injection detection and PII
anonymization in a single API call.

"""

import os
import ssl
import json
import asyncio
import logging
from contextlib import asynccontextmanager

import certifi
import websockets
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from dotenv import load_dotenv

from guardrail_client import GuardrailClient, PlaceholderRestorer

# =============================================================================
# Config
# =============================================================================

load_dotenv()

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
OPENAI_REALTIME_URL = "wss://api.openai.com/v1/realtime"
OPENAI_MODEL = "gpt-4o-realtime-preview"
HOST = os.getenv("HOST", "0.0.0.0")
PORT = int(os.getenv("PORT", "8000"))
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
DRY_RUN = os.getenv("DRY_RUN", "false").lower() in ("true", "1", "yes")

# AWS Bedrock Guardrails config
GUARDRAIL_ID = os.getenv("GUARDRAIL_ID", "")
GUARDRAIL_VERSION = os.getenv("GUARDRAIL_VERSION", "DRAFT")
AWS_REGION = os.getenv("AWS_REGION", "us-east-1")
AWS_PROFILE = os.getenv("AWS_PROFILE", None)

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL),
    format="%(asctime)s | %(name)s | %(levelname)s | %(message)s",
)
logger = logging.getLogger("proxy")

# =============================================================================
# Globals
# =============================================================================

guardrail: GuardrailClient | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize Bedrock Guardrails client at startup."""
    global guardrail

    if GUARDRAIL_ID:
        logger.info(f"Initializing Bedrock Guardrails client | id={GUARDRAIL_ID}")
        guardrail = GuardrailClient(
            guardrail_id=GUARDRAIL_ID,
            guardrail_version=GUARDRAIL_VERSION,
            region=AWS_REGION,
            profile_name=AWS_PROFILE,
        )
    else:
        logger.warning("No GUARDRAIL_ID set — running without Bedrock Guardrails")

    if DRY_RUN:
        logger.info("DRY RUN MODE — messages processed but NOT forwarded to OpenAI")

    logger.info("Server ready.")
    yield
    logger.info("Shutting down.")


app = FastAPI(
    title="PII Redaction Proxy (Bedrock Guardrails)",
    description="WebSocket proxy using AWS Bedrock Guardrails for PII and injection protection",
    lifespan=lifespan,
)


# =============================================================================
# Health check
# =============================================================================

@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "guardrail_configured": guardrail is not None,
        "guardrail_id": GUARDRAIL_ID or "not set",
        "dry_run": DRY_RUN or not OPENAI_API_KEY,
    }


# =============================================================================
# Core WebSocket proxy
# =============================================================================

@app.websocket("/ws")
async def websocket_proxy(client_ws: WebSocket):
    """
    Main proxy endpoint.

    Flow:
    1. Client sends message
    2. Proxy calls Bedrock Guardrails (injection + PII in one call)
    3. If blocked → reject back to client
    4. If allowed → store placeholder map, forward clean text to OpenAI
    5. OpenAI responds with placeholders
    6. Proxy restores placeholders → send natural text to client
    7. Discard mapping from memory
    """
    await client_ws.accept()
    logger.info("Client connected")

    use_dry_run = DRY_RUN or not OPENAI_API_KEY
    openai_ws = None

    # Each connection gets its own restorer (isolated per session)
    restorer = PlaceholderRestorer()

    # Track whether OpenAI is currently generating a response
    response_in_progress = asyncio.Event()  # SET = idle, CLEAR = busy
    response_in_progress.set()  # start idle

    try:
        if not use_dry_run:
            try:
                openai_headers = {
                    "Authorization": f"Bearer {OPENAI_API_KEY}",
                    "OpenAI-Beta": "realtime=v1",
                }
                ssl_ctx = ssl.create_default_context(cafile=certifi.where())
                openai_ws = await websockets.connect(
                    f"{OPENAI_REALTIME_URL}?model={OPENAI_MODEL}",
                    extra_headers=openai_headers,
                    ssl=ssl_ctx,
                )
                logger.info("Connected to OpenAI Realtime API")

                # Configure the session: text-only, manual turn handling,
                # no auto-responses from OpenAI's voice activity detection.
                session_config = {
                    "type": "session.update",
                    "session": {
                        "modalities": ["text"],
                        "temperature": 0.7,
                        "turn_detection": None,
                        "instructions": (
                            "You are a helpful assistant. Always respond in English. "
                            "Respond naturally and concisely. "
                            "If you see placeholders like {NAME} or {SSN} in the conversation, "
                            "use them as-is — the system will restore them to real values."
                        ),
                    },
                }
                await openai_ws.send(json.dumps(session_config))
                logger.info("Sent session.update (text-only, manual turns)")

            except Exception as e:
                logger.warning(f"Could not connect to OpenAI: {e}")
                openai_ws = None

        if openai_ws:
            await asyncio.gather(
                _process_client_messages(client_ws, openai_ws, restorer, response_in_progress),
                _forward_openai_to_client(openai_ws, client_ws, restorer, response_in_progress),
            )
        else:
            await _process_client_messages(client_ws, None, restorer, None)

    except WebSocketDisconnect:
        logger.info("Client disconnected")
    except Exception as e:
        logger.error(f"Proxy error: {e}", exc_info=True)
    finally:
        if openai_ws:
            await openai_ws.close()
        restorer.clear()
        logger.info("Session ended, mappings cleared")


async def _process_client_messages(
    client_ws: WebSocket,
    openai_ws: websockets.WebSocketClientProtocol | None,
    restorer: PlaceholderRestorer,
    response_in_progress: asyncio.Event | None = None,
):
    """
    Client → [Bedrock Guardrails] → OpenAI

    Single API call replaces both injection guard and PII redactor.
    """
    try:
        while True:
            raw_message = await client_ws.receive_text()

            try:
                message = json.loads(raw_message)
            except json.JSONDecodeError:
                logger.warning("Non-JSON message from client, dropping")
                continue

            text_content = _extract_text(message)

            if text_content and guardrail:
                # =============================================
                # SINGLE CALL: Injection + PII via Bedrock
                # =============================================
                result = guardrail.evaluate(text_content, source="INPUT")

                if result.blocked:
                    # Injection detected — reject immediately
                    await client_ws.send_json({
                        "type": "security.blocked",
                        "reason": result.block_reason,
                        "action": result.raw_action,
                    })
                    logger.warning(f"Blocked: {result.block_reason}")
                    continue

                # Store placeholder map for restoration on the outbound path
                if result.placeholder_map:
                    restorer.store(result.placeholder_map)
                    await client_ws.send_json({
                        "type": "security.pii_anonymized",
                        "entity_count": len(result.placeholder_map),
                        "entity_types": list(result.placeholder_map.keys()),
                        "anonymized_text": result.anonymized_text,
                    })
                    logger.info(f"Anonymized {len(result.placeholder_map)} PII entities")

                # Replace text with anonymized version
                message = _replace_text(message, result.anonymized_text)

            # Forward to OpenAI or echo in dry-run mode
            if openai_ws:
                await openai_ws.send(json.dumps(message))

                # Auto-trigger a response if this was a user message.
                # Wait for any in-progress response to finish first.
                if message.get("type") == "conversation.item.create":
                    if response_in_progress and not response_in_progress.is_set():
                        logger.info("Waiting for active response to finish...")
                        await asyncio.wait_for(response_in_progress.wait(), timeout=30)
                    if response_in_progress:
                        response_in_progress.clear()  # mark busy
                    await openai_ws.send(json.dumps({
                        "type": "response.create",
                        "response": {"modalities": ["text"]},
                    }))
            else:
                await client_ws.send_json({
                    "type": "proxy.dry_run",
                    "message": "Processed (dry-run — not forwarded to OpenAI)",
                    "cleaned_message": message,
                })

    except WebSocketDisconnect:
        logger.info("Client disconnected (inbound)")
    except Exception as e:
        logger.error(f"Inbound error: {e}", exc_info=True)


async def _forward_openai_to_client(
    openai_ws: websockets.WebSocketClientProtocol,
    client_ws: WebSocket,
    restorer: PlaceholderRestorer,
    response_in_progress: asyncio.Event | None = None,
):
    """
    OpenAI → [Placeholder Restoration] → Client

    Swap {NAME} back to "Sarah Johnson" so the user hears natural speech.
    Then discard the mapping.
    """
    try:
        async for raw_message in openai_ws:
            try:
                message = json.loads(raw_message)
            except json.JSONDecodeError:
                await client_ws.send_text(raw_message)
                continue

            msg_type = message.get("type", "")

            # Mark idle when OpenAI finishes a response
            if msg_type in ("response.done", "response.cancelled") and response_in_progress:
                response_in_progress.set()

            text_content = _extract_text(message)
            if text_content and restorer.has_mappings:
                restored_text = restorer.restore(text_content)
                message = _replace_text(message, restored_text)

            await client_ws.send_json(message)

    except websockets.exceptions.ConnectionClosed:
        logger.info("OpenAI disconnected (outbound)")
    except WebSocketDisconnect:
        logger.info("Client disconnected (outbound)")
    except Exception as e:
        logger.error(f"Outbound error: {e}", exc_info=True)


# =============================================================================
# Message helpers
# =============================================================================

def _extract_text(message: dict) -> str | None:
    """Extract text from OpenAI Realtime API message events."""
    msg_type = message.get("type", "")

    if msg_type == "conversation.item.create":
        for part in message.get("item", {}).get("content", []):
            if part.get("type") == "input_text":
                return part.get("text")

    if msg_type in ("response.text.delta", "response.text.done"):
        return message.get("delta") or message.get("text")

    if msg_type in ("conversation.item.input_audio_transcription.completed",
                     "response.audio_transcript.delta",
                     "response.audio_transcript.done"):
        return message.get("transcript") or message.get("delta")

    return None


def _replace_text(message: dict, new_text: str) -> dict:
    """Replace text content in an OpenAI Realtime API message."""
    message = json.loads(json.dumps(message))
    msg_type = message.get("type", "")

    if msg_type == "conversation.item.create":
        for part in message.get("item", {}).get("content", []):
            if part.get("type") == "input_text":
                part["text"] = new_text
    elif msg_type in ("response.text.delta",):
        message["delta"] = new_text
    elif msg_type in ("response.text.done",):
        message["text"] = new_text
    elif msg_type in ("conversation.item.input_audio_transcription.completed",):
        message["transcript"] = new_text
    elif msg_type in ("response.audio_transcript.delta",):
        message["delta"] = new_text
    elif msg_type in ("response.audio_transcript.done",):
        message["transcript"] = new_text

    return message


# =============================================================================
# Run directly
# =============================================================================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=HOST, port=int(PORT))
