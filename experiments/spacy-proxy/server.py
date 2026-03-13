"""
SpaCy Proxy
=====================================
Sits between the client and OpenAI's Realtime API over WebSocket.
Every message passes through two security layers before reaching the LLM:

  1. Prompt Injection Guard — blocks malicious instructions
  2. PII Redactor — strips personal information, replaces with placeholders

On the return path (LLM -> user), placeholders are restored to original values
so the user sees a natural response.
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

from redactor import PIIRedactor
from injection_guard import InjectionGuard, ThreatLevel

# =============================================================================
# Config
# =============================================================================

load_dotenv()

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
OPENAI_REALTIME_URL = "wss://api.openai.com/v1/realtime"
OPENAI_MODEL = "gpt-4o-realtime-preview"
HOST = os.getenv("HOST", "0.0.0.0")
PORT = int(os.getenv("PORT", "8000"))
NER_MODEL = os.getenv("NER_MODEL", "en_core_web_md")
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")

# DRY_RUN mode: process messages through injection guard + PII redactor
# but don't forward to OpenAI. Perfect for demos and testing.
DRY_RUN = os.getenv("DRY_RUN", "false").lower() in ("true", "1", "yes")

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL),
    format="%(asctime)s | %(name)s | %(levelname)s | %(message)s",
)
logger = logging.getLogger("proxy")

# =============================================================================
# Globals — initialized at startup
# =============================================================================

redactor: PIIRedactor | None = None
guard: InjectionGuard | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Load models at startup, clean up on shutdown."""
    global redactor, guard

    logger.info("Initializing PII redaction engine...")
    redactor = PIIRedactor()
    guard = InjectionGuard()

    if DRY_RUN:
        logger.info("DRY RUN MODE — messages will be processed but NOT forwarded to OpenAI")
    elif not OPENAI_API_KEY:
        logger.warning("No OPENAI_API_KEY set — will run in dry-run mode automatically")

    logger.info("All models loaded. Server ready.")
    yield
    logger.info("Shutting down.")


app = FastAPI(
    title="PII Redaction Proxy",
    description="WebSocket proxy that strips PII before it reaches the LLM",
    lifespan=lifespan,
)


# =============================================================================
# Health check
# =============================================================================

@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "redactor_loaded": redactor is not None,
        "guard_loaded": guard is not None,
        "dry_run": DRY_RUN or not OPENAI_API_KEY,
    }


# =============================================================================
# Core WebSocket proxy
# =============================================================================

@app.websocket("/ws")
async def websocket_proxy(client_ws: WebSocket):
    """
    Main proxy endpoint. Client connects here instead of directly to OpenAI.

    IMPORTANT CHANGE: The injection guard and PII redactor now run
    REGARDLESS of whether the OpenAI connection is available. This means:
    - Injection blocking works even if OpenAI is down or misconfigured
    - PII redaction can be tested without an API key (dry-run mode)
    - The security layers are never bypassed due to upstream failures
    """
    await client_ws.accept()
    logger.info("Client connected")

    use_dry_run = DRY_RUN or not OPENAI_API_KEY
    openai_ws = None

    try:
        # Try to connect to OpenAI if not in dry-run mode
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
            except Exception as e:
                logger.warning(f"Could not connect to OpenAI: {e}")
                logger.warning("Falling back to dry-run mode for this session")
                openai_ws = None

        # Main message loop — security layers run regardless of OpenAI status
        if openai_ws:
            # Full proxy mode: bidirectional forwarding
            await asyncio.gather(
                _process_client_messages(client_ws, openai_ws=openai_ws),
                _forward_openai_to_client(openai_ws, client_ws),
            )
        else:
            # Dry-run mode: process messages locally, return results to client
            await _process_client_messages(client_ws, openai_ws=None)

    except WebSocketDisconnect:
        logger.info("Client disconnected")
    except Exception as e:
        logger.error(f"Proxy error: {e}", exc_info=True)
    finally:
        if openai_ws:
            await openai_ws.close()
        logger.info("Session ended")


async def _process_client_messages(
    client_ws: WebSocket,
    openai_ws: websockets.WebSocketClientProtocol | None = None,
):
    """
    Process incoming client messages through security layers.

    This is the INBOUND path where all the security work happens:
      1. Injection Guard — block malicious instructions
      2. PII Redactor — strip personal information
    """
    try:
        while True:
            raw_message = await client_ws.receive_text()

            try:
                message = json.loads(raw_message)
            except json.JSONDecodeError:
                logger.warning("Received non-JSON message from client, dropping")
                continue

            # Extract text content from the message
            text_content = _extract_text(message)

            if text_content:
                # =============================================
                # LAYER 1: Prompt Injection Detection
                # =============================================
                injection_result = guard.analyze(text_content)

                if injection_result.threat_level == ThreatLevel.BLOCKED:
                    # Send rejection back to client IMMEDIATELY
                    # This works regardless of OpenAI connection status
                    await client_ws.send_json({
                        "type": "security.injection_blocked",
                        "reason": injection_result.reason,
                        "score": injection_result.score,
                        "matched_patterns": injection_result.matched_patterns,
                    })
                    logger.warning(f"Blocked injection attempt: {injection_result.reason}")
                    continue  # Do NOT forward to OpenAI

                if injection_result.threat_level == ThreatLevel.SUSPICIOUS:
                    # Log and notify client, but still forward
                    await client_ws.send_json({
                        "type": "security.injection_suspicious",
                        "reason": injection_result.reason,
                        "score": injection_result.score,
                        "matched_patterns": injection_result.matched_patterns,
                    })
                    logger.warning(f"Suspicious message: {injection_result.reason}")

                # =============================================
                # LAYER 2: PII Redaction
                # =============================================
                redacted_text, entities = redactor.redact(text_content)

                if entities:
                    # Notify client what was redacted (useful for demos/logging)
                    await client_ws.send_json({
                        "type": "security.pii_redacted",
                        "entity_count": len(entities),
                        "entity_types": [e.entity_type for e in entities],
                        "redacted_text": redacted_text,
                    })
                    logger.info(f"Redacted {len(entities)} entities before forwarding")

                # Replace text in the message with redacted version
                message = _replace_text(message, redacted_text)

            # Forward to OpenAI or echo back in dry-run mode
            if openai_ws:
                await openai_ws.send(json.dumps(message))
            else:
                # Dry-run mode: echo the cleaned message back so the client
                # can see what would have been forwarded to OpenAI
                await client_ws.send_json({
                    "type": "proxy.dry_run",
                    "message": "Message processed (dry-run — not forwarded to OpenAI)",
                    "cleaned_message": message,
                })

    except WebSocketDisconnect:
        logger.info("Client disconnected (inbound)")
    except Exception as e:
        logger.error(f"Inbound proxy error: {e}", exc_info=True)


async def _forward_openai_to_client(
    openai_ws: websockets.WebSocketClientProtocol,
    client_ws: WebSocket,
):
    """
    OpenAI -> [Placeholder Restoration] -> Client

    The LLM's response may contain our placeholders (e.g., "Hello [PERSON_1]").
    We restore them to the original values so the user sees natural text.
    """
    try:
        async for raw_message in openai_ws:
            try:
                message = json.loads(raw_message)
            except json.JSONDecodeError:
                await client_ws.send_text(raw_message)
                continue

            # Restore placeholders in any text content
            text_content = _extract_text(message)
            if text_content and redactor.placeholder_map:
                restored_text = redactor.restore(text_content)
                message = _replace_text(message, restored_text)

            await client_ws.send_json(message)

    except websockets.exceptions.ConnectionClosed:
        logger.info("OpenAI disconnected (outbound)")
    except WebSocketDisconnect:
        logger.info("Client disconnected (outbound)")
    except Exception as e:
        logger.error(f"Outbound proxy error: {e}", exc_info=True)


# =============================================================================
# Message helpers
# =============================================================================

def _extract_text(message: dict) -> str | None:
    """
    Extract text content from an OpenAI Realtime API message.
    Handles common event types that contain user or assistant text.
    """
    msg_type = message.get("type", "")

    if msg_type == "conversation.item.create":
        item = message.get("item", {})
        content_parts = item.get("content", [])
        for part in content_parts:
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
    message = json.loads(json.dumps(message))  # deep copy
    msg_type = message.get("type", "")

    if msg_type == "conversation.item.create":
        content_parts = message.get("item", {}).get("content", [])
        for part in content_parts:
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
