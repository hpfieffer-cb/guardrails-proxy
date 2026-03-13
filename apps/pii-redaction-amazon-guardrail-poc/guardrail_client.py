"""
AWS Bedrock Guardrails Client
==============================
Replaces both injection_guard.py and redactor.py from the original POC.
One API call handles:
  - Prompt injection / jailbreak detection
  - PII anonymization with placeholder tags ({NAME}, {SSN}, etc.)

The client returns:
  - Cleaned text (anonymized)
  - A placeholder map for round-trip restoration
  - Block/allow decision for injection detection

Usage:
    client = GuardrailClient(guardrail_id="abc123", guardrail_version="1")
    result = client.evaluate("My name is Sarah Johnson")

    if result.blocked:
        # injection detected — reject blocked message 
        pass
    else:
        # result.anonymized_text = "My name is {NAME}"
        # result.placeholder_map = {"{NAME}": "Sarah Johnson"}
        forward_to_openai(result.anonymized_text)
"""

import json
import logging
from dataclasses import dataclass, field
import boto3

logger = logging.getLogger(__name__)


@dataclass
class GuardrailResult:
    """Result from Bedrock Guardrails evaluation."""
    blocked: bool                          # True if injection detected and blocked
    anonymized_text: str                   # Text with PII replaced by placeholders
    placeholder_map: dict[str, str]        # {"{NAME}": "Sarah Johnson", ...}
    raw_action: str                        # "GUARDRAIL_INTERVENED" or "NONE"
    assessments: list                      # Full assessment data for logging
    block_reason: str = ""                 # Why it was blocked (if blocked)


class GuardrailClient:
    """
    Wrapper around AWS Bedrock Guardrails ApplyGuardrail API.

    Handles:
    1. Sending text to Bedrock for injection detection + PII anonymization
    2. Parsing the response to extract anonymized text and placeholder mappings
    3. Providing a clean interface for the proxy server

    Config:
        guardrail_id: The Guardrail ID from your AWS Bedrock console or CDK stack
        guardrail_version: Version string (use "DRAFT" for testing, numbered for prod)
        region: AWS region where the Guardrail is deployed
    """

    def __init__(
        self,
        guardrail_id: str,
        guardrail_version: str = "DRAFT",
        region: str = "us-east-1",
        profile_name: str | None = None,
    ):
        self.guardrail_id = guardrail_id
        self.guardrail_version = guardrail_version

        if profile_name:
            session = boto3.Session(profile_name=profile_name, region_name=region)
            self.client = session.client("bedrock-runtime")
        else:
            self.client = boto3.client("bedrock-runtime", region_name=region)

        logger.info(
            f"Bedrock Guardrails client initialized | "
            f"guardrail={guardrail_id} version={guardrail_version} region={region}"
            f"{f' profile={profile_name}' if profile_name else ''}"
        )

    def evaluate(self, text: str, source: str = "INPUT") -> GuardrailResult:
        """
        Evaluate text through Bedrock Guardrails.

        Args:
            text: The message to evaluate
            source: "INPUT" for user messages (inbound), "OUTPUT" for LLM responses

        Returns:
            GuardrailResult with blocked status, anonymized text, and placeholder map
        """
        try:
            response = self.client.apply_guardrail(
                guardrailIdentifier=self.guardrail_id,
                guardrailVersion=self.guardrail_version,
                source=source,
                content=[
                    {
                        "text": {
                            "text": text,
                        }
                    }
                ],
            )

            return self._parse_response(response, original_text=text)

        except Exception as e:
            logger.error(f"Bedrock Guardrails API error: {e}", exc_info=True)
            # On API failure, return unmodified text (fail-open for POC)
            # OPINION: In production, you might want fail-closed instead.
            # That means blocking the message if the guardrail can't evaluate it.
            # For a POC, fail-open lets you keep testing even if AWS is misconfigured.
            return GuardrailResult(
                blocked=False,
                anonymized_text=text,
                placeholder_map={},
                raw_action="ERROR",
                assessments=[],
                block_reason=f"Guardrail API error: {str(e)}",
            )

    def _parse_response(self, response: dict, original_text: str) -> GuardrailResult:
        """
        Parse the Bedrock Guardrails API response.

        The response contains:
        - action: "GUARDRAIL_INTERVENED" or "NONE"
        - outputs: list of output text (anonymized or blocked message)
        - assessments: detailed breakdown of what was detected

        We extract the placeholder map from the assessments by matching
        detected PII entities back to their positions in the text.
        """
        action = response.get("action", "NONE")
        outputs = response.get("outputs", [])
        assessments = response.get("assessments", [])

        # Get the output text
        output_text = original_text
        if outputs:
            output_text = outputs[0].get("text", original_text)

        # Check if blocked (injection detected)
        blocked = action == "GUARDRAIL_INTERVENED"
        block_reason = ""

        # Determine if this was a PII anonymization (not a block) or an actual block
        # Bedrock uses GUARDRAIL_INTERVENED for both anonymization and blocking.
        # We distinguish by checking if the output contains placeholder tags —
        # if it does, it was anonymized (not blocked). 
        is_anonymization = any(
            placeholder in output_text
            for placeholder in ["{NAME}", "{SSN}", "{EMAIL}", "{PHONE}",
                                "{ADDRESS}", "{CREDIT_DEBIT_NUMBER}",
                                "{AWS_ACCESS_KEY}", "{IP_ADDRESS}"]
        )

        if blocked and is_anonymization:
            # This was PII anonymization, not a security block
            blocked = False
        elif blocked:
            # This was a genuine block (injection, denied topic, etc.)
            block_reason = self._extract_block_reason(assessments)
            logger.warning(f"BLOCKED by Bedrock Guardrails: {block_reason}")

        # Extract placeholder map from assessments
        placeholder_map = self._extract_placeholder_map(assessments)

        if placeholder_map:
            logger.info(
                f"PII anonymized: {len(placeholder_map)} entities | "
                f"types: {list(placeholder_map.keys())}"
            )

        return GuardrailResult(
            blocked=blocked,
            anonymized_text=output_text,
            placeholder_map=placeholder_map,
            raw_action=action,
            assessments=assessments,
            block_reason=block_reason,
        )

    def _extract_placeholder_map(self, assessments: list) -> dict[str, str]:
        """
        Extract the mapping of placeholders to original values from assessments.

        Bedrock returns assessment data that includes:
        - The detected PII type (NAME, etc.)
        - The original matched text
        - The action taken (ANONYMIZED, BLOCKED, etc.)

        We build a map like: {"{NAME}": "Sarah Johnson"}
        """
        placeholder_map = {}

        for assessment in assessments:
            sensitive_info = assessment.get("sensitiveInformationPolicy", {})
            pii_entities = sensitive_info.get("piiEntities", [])

            for entity in pii_entities:
                entity_type = entity.get("type", "")
                match_text = entity.get("match", "")
                action = entity.get("action", "")

                if action == "ANONYMIZED" and match_text:
                    placeholder = f"{{{entity_type}}}"
                    placeholder_map[placeholder] = match_text

            # Also check for custom regex matches
            regexes = sensitive_info.get("regexes", [])
            for regex_match in regexes:
                name = regex_match.get("name", "")
                match_text = regex_match.get("match", "")
                action = regex_match.get("action", "")

                if action == "ANONYMIZED" and match_text:
                    placeholder = f"{{{name}}}"
                    placeholder_map[placeholder] = match_text

        return placeholder_map

    def _extract_block_reason(self, assessments: list) -> str:
        """Extract a human-readable reason for why the message was blocked."""
        reasons = []

        for assessment in assessments:
            # Check content filters (injection, jailbreak)
            content_policy = assessment.get("contentPolicy", {})
            for filter_result in content_policy.get("filters", []):
                if filter_result.get("action") == "BLOCKED":
                    filter_type = filter_result.get("type", "unknown")
                    confidence = filter_result.get("confidence", "unknown")
                    reasons.append(f"{filter_type} (confidence: {confidence})")

            # Check denied topics
            topic_policy = assessment.get("topicPolicy", {})
            for topic in topic_policy.get("topics", []):
                if topic.get("action") == "BLOCKED":
                    reasons.append(f"denied_topic: {topic.get('name', 'unknown')}")

            # Check word filters
            word_policy = assessment.get("wordPolicy", {})
            for word in word_policy.get("customWords", []):
                if word.get("action") == "BLOCKED":
                    reasons.append(f"word_filter: {word.get('match', 'unknown')}")

        return "; ".join(reasons) if reasons else "Blocked by guardrail (reason not specified)"


class PlaceholderRestorer:
    """
    Handles round-trip restoration of PII placeholders.

    This is the only piece of custom logic that lives in the proxy.
    Bedrock handles detection and anonymization; this handles restoration.

    Usage:
        restorer = PlaceholderRestorer()

        # Inbound: store the mapping from a guardrail result
        restorer.store(result.placeholder_map)

        # Outbound: restore placeholders in LLM response
        natural_text = restorer.restore("Hello {NAME}, I can help you.")
        # "Hello Sarah Johnson, I can help you."

        # After restoration: discard the mapping
        restorer.clear()
    """

    def __init__(self):
        self._map: dict[str, str] = {}

    def store(self, placeholder_map: dict[str, str]):
        """Store a placeholder map from a guardrail result. Merges with existing."""
        self._map.update(placeholder_map)

    def restore(self, text: str) -> str:
        """Replace all placeholders with original values."""
        restored = text
        for placeholder, original in self._map.items():
            restored = restored.replace(placeholder, original)
        return restored

    def clear(self):
        """Discard all stored mappings. Call after each turn."""
        self._map.clear()

    @property
    def has_mappings(self) -> bool:
        return bool(self._map)
