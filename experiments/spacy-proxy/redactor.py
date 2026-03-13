"""
PII Redaction Engine
====================
Two-layer PII detection:
  1. NER model:
       a. spaCy (en_core_web_md) — installs from PyPI
       b. Regex-only fallback — no model needed, misses names/orgs
  2. Regex patterns — catches structured PII (SSN, credit cards, emails, phones,
     student IDs, driver's license, etc.)

PII categories covered:
  - Personal identifiers: name, email, phone, DOB
  - Government identifiers: SSN, driver's license
  - Institutional identifiers: student ID
  - Financial data: credit card numbers
  - Electronic credentials: usernames/passwords in context
  - Network identifiers: IP addresses
"""

import os
import re
import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)


# =============================================================================
# Data structures
# =============================================================================

@dataclass
class PIIEntity:
    """A detected PII entity with its location in the original text."""
    entity_type: str   # e.g. "PERSON", "SSN", "EMAIL"
    value: str         # the actual PII value found
    start: int         # char offset start
    end: int           # char offset end
    source: str        # "spacy" or "regex" — useful for debugging


# =============================================================================
# Regex-based PII patterns
# =============================================================================
# Covers PII categories:
#   Personal identifiers, government IDs, institutional IDs,
#   financial data, electronic credentials, network identifiers.

PII_PATTERNS = {
    # US Social Security Number: 123-45-6789 or 123 45 6789
    "SSN": re.compile(
        r"\b(\d{3}[-\s]?\d{2}[-\s]?\d{4})\b"
    ),

    # Credit card numbers: 13-19 digits, optionally separated by spaces or dashes
    "CREDIT_CARD": re.compile(
        r"\b(\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{1,7})\b"
    ),

    # Email addresses
    "EMAIL": re.compile(
        r"\b([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b"
    ),

    # US phone numbers: (555) 123-4567, 555-123-4567, 5551234567
    "PHONE": re.compile(
        r"(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"
    ),

    # IP addresses (v4)
    "IP_ADDRESS": re.compile(
        r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b"
    ),

    # Date of birth patterns: MM/DD/YYYY, MM-DD-YYYY, YYYY-MM-DD
    "DOB": re.compile(
        r"\b(\d{1,2}[/-]\d{1,2}[/-]\d{2,4})\b"
    ),

    # US Driver's license (common formats: 1-2 letters + 4-8 digits)
    "DRIVERS_LICENSE": re.compile(
        r"\b([A-Z]{1,2}\d{4,8})\b"
    ),

    # Student ID (6-10 digit number, often prefixed with context)
    "STUDENT_ID": re.compile(
        r"(?:student\s*(?:id|number|#|no\.?)\s*[:=]?\s*)(\d{6,10})\b",
        re.IGNORECASE,
    ),

    # Financial account numbers (8-17 digits, often with context)
    "ACCOUNT_NUMBER": re.compile(
        r"(?:account\s*(?:number|#|no\.?)\s*[:=]?\s*)(\d{8,17})\b",
        re.IGNORECASE,
    ),

    # Passwords / credentials appearing in text
    "CREDENTIAL": re.compile(
        r"(?:password|passwd|pwd|pin)\s*(?:is\s*)?[:=]\s*(\S+)",
        re.IGNORECASE,
    ),
}

# =============================================================================
# NER backend — spaCy
# =============================================================================

class SpaCyDetector:
    """
    Using NER using spaCy's en_core_web_md model
    """

    LABEL_MAP = {
        "PERSON": "PERSON",
        "ORG": "ORGANIZATION",
        "GPE": "LOCATION",      # geopolitical entities (cities, countries)
        "LOC": "LOCATION",      # non-GPE locations (mountains, rivers)
        "FAC": "LOCATION",      # facilities (airports, buildings)
    }

    def __init__(self, model_name: str = "en_core_web_md"):
        import spacy
        logger.info(f"Loading spaCy NER model: {model_name}")
        self.nlp = spacy.load(model_name)
        logger.info("spaCy NER model loaded successfully")

    def detect(self, text: str) -> list[PIIEntity]:
        doc = self.nlp(text)
        results = []
        for ent in doc.ents:
            mapped_type = self.LABEL_MAP.get(ent.label_)
            if mapped_type:
                results.append(PIIEntity(
                    entity_type=mapped_type,
                    value=ent.text,
                    start=ent.start_char,
                    end=ent.end_char,
                    source="spacy",
                ))
        return results


# =============================================================================
# Combined redaction engine
# =============================================================================

class PIIRedactor:
    """
    Main redaction engine. Combines spaCy NER + regex patterns.

    Usage:
        redactor = PIIRedactor()
        clean_text, entities = redactor.redact("My name is John, SSN 123-45-6789")
        # clean_text = "My name is [PERSON_1], SSN [SSN_1]"
        # entities = {("[PERSON_1]", "John"), ("[SSN_1]", "123-45-6789")}

    OPTIONAL: We use numbered placeholders (PERSON_1, PERSON_2) instead of a
    single generic [REDACTED] tag. This lets the LLM distinguish between
    multiple entities of the same type, which matters for coherent responses.
    The placeholder map can be used for round-trip restoration if needed.
    """

    def __init__(self):
        # NER backend selection:
        #   NER_BACKEND=spacy → use spaCy (default, works behind Zscaler)
        #   NER_BACKEND=none  → regex-only mode
        backend = os.getenv("NER_BACKEND", "spacy").lower()

        self.ner = None
        if backend == "spacy":
            try:
                self.ner = SpaCyDetector()
            except (OSError, ImportError, Exception) as e:
                logger.warning(
                    f"spaCy NER unavailable ({e}). "
                    "Running in REGEX-ONLY mode — names/orgs/locations will not be detected."
                )

        if backend == "none":
            logger.info("NER_BACKEND=none — running in regex-only mode.")

        ner_name = type(self.ner).__name__ if self.ner else "None (regex-only)"
        logger.info(f"PII Redactor initialized — NER backend: {ner_name}")
        # Tracks placeholder counts per entity type for numbering
        self._counters: dict[str, int] = {}
        # Maps placeholder -> original value for round-trip restoration
        self.placeholder_map: dict[str, str] = {}

    def _next_placeholder(self, entity_type: str) -> str:
        """Generate the next numbered placeholder for an entity type."""
        count = self._counters.get(entity_type, 0) + 1
        self._counters[entity_type] = count
        return f"[{entity_type}_{count}]"

    def _regex_detect(self, text: str) -> list[PIIEntity]:
        """Run all regex patterns against the text."""
        results = []
        for pii_type, pattern in PII_PATTERNS.items():
            for match in pattern.finditer(text):
                results.append(PIIEntity(
                    entity_type=pii_type,
                    value=match.group(),
                    start=match.start(),
                    end=match.end(),
                    source="regex",
                ))
        return results

    def redact(self, text: str) -> tuple[str, list[PIIEntity]]:
        """
        Detect and redact all PII from text.

        Returns:
            - redacted text with placeholders
            - list of all detected entities (for logging/audit)
        """
        # Reset counters for each message
        self._counters = {}
        self.placeholder_map = {}

        # Layer 1: NER (names, orgs, locations)
        ner_entities = self.ner.detect(text) if self.ner else []

        # Layer 2: Regex (SSNs, credit cards, emails, phones, etc.)
        regex_entities = self._regex_detect(text)

        # Combine and deduplicate (prefer NER when overlapping, since it's
        # context-aware and more likely to have correct boundaries)
        all_entities = self._merge_entities(ner_entities, regex_entities)

        # Sort by position descending so we can replace without offset issues
        all_entities.sort(key=lambda e: e.start, reverse=True)

        # Replace each entity with a numbered placeholder
        redacted = text
        for entity in all_entities:
            placeholder = self._next_placeholder(entity.entity_type)
            self.placeholder_map[placeholder] = entity.value
            redacted = redacted[:entity.start] + placeholder + redacted[entity.end:]

        if all_entities:
            logger.info(
                f"Redacted {len(all_entities)} PII entities: "
                f"{[e.entity_type for e in all_entities]}"
            )

        return redacted, all_entities

    def restore(self, text: str) -> str:
        """
        Round-trip restoration: replace placeholders with original values.

        Use this on the LLM's response so the user sees real values.
        Only call this on the OUTBOUND path (LLM -> user), never on
        inbound (user -> LLM).
        """
        restored = text
        for placeholder, original in self.placeholder_map.items():
            restored = restored.replace(placeholder, original)
        return restored

    def _merge_entities(
        self,
        ner_entities: list[PIIEntity],
        regex_entities: list[PIIEntity],
    ) -> list[PIIEntity]:
        """
        Merge NER and regex entities, removing overlaps.
        When entities overlap, prefer NER (better boundary detection).
        """
        # Start with all NER entities
        merged = list(ner_entities)
        ner_spans = [(e.start, e.end) for e in ner_entities]

        # Add regex entities only if they don't overlap with NER
        for regex_ent in regex_entities:
            overlaps = any(
                not (regex_ent.end <= ns or regex_ent.start >= ne)
                for ns, ne in ner_spans
            )
            if not overlaps:
                merged.append(regex_ent)

        return merged
