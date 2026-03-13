# Shared Datasets

Evaluation datasets shared across all POC apps in `apps/`.

## Files

| File | Samples | Purpose |
|---|---|---|
| `synthetic_dataset.py` | 48 PII + 49 Guard = 97 total | TP/FP evaluation for PII detection and injection/content guard |

## Usage

Both apps import this dataset in their `eval_tpfp.py`:

```python
from synthetic_dataset import PII_SAMPLES, GUARD_SAMPLES       # spaCy POC
from synthetic_dataset import PII_SAMPLES, INJECTION_SAMPLES    # Bedrock Guardrails POC
```

## Dataset Structure

### PII Samples

Each sample includes fields for both evaluation engines:

| Field | Used by | Purpose |
|---|---|---|
| `input` | Both | Text to evaluate |
| `has_pii` | Guardrails | Boolean — does this message contain PII? |
| `expected_pii` | spaCy | List of expected spaCy NER / regex entity types |
| `pii_types` | Guardrails | List of expected Bedrock entity types |
| `description` | Both | Human-readable label |

### Guard / Injection Samples

| Field | Used by | Purpose |
|---|---|---|
| `input` | Both | Text to evaluate |
| `is_injection` | Guardrails | Boolean — should Bedrock block this? |
| `expected_result` | spaCy | `"blocked"`, `"suspicious"`, or `"clean"` |
| `category` | spaCy | Threat type (injection, academic_misuse, unsafe_content, etc.) |
| `description` | Both | Human-readable label |

## Source of Truth

The Bedrock Guardrails dataset is the primary source. Additional samples from the spaCy POC extend coverage for:
- PII types only the spaCy regex patterns detect (DOB, student ID, driver's license, credentials, account numbers)
- Threat categories beyond injection (academic misuse, content safety)
- Education-context false-positive traps
