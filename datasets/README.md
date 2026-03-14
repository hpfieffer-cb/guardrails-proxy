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

### Synthetic Evaluation Dataset (97 samples)

| Category | Positives (Should Trigger) | Negatives (Benign) | Total |
|---|---|---|---|
| **PII Detection** | 26 | 22 | 48 |
| **Injection / Guard Detection** | 25 *(23 blocked + 2 suspicious)* | 24 | 49 |
| **TOTAL** | **51** | **46** | **97** |

### Visual Summary

| Type | Count |
|---|---|
| Total Samples | **97** |
| Total Positives | **51** |
| Total Negatives | **46** |
