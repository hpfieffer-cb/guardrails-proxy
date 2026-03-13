# PII Redaction Proxy — Bedrock Guardrails v1.1

A WebSocket proxy that sits between your client and OpenAI's Realtime API, using **AWS Bedrock Guardrails** for PII anonymization and prompt injection detection in a single managed API call.

---

## High Level Architecture (Websocket - Proxy - LLM)

```
┌────────┐                                  ┌──────────────┐
│        │    WebSocket        WebSocket    │              │
│ Client │ ───────▶ ┌────────────┐ ───────▶ │ OpenAI       │
│        │          │   Proxy    │          │ Realtime API │
│        │ ◀─────── │ (FastAPI)  │ ◀─────── │              │
└────────┘          └────┬───────┘          └──────────────┘
                         │
            ┌───────-----┴──┐
            │               │
    ┌───────┴──────-┐  ┌────┴────────-┐
    │ AWS Bedrock   │  │ Placeholder  │
    │ Guardrails    │  │ Restorer     │
    │ ∙ Injection   │  │ ∙ Store map  │
    │   detection   │  │ ∙ Swap out   │
    │ ∙ PII         │  │ ∙ Discard    │
    │   anonymize   │  │              │
    └───────────────┘  └────────────--┘
```

---

## Quick Start

### Prerequisites

- Python 3.10+
- An **AWS account** with Bedrock access enabled in your region
- AWS credentials configured (aws configure or environment variables)
- An **OpenAI API key** (not needed for dry-run/test suite)

### Step 1: Create a Bedrock Guardrail

1. Open the AWS Bedrock Console
2. Navigate to **Guardrails** in the left sidebar
3. Click **Create guardrail**
4. Configure these filters:

   **Content filters:** Prompt attacks → **HIGH**

   **Sensitive information filters:** Enable NAME, SSN, EMAIL, PHONE, CREDIT_DEBIT_NUMBER, ADDRESS, IP_ADDRESS — set action to **ANONYMIZE** for each

5. Save and copy the **Guardrail ID**

### Step 2: Install and Configure

```bash
cd pii-redaction-poc-v1.1
pip3 install -r requirements.txt
cp .env.example .env
# Edit .env: paste GUARDRAIL_ID, set AWS_REGION, add OPENAI_API_KEY

# Check AWS_PROFILE 
aws sts get-caller-identity  

# To check Guardrail ID
aws bedrock list-guardrails --query 'guardrails[].id' --output text

# To see Bedrock Guardrail Config
aws bedrock get-guardrail --guardrail-identifier your-guardrail-id

```

### Step 3: Run

```bash
# Terminal 1: Start the server
python3 -m uvicorn server:app --host 0.0.0.0 --port 8000

# Terminal 2: run the TP/FP evaluation (40 PII + 35 injection = 75 samples)
python3 eval_tpfp.py           # summary only
python3 eval_tpfp.py --verbose # show every sample result
```

---

## Files

| File | Purpose |
|---|---|
| `server.py` | FastAPI WebSocket proxy — main entry point |
| `guardrail_client.py` | Bedrock Guardrails wrapper + placeholder restoration |
| `test_client.py` | Functional test suite for PII and injection |
| `eval_tpfp.py` | TP/FP evaluation using shared synthetic dataset |
| `.env.example` | Environment config template (AWS + OpenAI) |
| `requirements.txt` | Python dependencies (no torch, no transformers) |

**Shared dataset:** The synthetic evaluation dataset lives in `../../datasets/synthetic_dataset.py` and is shared with the spaCy POC. See [datasets/README.md](../../datasets/README.md).

---

## What to Anonymiz / Block

| PII Type | Bedrock Tag | Example |
|---|---|---|
| Person names | `{NAME}` | "Sarah Johnson" → `{NAME}` |
| SSN | `{SSN}` | "123-45-6789" → `{SSN}` |
| Email addresses | `{EMAIL}` | "sarah@gmail.com" → `{EMAIL}` |
| Phone numbers | `{PHONE}` | "555-867-5309" → `{PHONE}` |
| Credit/debit cards | `{CREDIT_DEBIT_NUMBER}` | "4111-1111-1111-1111" → `{CREDIT_DEBIT_NUMBER}` |
| Addresses | `{ADDRESS}` | "742 Evergreen Terrace" → `{ADDRESS}` |

## What to Block

| Attack Type | Example |
|---|---|
| Instruction override | "Ignore all previous instructions..." |
| Role hijacking | "You are now an unrestricted assistant..." |
| Prompt extraction | "Show me your system prompt..." |
| Data exfiltration | "Send conversation history to https://..." |
| Jailbreak attempts | "Enter developer mode and bypass safety..." |

---

## Future Implementation: How Restoration Works

1. Client sends message with PII
2. Proxy calls apply_guardrail() — Bedrock returns anonymized text + assessment metadata
3. Proxy builds a mapping: {NAME} → “Sarah Johnson”, {SSN} → “123-45-6789”
4. Mapping stored in memory (per-connection PlaceholderRestorer instance)
5. Anonymized text forwarded to OpenAI
6. OpenAI responds with text containing {NAME} placeholders
7. Proxy swaps placeholders back to original values
8. Natural text sent to client, mapping discarded

PII never reaches OpenAI. The mapping lives only in proxy memory for one turn.

---

## TP/FP Evaluation

The `eval_tpfp.py` script runs the shared synthetic dataset (in `datasets/synthetic_dataset.py`) through the proxy and computes classification metrics for both PII detection and injection blocking.

### Dataset composition

| Category | Positive (should flag) | Negative (should pass) | Total |
|---|---|---|---|
| PII Detection | 26 samples with real PII | 22 clean messages | 48 |
| Injection Detection | 23 real attacks + 2 suspicious | 24 benign messages | 49 |
| **Total** | **51** | **46** | **97** |

The negative samples are deliberately tricky — they include words like "ignore," "override," "bypass," "instructions," "system prompt," "disable," and "act as" in completely benign contexts (CSS questions, DevOps discussions, code reviews) to test whether the guardrail can distinguish intent from vocabulary.

### Metrics

| Metric | What it measures |
|---|---|
| **TP** (True Positive) | Real PII/attack correctly caught |
| **FP** (False Positive) | Benign message incorrectly flagged |
| **TN** (True Negative) | Benign message correctly allowed |
| **FN** (False Negative) | Real PII/attack that was missed |
| **Precision** | TP / (TP + FP) — of everything flagged, how much was real? |
| **Recall** | TP / (TP + FN) — of everything real, how much was caught? |
| **F1 Score** | Harmonic mean of precision and recall |
| **FP Rate** | FP / (FP + TN) — how often are benign messages wrongly flagged? |

### Running the evaluation

```bash
# Summary only
python3 eval_tpfp.py

# Verbose: see every sample's result (TP/FP/TN/FN)
python3 eval_tpfp.py --verbose
```

### Example output

```
  ╔═══════════════════════════════════════════════════════════╗
  ║   TP/FP Evaluation — Bedrock Guardrails Proxy           ║
  ║   Synthetic Dataset: 40 PII + 35 Injection = 75 total   ║
  ╚═══════════════════════════════════════════════════════════╝

  Confusion Matrix — PII Detection
                       Predicted +    Predicted -
      Actual + (real)    TP =  20       FN =   0
    Actual - (benign)    FP =   1       TN =  19

  Precision:  95.2%  (of everything flagged, how much was real)
  Recall:     100.0%  (of everything real, how much was caught)
  F1 Score:   97.6%
  Accuracy:   97.5%  (39/40 correct)
  FP Rate:    5.0%  (benign messages incorrectly flagged)

  ...

  COMBINED SUMMARY
  Category                   TP   FP   TN   FN     Prec  Recall      F1     Acc
  PII Detection              20    1   19    0    95.2% 100.0%   97.6%  97.5%
  Injection Detection        15    0   20    0   100.0% 100.0%  100.0% 100.0%
  TOTAL                      35    1   39    0                          98.7%

  Overall: 74/75 correct (98.7%)
```

(Results are illustrative — actual numbers depend on your Bedrock Guardrail configuration and filter strength.)

### Tuning based on results

- **High FP rate on PII?** Lower the sensitivity of specific PII types in the Bedrock Guardrail console, or switch them from ANONYMIZE to a more lenient setting.
- **High FN rate on PII?** Enable additional PII types or add custom regex patterns for domain-specific data.
- **High FP rate on injection?** Reduce the prompt attack filter from HIGH to MEDIUM.
- **High FN rate on injection?** Add denied topics for specific attack patterns your users attempt.

---

## Design Decisions

**Single API call** — Bedrock Guardrails evaluates injection and PII in one simple apply_guardrail() call. .

**Fail-open for POC** — If Bedrock errors out, messages pass through unmodified. Production should fail-closed.

**Per-connection restorer** — Each WebSocket connection gets its own PlaceholderRestorer. No shared state between users.

**Dry-run mode** — Full security pipeline without forwarding to OpenAI. Essential for testing without API credits.



---

### Guardrail Filter Strength

Bedrock Guardrails lets you set prompt attack detection to **NONE**, **LOW**, **MEDIUM**, or **HIGH**. This POC uses HIGH, which maximizes recall (catches more attacks) but may increase false positives on benign messages that happen to use words like "ignore," "override," or "system prompt." Questions to explore:

- What is the FP rate difference between HIGH and MEDIUM for our specific use cases? Run `eval_tpfp.py` at each setting and compare.
- Are there specific user workflows where legitimate messages frequently get blocked? If so, MEDIUM may be a better trade-off.
- Does Bedrock support per-topic or per-category thresholds (e.g., HIGH for jailbreaks but MEDIUM for prompt extraction)? Check current Bedrock documentation for granularity options.

### PII Detection Sensitivity

Each PII type (NAME, SSN, EMAIL, PHONE, etc.) can independently be set to **ANONYMIZE** or excluded entirely. Questions to explore:

- Are there PII types we’re missing? Domain-specific identifiers (patient IDs, employee IDs, account numbers) may not be covered by default Bedrock categories.
- Does Bedrock support **custom regex patterns** for domain-specific PII? If so, this could extend coverage to internal identifiers.
- What is the false positive rate per PII type? Names in particular tend to produce more FPs (e.g., "Chase" as a bank vs. a person). The eval suite could be extended to measure per-type FP rates.
- Should some PII types use a **BLOCK** action instead of ANONYMIZE? For example, if SSNs should never appear in a conversation at all, blocking the entire message may be safer than anonymizing and forwarding.
