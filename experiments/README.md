# Experiments

Proof-of-concept proxy layers for PII redaction and prompt injection detection. Each experiment implements the same core pattern — a WebSocket proxy sitting between your client and the LLM — using a different detection backend.

---

## Experiments

| Experiment | Detection Backend | Key Trade-off |
|---|---|---|
| [pii-redaction-spaCy-poc](pii-redaction-spaCy-poc/) | spaCy NER + regex (local, in-process) | Full control, no cloud dependency, more code to maintain |
| [pii-redaction-amazon-guardrail-poc](pii-redaction-amazon-guardrail-poc/) | AWS Bedrock Guardrails (managed service) | Single API call, no model management, requires AWS account |

---

## Shared Architecture

Both experiments follow the same proxy pattern:

```
┌────────┐     WebSocket     ┌──────────────────────┐     WebSocket     ┌──────────────┐
│        │ ──────────────►   │                      │ ──────────────►   │              │
│ Client │                   │    Guardrails Proxy  │                   │ OpenAI       │
│        │ ◄──────────────   │                      │ ◄──────────────   │ Realtime API │
└────────┘  (restored text)  └──────────────────────┘  (clean text)    └──────────────┘
                                      │
                              ┌───────┴────────┐
                              │                │
                    ┌─────────┴────────┐  ┌────┴─────────────┐
                    │ Injection /      │  │ Placeholder      │
                    │ Content Guard    │  │ Restoration      │
                    │                  │  │                  │
                    │ Block threats    │  │ Restore PII on   │
                    │ before they      │  │ outbound so the  │
                    │ reach the LLM    │  │ user sees natural │
                    └──────────────────┘  │ responses        │
                                          └──────────────────┘
```

### Inbound (Client → LLM)

1. **Injection / Content Guard** — detect and block prompt injection, academic misuse, content safety violations, and data exfiltration attempts.
2. **PII Redactor** — detect PII (names, SSNs, credit cards, emails, etc.) and replace with placeholders before the message reaches the LLM.

### Outbound (LLM → Client)

1. **Placeholder Restoration** — swap placeholders back to original values so the user sees natural responses. PII never reaches the LLM; the mapping lives only in proxy memory.

---

## Shared Dataset

Both experiments use the same synthetic evaluation dataset at [`datasets/synthetic_dataset.py`](../datasets/synthetic_dataset.py) — 40 PII samples + 35 injection samples = 75 total. See [`datasets/README.md`](../datasets/README.md) for details.

---

## Possible Next Steps

The two experiments demonstrate different detection backends with different trade-offs. A natural progression:

1. **SpaCy proxy** — local NER + regex for PII redaction. No cloud dependency, full control over detection logic, fast iteration.
2. **Amazon Bedrock Guardrails proxy** — managed service that handles both PII anonymization and prompt injection detection in a single API call. No model management, no custom ML infrastructure.

These could be composed in a chain, or selected independently depending on deployment constraints (e.g., cloud access, latency requirements, compliance needs).
