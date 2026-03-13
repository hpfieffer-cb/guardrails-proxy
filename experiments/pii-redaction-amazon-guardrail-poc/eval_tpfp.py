"""
TP/FP Evaluation Suite — PII Anonymization & Prompt Injection
==============================================================
Runs the shared synthetic dataset through the Bedrock Guardrails proxy
and computes True Positive / False Positive / True Negative / False Negative
rates for both PII detection and injection blocking.

Metrics:
  TP = Should be caught AND was caught
  FP = Should NOT be caught BUT was caught
  TN = Should NOT be caught AND was not caught
  FN = Should be caught BUT was NOT caught

  Precision = TP / (TP + FP)   — "of everything flagged, how much was real?"
  Recall    = TP / (TP + FN)   — "of everything that was real, how much was caught?"
  F1        = 2 * (Precision * Recall) / (Precision + Recall)
"""

import asyncio
import json
import sys
import os
import argparse
import websockets

# Import shared dataset from /datasets
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "datasets"))
from synthetic_dataset import PII_SAMPLES, INJECTION_SAMPLES

PROXY_URL = "ws://localhost:8000/ws"

# ── ANSI colors ──
CYAN = "\033[36m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
RED = "\033[31m"
DIM = "\033[2m"
BOLD = "\033[1m"
RESET = "\033[0m"


# =============================================================================
# Helpers
# =============================================================================

def _wrap_as_realtime_event(text: str) -> dict:
    return {
        "type": "conversation.item.create",
        "item": {
            "type": "message",
            "role": "user",
            "content": [{"type": "input_text", "text": text}],
        },
    }


async def _collect_responses(ws, timeout: float = 3.0) -> list[dict]:
    responses = []
    try:
        while True:
            raw = await asyncio.wait_for(ws.recv(), timeout=timeout)
            resp = json.loads(raw)
            responses.append(resp)
            timeout = 0.5
    except (asyncio.TimeoutError, json.JSONDecodeError):
        pass
    return responses


def _print_metrics(tp, fp, tn, fn, label):
    """Print a confusion matrix and metrics."""
    total = tp + fp + tn + fn
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    accuracy = (tp + tn) / total if total > 0 else 0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0

    print(f"\n  {BOLD}{CYAN}Confusion Matrix — {label}{RESET}")
    print(f"  {'':>20} {'Predicted +':>14} {'Predicted -':>14}")
    print(f"  {'Actual + (real)':>20} {GREEN}TP = {tp:>3}{RESET}       {RED}FN = {fn:>3}{RESET}")
    print(f"  {'Actual - (benign)':>20} {YELLOW}FP = {fp:>3}{RESET}       {GREEN}TN = {tn:>3}{RESET}")
    print()
    print(f"  {BOLD}Precision:{RESET}  {precision:.1%}  {DIM}(of everything flagged, how much was real){RESET}")
    print(f"  {BOLD}Recall:{RESET}     {recall:.1%}  {DIM}(of everything real, how much was caught){RESET}")
    print(f"  {BOLD}F1 Score:{RESET}   {f1:.1%}")
    print(f"  {BOLD}Accuracy:{RESET}   {accuracy:.1%}  ({tp + tn}/{total} correct)")
    print(f"  {BOLD}FP Rate:{RESET}    {fpr:.1%}  {DIM}(benign messages incorrectly flagged){RESET}")

    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn,
            "precision": precision, "recall": recall, "f1": f1, "accuracy": accuracy, "fpr": fpr}


# =============================================================================
# Evaluation runners
# =============================================================================

async def eval_pii(verbose: bool = False):
    """Evaluate PII detection: TP/FP/TN/FN."""
    print(f"\n{'='*70}")
    print(f"  {BOLD}PII DETECTION EVALUATION{RESET}  ({len(PII_SAMPLES)} samples)")
    print(f"  Positive = contains PII | Negative = no PII")
    print(f"{'='*70}")

    tp = fp = tn = fn = 0
    skipped = 0

    for i, sample in enumerate(PII_SAMPLES, 1):
        has_pii = sample["has_pii"]
        desc = sample["description"]
        text = sample["input"]

        try:
            async with websockets.connect(PROXY_URL) as ws:
                await ws.send(json.dumps(_wrap_as_realtime_event(text)))
                responses = await _collect_responses(ws)

                pii_resp = next(
                    (r for r in responses if r.get("type") == "security.pii_anonymized"), None
                )
                dry_run = next(
                    (r for r in responses if r.get("type") == "proxy.dry_run"), None
                )

                # Skip if guardrail not configured
                if dry_run and not pii_resp:
                    if has_pii:
                        skipped += 1
                        if verbose:
                            print(f"  {DIM}[{i:>2}] SKIP  {desc}{RESET}")
                        continue

                was_flagged = pii_resp is not None

                if has_pii and was_flagged:
                    tp += 1
                    label = f"{GREEN}TP{RESET}"
                elif has_pii and not was_flagged:
                    fn += 1
                    label = f"{RED}FN{RESET}"
                elif not has_pii and was_flagged:
                    fp += 1
                    label = f"{YELLOW}FP{RESET}"
                else:
                    tn += 1
                    label = f"{GREEN}TN{RESET}"

                if verbose:
                    entities = pii_resp.get("entity_types", []) if pii_resp else []
                    entity_str = f" {DIM}entities={entities}{RESET}" if entities else ""
                    print(f"  [{i:>2}] {label}  {desc}{entity_str}")
                    if (has_pii and not was_flagged) or (not has_pii and was_flagged):
                        print(f"       {DIM}\"{text[:80]}...\"{RESET}")

        except ConnectionRefusedError:
            print(f"\n  {RED}ERROR: Could not connect to proxy server.{RESET}")
            print(f"  Start it with: python3 -m uvicorn server:app --port 8000")
            return None

    if skipped > 0:
        print(f"\n  {YELLOW}Skipped {skipped} samples (guardrail not configured in dry-run){RESET}")

    return _print_metrics(tp, fp, tn, fn, "PII Detection")


async def eval_injection(verbose: bool = False):
    """Evaluate injection detection: TP/FP/TN/FN."""
    print(f"\n{'='*70}")
    print(f"  {BOLD}INJECTION DETECTION EVALUATION{RESET}  ({len(INJECTION_SAMPLES)} samples)")
    print(f"  Positive = injection attack | Negative = benign message")
    print(f"{'='*70}")

    tp = fp = tn = fn = 0
    skipped = 0

    for i, sample in enumerate(INJECTION_SAMPLES, 1):
        is_injection = sample["is_injection"]
        desc = sample["description"]
        text = sample["input"]

        try:
            async with websockets.connect(PROXY_URL) as ws:
                await ws.send(json.dumps(_wrap_as_realtime_event(text)))
                responses = await _collect_responses(ws)

                blocked = next(
                    (r for r in responses if r.get("type") == "security.blocked"), None
                )
                dry_run = next(
                    (r for r in responses if r.get("type") == "proxy.dry_run"), None
                )

                # Skip if guardrail not configured
                if dry_run and not blocked:
                    if is_injection:
                        skipped += 1
                        if verbose:
                            print(f"  {DIM}[{i:>2}] SKIP  {desc}{RESET}")
                        continue

                was_blocked = blocked is not None

                if is_injection and was_blocked:
                    tp += 1
                    label = f"{GREEN}TP{RESET}"
                elif is_injection and not was_blocked:
                    fn += 1
                    label = f"{RED}FN{RESET}"
                elif not is_injection and was_blocked:
                    fp += 1
                    label = f"{YELLOW}FP{RESET}"
                else:
                    tn += 1
                    label = f"{GREEN}TN{RESET}"

                if verbose:
                    reason = blocked.get("reason", "") if blocked else ""
                    reason_str = f" {DIM}reason=\"{reason}\"{RESET}" if reason else ""
                    print(f"  [{i:>2}] {label}  {desc}{reason_str}")
                    if (is_injection and not was_blocked) or (not is_injection and was_blocked):
                        print(f"       {DIM}\"{text[:80]}...\"{RESET}")

        except ConnectionRefusedError:
            print(f"\n  {RED}ERROR: Could not connect to proxy server.{RESET}")
            print(f"  Start it with: python3 -m uvicorn server:app --port 8000")
            return None

    if skipped > 0:
        print(f"\n  {YELLOW}Skipped {skipped} samples (guardrail not configured in dry-run){RESET}")

    return _print_metrics(tp, fp, tn, fn, "Injection Detection")


# =============================================================================
# Main
# =============================================================================

async def main(verbose: bool = False):
    print(f"\n{BOLD}{CYAN}")
    print(f"  ╔═══════════════════════════════════════════════════════════╗")
    print(f"  ║   TP/FP Evaluation — Bedrock Guardrails Proxy           ║")
    print(f"  ║   Synthetic Dataset: {len(PII_SAMPLES)} PII + {len(INJECTION_SAMPLES)} Injection = {len(PII_SAMPLES) + len(INJECTION_SAMPLES)} total   ║")
    print(f"  ╚═══════════════════════════════════════════════════════════╝")
    print(f"{RESET}")

    pii_metrics = await eval_pii(verbose)
    if pii_metrics is None:
        return

    inj_metrics = await eval_injection(verbose)
    if inj_metrics is None:
        return

    # ── Combined summary ──
    print(f"\n{'='*70}")
    print(f"  {BOLD}{CYAN}COMBINED SUMMARY{RESET}")
    print(f"{'='*70}")
    print()

    total_samples = len(PII_SAMPLES) + len(INJECTION_SAMPLES)
    total_tp = pii_metrics["tp"] + inj_metrics["tp"]
    total_fp = pii_metrics["fp"] + inj_metrics["fp"]
    total_tn = pii_metrics["tn"] + inj_metrics["tn"]
    total_fn = pii_metrics["fn"] + inj_metrics["fn"]
    total_correct = total_tp + total_tn
    total_evaluated = total_tp + total_fp + total_tn + total_fn

    print(f"  {'Category':<25} {'TP':>4} {'FP':>4} {'TN':>4} {'FN':>4}  {'Prec':>7} {'Recall':>7} {'F1':>7} {'Acc':>7}")
    print(f"  {'-'*25} {'----':>4} {'----':>4} {'----':>4} {'----':>4}  {'-------':>7} {'-------':>7} {'-------':>7} {'-------':>7}")
    print(f"  {'PII Detection':<25} {pii_metrics['tp']:>4} {pii_metrics['fp']:>4} {pii_metrics['tn']:>4} {pii_metrics['fn']:>4}"
          f"  {pii_metrics['precision']:>6.1%} {pii_metrics['recall']:>6.1%} {pii_metrics['f1']:>6.1%} {pii_metrics['accuracy']:>6.1%}")
    print(f"  {'Injection Detection':<25} {inj_metrics['tp']:>4} {inj_metrics['fp']:>4} {inj_metrics['tn']:>4} {inj_metrics['fn']:>4}"
          f"  {inj_metrics['precision']:>6.1%} {inj_metrics['recall']:>6.1%} {inj_metrics['f1']:>6.1%} {inj_metrics['accuracy']:>6.1%}")
    print(f"  {'-'*25} {'----':>4} {'----':>4} {'----':>4} {'----':>4}  {'-------':>7} {'-------':>7} {'-------':>7} {'-------':>7}")

    overall_acc = total_correct / total_evaluated if total_evaluated > 0 else 0
    print(f"  {'TOTAL':<25} {total_tp:>4} {total_fp:>4} {total_tn:>4} {total_fn:>4}  {'':>7} {'':>7} {'':>7} {overall_acc:>6.1%}")
    print()
    print(f"  {BOLD}Overall: {total_correct}/{total_evaluated} correct ({overall_acc:.1%}){RESET}")
    if total_fp > 0:
        print(f"  {YELLOW}False positives: {total_fp} benign messages were incorrectly flagged{RESET}")
    if total_fn > 0:
        print(f"  {RED}False negatives: {total_fn} real threats/PII were missed{RESET}")
    print(f"\n{'='*70}\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="TP/FP Evaluation for Bedrock Guardrails Proxy")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Show result for every individual sample")
    args = parser.parse_args()

    try:
        asyncio.run(main(verbose=args.verbose))
    except KeyboardInterrupt:
        print(f"\n{DIM}Interrupted.{RESET}")
