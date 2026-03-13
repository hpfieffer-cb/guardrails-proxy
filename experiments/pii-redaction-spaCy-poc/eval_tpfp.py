"""
TP/FP Evaluation Suite — spaCy + Regex + Injection Guard
=========================================================
Runs all synthetic samples through the PII redactor (spaCy NER + regex)
and injection guard (pattern + heuristic), then displays:
  - Per-sample TP/FP/TN/FN classification
  - Confusion matrix
  - Precision, Recall, F1 Score, Accuracy, FP Rate

Usage:
    python3 eval_tpfp.py              # summary only
    python3 eval_tpfp.py --verbose    # per-sample classification
    NER_BACKEND=none python3 eval_tpfp.py   # regex-only mode
"""

import argparse
import logging
import os
import sys

logging.basicConfig(level=logging.WARNING, format="%(levelname)s: %(message)s")

# Import shared dataset from /datasets
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "datasets"))
from synthetic_dataset import PII_SAMPLES, GUARD_SAMPLES
from redactor import PIIRedactor
from injection_guard import InjectionGuard, ThreatLevel

# ── ANSI colors ──
CYAN = "\033[36m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
RED = "\033[31m"
DIM = "\033[2m"
BOLD = "\033[1m"
RESET = "\033[0m"


# ── Metrics ──────────────────────────────────────────────────────────────────

def _print_metrics(tp, fp, tn, fn, label):
    """Print a confusion matrix and metrics — matches v1.1 Bedrock style."""
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
    print(f"  {BOLD}Precision:{RESET}  {precision:.1%}")
    print(f"  {BOLD}Recall:{RESET}     {recall:.1%}")
    print(f"  {BOLD}F1 Score:{RESET}   {f1:.1%}")
    print(f"  {BOLD}Accuracy:{RESET}   {accuracy:.1%}  ({tp + tn}/{total} correct)")
    print(f"  {BOLD}FP Rate:{RESET}    {fpr:.1%}")

    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn,
            "precision": precision, "recall": recall, "f1": f1,
            "accuracy": accuracy, "fpr": fpr}


# ── PII Evaluation ───────────────────────────────────────────────────────────

def eval_pii(redactor: PIIRedactor, verbose: bool = False) -> dict:
    """Evaluate PII detection. Returns metrics dict."""
    print(f"\n{'=' * 70}")
    print(f"  {BOLD}PII DETECTION EVALUATION{RESET}  ({len(PII_SAMPLES)} samples)")
    print(f"  Positive = contains PII | Negative = no PII")
    print(f"{'=' * 70}")

    tp = fp = tn = fn = 0

    for i, sample in enumerate(PII_SAMPLES, 1):
        _, detected = redactor.redact(sample["input"])
        detected_types = {e.entity_type for e in detected}
        expected = set(sample["expected_pii"])
        has_pii = len(expected) > 0
        found_something = len(detected_types) > 0

        if has_pii and found_something:
            tp += 1
            label = f"{GREEN}TP{RESET}"
        elif has_pii and not found_something:
            fn += 1
            label = f"{RED}FN{RESET}"
        elif not has_pii and found_something:
            fp += 1
            label = f"{YELLOW}FP{RESET}"
        else:
            tn += 1
            label = f"{GREEN}TN{RESET}"

        if verbose:
            entities = sorted(detected_types) if detected_types else []
            entity_str = f" {DIM}entities={entities}{RESET}" if entities else ""
            print(f"  [{i:>2}] {label}  {sample['description']}{entity_str}")
            if not has_pii and found_something:
                print(f"       {DIM}\"{sample['input'][:80]}...\"{RESET}")
                print(f"       {DIM}Detected: {sorted(detected_types)}{RESET}")
            elif has_pii and not found_something:
                print(f"       {DIM}\"{sample['input'][:80]}...\"{RESET}")
                print(f"       {DIM}Expected: {sorted(expected)}, Got: {sorted(detected_types)}{RESET}")

    return _print_metrics(tp, fp, tn, fn, "PII Detection")


# ── Injection Guard Evaluation ───────────────────────────────────────────────

def eval_injection(guard: InjectionGuard, verbose: bool = False) -> dict:
    """Evaluate injection/content guard. Returns metrics dict."""
    print(f"\n{'=' * 70}")
    print(f"  {BOLD}INJECTION / CONTENT GUARD EVALUATION{RESET}  ({len(GUARD_SAMPLES)} samples)")
    print(f"  Positive = should be blocked/flagged | Negative = clean message")
    print(f"{'=' * 70}")

    tp = fp = tn = fn = 0

    for i, sample in enumerate(GUARD_SAMPLES, 1):
        result = guard.analyze(sample["input"])
        expected = sample["expected_result"]
        actual = result.threat_level.value

        # Classification logic:
        # - blocked/suspicious expected and blocked/suspicious actual → TP
        # - clean expected and clean actual → TN
        # - clean expected but blocked/suspicious actual → FP
        # - blocked/suspicious expected but clean actual → FN
        expected_positive = expected in ("blocked", "suspicious")
        actual_positive = actual in ("blocked", "suspicious")

        if expected_positive and actual_positive:
            tp += 1
            label = f"{GREEN}TP{RESET}"
        elif not expected_positive and not actual_positive:
            tn += 1
            label = f"{GREEN}TN{RESET}"
        elif not expected_positive and actual_positive:
            fp += 1
            label = f"{YELLOW}FP{RESET}"
        else:
            fn += 1
            label = f"{RED}FN{RESET}"

        if verbose:
            reason = ""
            if result.matched_patterns:
                reason += f" patterns={result.matched_patterns[:3]}"
            if result.categories:
                reason += f" categories={result.categories}"
            reason_str = f" {DIM}(expected={expected}, actual={actual}, score={result.score:.2f}{reason}){RESET}"
            print(f"  [{i:>2}] {label}  {sample['description']}{reason_str}")
            if (expected_positive and not actual_positive) or (not expected_positive and actual_positive):
                print(f"       {DIM}\"{sample['input'][:80]}...\"{RESET}")

    return _print_metrics(tp, fp, tn, fn, "Injection / Content Guard")


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="TP/FP Evaluation Suite")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Show per-sample classification")
    args = parser.parse_args()

    backend = os.getenv("NER_BACKEND", "spacy").lower()

    print(f"\n{BOLD}{CYAN}")
    print(f"  ╔═══════════════════════════════════════════════════════════╗")
    print(f"  ║   TP/FP Evaluation — spaCy + Regex + Injection Guard    ║")
    print(f"  ║   PII Redaction POC (spaCy v1.1)                        ║")
    print(f"  ║   Synthetic Dataset: {len(PII_SAMPLES)} PII + {len(GUARD_SAMPLES)} Guard = {len(PII_SAMPLES) + len(GUARD_SAMPLES)} total     ║")
    print(f"  ╚═══════════════════════════════════════════════════════════╝")
    print(f"{RESET}")
    print(f"  NER backend: {backend}")
    print(f"  PII samples: {len(PII_SAMPLES)} ({sum(1 for s in PII_SAMPLES if s['expected_pii'])} positive, "
          f"{sum(1 for s in PII_SAMPLES if not s['expected_pii'])} negative)")
    print(f"  Guard samples: {len(GUARD_SAMPLES)} ({sum(1 for s in GUARD_SAMPLES if s['expected_result'] != 'clean')} positive, "
          f"{sum(1 for s in GUARD_SAMPLES if s['expected_result'] == 'clean')} negative)")

    print(f"\n  Loading models...")
    redactor = PIIRedactor()
    guard = InjectionGuard()

    # PII evaluation
    pii_metrics = eval_pii(redactor, verbose=args.verbose)

    # Injection guard evaluation
    guard_metrics = eval_injection(guard, verbose=args.verbose)

    # ── Combined summary ──
    print(f"\n{'=' * 70}")
    print(f"  {BOLD}{CYAN}COMBINED SUMMARY{RESET}")
    print(f"{'=' * 70}")
    print()

    total_samples = len(PII_SAMPLES) + len(GUARD_SAMPLES)
    total_tp = pii_metrics["tp"] + guard_metrics["tp"]
    total_fp = pii_metrics["fp"] + guard_metrics["fp"]
    total_tn = pii_metrics["tn"] + guard_metrics["tn"]
    total_fn = pii_metrics["fn"] + guard_metrics["fn"]
    total_correct = total_tp + total_tn
    total_evaluated = total_tp + total_fp + total_tn + total_fn

    print(f"  {'Category':<25} {'TP':>4} {'FP':>4} {'TN':>4} {'FN':>4}  {'Prec':>7} {'Recall':>7} {'F1':>7} {'Acc':>7}")
    print(f"  {'-' * 25} {'----':>4} {'----':>4} {'----':>4} {'----':>4}  {'-------':>7} {'-------':>7} {'-------':>7} {'-------':>7}")
    print(f"  {'PII Detection':<25} {pii_metrics['tp']:>4} {pii_metrics['fp']:>4} {pii_metrics['tn']:>4} {pii_metrics['fn']:>4}"
          f"  {pii_metrics['precision']:>6.1%} {pii_metrics['recall']:>6.1%} {pii_metrics['f1']:>6.1%} {pii_metrics['accuracy']:>6.1%}")
    print(f"  {'Injection/Content Guard':<25} {guard_metrics['tp']:>4} {guard_metrics['fp']:>4} {guard_metrics['tn']:>4} {guard_metrics['fn']:>4}"
          f"  {guard_metrics['precision']:>6.1%} {guard_metrics['recall']:>6.1%} {guard_metrics['f1']:>6.1%} {guard_metrics['accuracy']:>6.1%}")
    print(f"  {'-' * 25} {'----':>4} {'----':>4} {'----':>4} {'----':>4}  {'-------':>7} {'-------':>7} {'-------':>7} {'-------':>7}")

    overall_acc = total_correct / total_evaluated if total_evaluated > 0 else 0
    print(f"  {'TOTAL':<25} {total_tp:>4} {total_fp:>4} {total_tn:>4} {total_fn:>4}  {'':>7} {'':>7} {'':>7} {overall_acc:>6.1%}")
    print()
    print(f"  {BOLD}Overall: {total_correct}/{total_evaluated} correct ({overall_acc:.1%}){RESET}")
    if total_fp > 0:
        print(f"  {YELLOW}False positives: {total_fp} benign messages were incorrectly flagged{RESET}")
    if total_fn > 0:
        print(f"  {RED}False negatives: {total_fn} real threats/PII were missed{RESET}")
    print(f"\n{'=' * 70}\n")


if __name__ == "__main__":
    main()
