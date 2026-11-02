
from __future__ import annotations

import csv
import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CODE_DIR = ROOT / "code"
DATASET = ROOT / "dataset"

SAMPLE_REQUESTS = DATASET / "sample_deletion_requests.csv"
SAMPLE_OUTPUT = DATASET / "sample_output.csv"
REPORT = CODE_DIR / "evaluation" / "evaluation_report.md"

STEP_FIELDS = [
    "step_no",
    "phase",
    "system_id",
    "resource_id",
    "operation",
    "state",
    "evidence_id",
]


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def canonical_steps(value: str) -> list[dict]:
    steps = json.loads(value or "[]")
    if not isinstance(steps, list):
        raise ValueError("steps_json must be a JSON array")

    result = []
    for step in steps:
        if not isinstance(step, dict):
            raise ValueError("Each step must be a JSON object")
        result.append({field: step.get(field) for field in STEP_FIELDS})
    return result


def main() -> int:
    if not SAMPLE_REQUESTS.exists():
        raise FileNotFoundError(f"Missing {SAMPLE_REQUESTS}")
    if not SAMPLE_OUTPUT.exists():
        raise FileNotFoundError(f"Missing {SAMPLE_OUTPUT}")

    # Import the same inference implementation used for the final output.
    sys.path.insert(0, str(CODE_DIR))

    from main import (
        load_identity_index,
        load_evidence_records,
        load_rules,
        process_request,
        validate_output,
        request_authorizes_deletion,
    )

    requests = read_csv(SAMPLE_REQUESTS)
    gold_rows = read_csv(SAMPLE_OUTPUT)

    gold = {row["case_id"]: row for row in gold_rows}
    request_ids = {row["case_id"] for row in requests}

    if request_ids != set(gold):
        raise ValueError(
            "Sample request IDs and gold IDs do not match. "
            f"Requests only: {sorted(request_ids - set(gold))[:10]}; "
            f"Gold only: {sorted(set(gold) - request_ids)[:10]}"
        )

    print("Loading identity index and evidence...")
    identities, reverse = load_identity_index()
    observations = load_evidence_records()
    rules = load_rules()

    predictions = []
    for index, request in enumerate(requests, 1):
        predictions.append(
            process_request(
                request,
                identities,
                reverse,
                observations,
                rules,
            )
        )
        if index % 10 == 0:
            print(f"Evaluated {index}/{len(requests)} sample requests")

    predictions.sort(key=lambda row: row["case_id"])
    validate_output(predictions, requests)
    pred = {row["case_id"]: row for row in predictions}

    # Keep sample predictions separate from the real submission output.csv.
    sample_prediction_path = CODE_DIR / "evaluation" / "sample_predictions.csv"
    sample_prediction_path.parent.mkdir(parents=True, exist_ok=True)

    with sample_prediction_path.open(
        "w", encoding="utf-8", newline=""
    ) as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["case_id", "deletion_status", "steps_json"],
        )
        writer.writeheader()
        writer.writerows(predictions)

    total = len(gold_rows)
    status_correct = 0
    exact_rows = 0
    exact_sequences = 0
    gold_step_count = 0
    predicted_step_count = 0
    position_matches = 0
    field_correct = Counter()
    field_total = Counter()
    case_details = []

    for case_id in sorted(gold):
        expected = gold[case_id]
        actual = pred[case_id]

        status_ok = (
            actual["deletion_status"] == expected["deletion_status"]
        )
        status_correct += int(status_ok)

        expected_steps = canonical_steps(expected["steps_json"])
        actual_steps = canonical_steps(actual["steps_json"])

        sequence_ok = actual_steps == expected_steps
        exact_sequences += int(sequence_ok)

        row_ok = (
            status_ok
            and actual["deletion_status"] == expected["deletion_status"]
            and sequence_ok
        )
        exact_rows += int(row_ok)

        gold_step_count += len(expected_steps)
        predicted_step_count += len(actual_steps)

        # Compare steps by position and each individual field.
        for i, expected_step in enumerate(expected_steps):
            if i < len(actual_steps):
                actual_step = actual_steps[i]
                position_matches += int(actual_step == expected_step)

                for field in STEP_FIELDS:
                    field_total[field] += 1
                    field_correct[field] += int(
                        actual_step[field] == expected_step[field]
                    )
            else:
                for field in STEP_FIELDS:
                    field_total[field] += 1

        case_details.append({
            "case_id": case_id,
            "status_ok": status_ok,
            "sequence_ok": sequence_ok,
            "gold_steps": len(expected_steps),
            "pred_steps": len(actual_steps),
        })

    status_accuracy = status_correct / total if total else 0
    row_accuracy = exact_rows / total if total else 0
    sequence_accuracy = exact_sequences / total if total else 0
    step_accuracy = (
        position_matches / gold_step_count if gold_step_count else 1.0
    )

    field_lines = []
    for field in STEP_FIELDS:
        correct = field_correct[field]
        count = field_total[field]
        accuracy = correct / count if count else 1.0
        field_lines.append(
            f"| {field} | {correct} | {count} | {accuracy:.2%} |"
        )

    status_counts = Counter(
        row["deletion_status"] for row in predictions
    )

    # Additional intent-classification tests. These do not replace the
    # canonical sample comparison.
    custom_cases = [
        (
            "Explicit account deletion",
            "Please delete my account and erase my personal data.",
            True,
        ),
        (
            "Access request only",
            "Please provide a copy of my personal data for access.",
            False,
        ),
        (
            "Marketing opt-out only",
            "Please unsubscribe me and stop marketing emails.",
            False,
        ),
    ]

    custom_results = []
    for label, text, expected in custom_cases:
        actual = request_authorizes_deletion(text)
        custom_results.append({
            "name": label,
            "expected": expected,
            "actual": actual,
            "passed": actual == expected,
        })

    custom_lines = [
        f"| {x['name']} | {x['expected']} | {x['actual']} | "
        f"{'PASS' if x['passed'] else 'FAIL'} |"
        for x in custom_results
    ]

    failures = [
        row for row in case_details
        if not row["status_ok"] or not row["sequence_ok"]
    ]

    failure_lines = [
        f"| {x['case_id']} | {x['status_ok']} | "
        f"{x['sequence_ok']} | {x['gold_steps']} | {x['pred_steps']} |"
        for x in failures
    ]

    report = f"""# Evaluation Report

## Dataset

- Evaluation source: `dataset/sample_deletion_requests.csv`
- Gold labels: `dataset/sample_output.csv`
- Number of evaluated cases: {total}
- Cases with matching IDs: {len(set(pred) & set(gold))}

## Case-level metrics

| Metric | Correct | Total | Accuracy |
|---|---:|---:|---:|
| Deletion status accuracy | {status_correct} | {total} | {status_accuracy:.2%} |
| Exact row accuracy (status and complete steps) | {exact_rows} | {total} | {row_accuracy:.2%} |
| Exact ordered sequence accuracy | {exact_sequences} | {total} | {sequence_accuracy:.2%} |
| Position-wise step accuracy | {position_matches} | {gold_step_count} | {step_accuracy:.2%} |

## Field-level metrics

| Field | Correct | Total | Accuracy |
|---|---:|---:|---:|
{chr(10).join(field_lines)}

## Output counts

- Gold rows: {total}
- Predicted rows: {len(predictions)}
- Gold steps: {gold_step_count}
- Predicted steps: {predicted_step_count}
- COMPLETE: {status_counts.get("COMPLETE", 0)}
- INCOMPLETE: {status_counts.get("INCOMPLETE", 0)}
- NOT_APPLICABLE: {status_counts.get("NOT_APPLICABLE", 0)}

## Additional evaluation cases

| Test | Expected deletion intent | Actual | Result |
|---|---|---|---|
{chr(10).join(custom_lines)}

These are additional request-intent tests. They do not count as additional
end-to-end deletion-audit cases.

## Cases requiring review

| Case ID | Status correct | Sequence correct | Gold steps | Predicted steps |
|---|---|---|---:|---:|
{chr(10).join(failure_lines) if failure_lines else "| None | — | — | — | — |"}

## Failure analysis and improvement plan

Review incorrect sample cases by failure category:

1. Identity resolution: current and historical email, phone, and user ID.
2. Evidence cutoff: ignore evidence captured after `audit_at`.
3. Resource state: distinguish current state from historical activity and
   claimed workflow status.
4. Policy: apply the exact conditional treatment in `deletion_rules.csv`.
5. Data flows and backups: detect recreation risks and order their remediation.
6. Retention: preserve required records while removing prohibited identifiers.
7. Output: ensure exact operations, states, evidence references, and order.

Fix observed root causes in the inference logic and rerun this evaluation.
Do not hardcode sample case IDs or copy gold answers into prediction logic.

## Limitations

The current implementation is a deterministic baseline. Public-sample accuracy
does not establish performance on the hidden test set. PDF and image evidence
may not be fully parsed unless optional extraction dependencies are available.

## Usage report

See `code/evaluation/usage_report.md` for full-dataset model calls, tokens,
and cost. The deterministic baseline uses no remote model calls.
"""

    REPORT.write_text(report, encoding="utf-8")

    print()
    print(f"Sample cases:      {total}")
    print(f"Status accuracy:   {status_accuracy:.2%}")
    print(f"Exact row accuracy:{row_accuracy:.2%}")
    print(f"Step accuracy:     {step_accuracy:.2%}")
    print(f"Sequence accuracy: {sequence_accuracy:.2%}")
    print(f"Report:            {REPORT}")
    print(f"Predictions:       {sample_prediction_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
