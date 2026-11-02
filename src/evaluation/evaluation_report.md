# Evaluation Report

## Dataset

- Evaluation source: `dataset/sample_deletion_requests.csv`
- Gold labels: `dataset/sample_output.csv`
- Number of evaluated cases: 32
- Cases with matching IDs: 32

## Case-level metrics

| Metric | Correct | Total | Accuracy |
|---|---:|---:|---:|
| Deletion status accuracy | 21 | 32 | 65.62% |
| Exact row accuracy (status and complete steps) | 3 | 32 | 9.38% |
| Exact ordered sequence accuracy | 3 | 32 | 9.38% |
| Position-wise step accuracy | 35 | 193 | 18.13% |

## Field-level metrics

| Field | Correct | Total | Accuracy |
|---|---:|---:|---:|
| step_no | 89 | 193 | 46.11% |
| phase | 60 | 193 | 31.09% |
| system_id | 41 | 193 | 21.24% |
| resource_id | 38 | 193 | 19.69% |
| operation | 39 | 193 | 20.21% |
| state | 44 | 193 | 22.80% |
| evidence_id | 69 | 193 | 35.75% |

## Output counts

- Gold rows: 32
- Predicted rows: 32
- Gold steps: 193
- Predicted steps: 93
- COMPLETE: 7
- INCOMPLETE: 22
- NOT_APPLICABLE: 3

## Additional evaluation cases

| Test | Expected deletion intent | Actual | Result |
|---|---|---|---|
| Explicit account deletion | True | True | PASS |
| Access request only | False | False | PASS |
| Marketing opt-out only | False | False | PASS |

These are additional request-intent tests. They do not count as additional
end-to-end deletion-audit cases.

## Cases requiring review

| Case ID | Status correct | Sequence correct | Gold steps | Predicted steps |
|---|---|---|---:|---:|
| case_01 | False | False | 1 | 0 |
| case_02 | False | False | 1 | 0 |
| case_03 | True | False | 3 | 1 |
| case_04 | False | False | 2 | 0 |
| case_06 | True | False | 4 | 0 |
| case_07 | True | False | 4 | 0 |
| case_08 | True | False | 4 | 0 |
| case_09 | True | False | 5 | 3 |
| case_10 | True | False | 4 | 0 |
| case_12 | False | False | 5 | 0 |
| case_13 | True | False | 8 | 8 |
| case_15 | False | False | 5 | 1 |
| case_16 | True | False | 7 | 4 |
| case_17 | True | False | 5 | 6 |
| case_18 | True | False | 14 | 6 |
| case_19 | True | False | 8 | 4 |
| case_20 | True | False | 8 | 6 |
| case_21 | True | False | 3 | 1 |
| case_22 | False | False | 8 | 1 |
| case_23 | True | False | 8 | 0 |
| case_24 | False | False | 7 | 0 |
| case_25 | True | False | 3 | 1 |
| case_26 | False | False | 6 | 7 |
| case_27 | False | False | 6 | 7 |
| case_28 | False | False | 6 | 7 |
| case_29 | True | False | 14 | 3 |
| case_30 | True | False | 14 | 3 |
| case_31 | True | False | 3 | 1 |
| case_32 | False | False | 5 | 1 |

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
