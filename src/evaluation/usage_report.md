# Token Usage and Cost Report

## Final full-dataset run

- Date: 2026-10-25T04:03:08.254783+00:00
- Requests processed: 518
- Evidence files listed in manifest: 94
- Model provider: None (deterministic local Python implementation)
- Model name: None
- Model calls: 0
- Input tokens: 0
- Output tokens: 0
- Total tokens: 0
- Average tokens per request: 0
- Estimated total model cost: USD 0.00
- Estimated model cost per request: USD 0.00

## Method

This run uses local CSV parsing, evidence parsing, identifier matching, policy rules,
and deterministic output generation. No remote model API is called. Token counts and
model cost are therefore zero; local CPU/runtime cost is not represented as model cost.

## Limitations

PDF extraction and image OCR are attempted only when optional dependencies are installed.
A clean run without those dependencies still processes CSV, JSON, SQL, logs, and text.
