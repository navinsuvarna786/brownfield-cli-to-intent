# AI Modernization Report

Date: 2026-04-29 11:57:39.915405

## AI Decision Confidence
| Field | Confidence | Reason |
|---|---|---|
| `hostname` | **0** | Hostname is missing in config and legacy parser |

### ⚠️ Ambiguity Report (Humans Review Required)
- **hostname**: Confidence 0 < 0.8. Reason: Hostname is missing in config and legacy parser

## Execution Trace
- **Legacy Parser**: success (Extracted 28 keys.)
- **Intent Mapper**: success (Mapped intent with LLM (Merged legacy arrays).)
- **Schema Normalizer**: success (Normalized data structure.)
- **Validator**: failed (Found 1 issues.)
- **Intent Mapper**: success (Mapped intent with LLM (Merged legacy arrays).)
- **Schema Normalizer**: success (Normalized data structure.)
- **Validator**: failed (Found 1 issues.)
- **Intent Mapper**: success (Mapped intent with LLM (Merged legacy arrays).)
- **Schema Normalizer**: success (Normalized data structure.)
- **Validator**: failed (Found 1 issues.)

## Final Validation Status
- Valid: False
- Score: 0.8
- Issues:
  - [error] hostname: Hostname is missing