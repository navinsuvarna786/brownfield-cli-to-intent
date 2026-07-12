# Fallback / Recovery Stress Test — Results

Generated: 2026-04-29T11:57:39.917013
Total wall-clock time: 73.9s

## Design

Five synthetic configs probe the routing and recovery paths that are not
exercised by the main 34-config corpus (which uses only cisco/arista vendors).
The point is not translation accuracy. The point is to show that unsupported
or degraded inputs are **routed explicitly** to the LLM/retry/escalation path
and are **never silently accepted** as valid output.

## Results Summary

| # | Config | Vendor tag | Routing path | Validator iterations | Outcome | Latency (ms) |
|---|--------|------------|--------------|---------------------|---------|-------------|
| 1 | `STRESS-UNKNOWN-VENDOR-SW01` | `unknown` | Legacy Parser → Intent Mapper → Schema Normalizer → Validator → Generator | 1 | Pass (first attempt) | 15177 |
| 2 | `STRESS-SNMPV3-ONLY-SW01` | `unknown` | Legacy Parser → Intent Mapper → Schema Normalizer → Validator → Generator | 1 | Pass (first attempt) | 8950 |
| 3 | `STRESS-DEGRADED-CISCO-SW01` | `cisco` | Legacy Parser → Cisco Mapper → Intent Mapper → Schema Normalizer → Validator → Cisco Mapper → ... | 2 | Escalated / aborted (max retries exceeded) | 25386 |
| 4 | `STRESS-AUTOCORRECT-SW01` | `cisco` | Legacy Parser → Cisco Mapper → Intent Mapper → Schema Normalizer → Validator → Generator | 1 | Pass (first attempt) | 13790 |
| 5 | `STRESS-MAXDEGRADED-SW01` | `unknown` | Legacy Parser → Intent Mapper → Schema Normalizer → Validator → Intent Mapper → Schema Normalizer → ... | 3 | Escalated / aborted (max retries exceeded) | 10554 |

## Per-Config Detail

### STRESS-UNKNOWN-VENDOR-SW01

- **Vendor tag**: `unknown`
- **Hostname extracted**: `STRESS-UNKNOWN-VENDOR-SW01`
- **Full routing path**: Legacy Parser → Intent Mapper → Schema Normalizer → Validator → Generator
- **Validator iterations**: 1
- **Outcome**: Pass (first attempt)
- **Valid**: True  |  **Score**: 1.00
- **Latency**: 15177 ms
- **Auto-corrections fired**:
  - rule121: stp_mode='need_input'
  - rule121: logging_hosts=['need_input']
  - rule121: errdisable_config.causes=['need_input']

### STRESS-SNMPV3-ONLY-SW01

- **Vendor tag**: `unknown`
- **Hostname extracted**: `STRESS-SNMPV3-ONLY-SW01`
- **Full routing path**: Legacy Parser → Intent Mapper → Schema Normalizer → Validator → Generator
- **Validator iterations**: 1
- **Outcome**: Pass (first attempt)
- **Valid**: True  |  **Score**: 1.00
- **Latency**: 8950 ms
- **Auto-corrections fired**:
  - rule121: stp_mode='need_input'
  - rule121: errdisable_config.causes=['need_input']

### STRESS-DEGRADED-CISCO-SW01

- **Vendor tag**: `cisco`
- **Hostname extracted**: `unknown`
- **Full routing path**: Legacy Parser → Cisco Mapper → Intent Mapper → Schema Normalizer → Validator → Cisco Mapper → Intent Mapper → Schema Normalizer → Validator
- **Validator iterations**: 2
- **Outcome**: Escalated / aborted (max retries exceeded)
- **Valid**: False  |  **Score**: 0.80
- **Latency**: 25386 ms
- **Validation issues**:
  - [error] hostname: Hostname is missing

### STRESS-AUTOCORRECT-SW01

- **Vendor tag**: `cisco`
- **Hostname extracted**: `STRESS-AUTOCORRECT-SW01`
- **Full routing path**: Legacy Parser → Cisco Mapper → Intent Mapper → Schema Normalizer → Validator → Generator
- **Validator iterations**: 1
- **Outcome**: Pass (first attempt)
- **Valid**: True  |  **Score**: 1.00
- **Latency**: 13790 ms
- **Auto-corrections fired**:
  - rule121: ntp_servers=['need_input']
  - rule121: dns_servers=['need_input']
  - rule121: stp_mode='need_input'
  - rule121: errdisable_config.causes=['need_input']

### STRESS-MAXDEGRADED-SW01

- **Vendor tag**: `unknown`
- **Hostname extracted**: `unknown`
- **Full routing path**: Legacy Parser → Intent Mapper → Schema Normalizer → Validator → Intent Mapper → Schema Normalizer → Validator → Intent Mapper → Schema Normalizer → Validator
- **Validator iterations**: 3
- **Outcome**: Escalated / aborted (max retries exceeded)
- **Valid**: False  |  **Score**: 0.80
- **Latency**: 10554 ms
- **Validation issues**:
  - [error] hostname: Hostname is missing

## Interpretation

- Configs 1–2 (`unknown` vendor) are routed to the LLM fallback path,
  bypassing the deterministic parsers entirely. The LLM receives the raw
  config, the schema definition, and any prior validation feedback.

- Config 3 (`cisco`, hostname stripped) triggers the deterministic parser
  then fails validation. The `cisco_mapper_retry` → `llm_mapper` edge
  injects the validator error list into the next LLM prompt.

- Config 4 (`cisco`, NTP+DNS missing) passes through `_auto_correct_intent()`
  which applies Rule 121 placeholders. Output YAML contains explicit
  `need_input` tokens rather than silently empty fields.

- Config 5 (severely degraded, `unknown`) exhausts all three retry iterations.
  `check_validation()` returns `abort`, and the reporter agent emits
  `6_report.md` listing every unresolved issue — no partial YAML is accepted.

Together these five cases demonstrate that the multi-agent workflow provides
**explicit routing**, **traceable feedback**, and **controlled escalation** for
inputs outside the deterministic parser's coverage.
