# AI Modernization Report

Date: 2026-04-29 11:55:03.540690

## AI Decision Confidence
| Field | Confidence | Reason |
|---|---|---|
| `aaa.tacacs_servers.key` | **0.9** | key masked as 'need_input' in config |
| `aaa.radius_servers.key` | **0.9** | key masked as 'xxxxxxxx' in config |
| `local_users.secret` | **0.9** | secret masked as 'need_input' in config |
| `interfaces.authentication.mab` | **1** | explicit mab configured on interfaces GigabitEthernet1/0/1 and 1/0/2 |
| `interfaces.storm_control` | **1** | storm-control broadcast and multicast levels configured on access interfaces |

## Execution Trace
- **Legacy Parser**: success (Extracted 28 keys.)
- **Cisco Mapper**: success (Deterministic map: 3 VLANs, 2 access intfs, 1 SVIs, 0 loopbacks, 0 ACLs)
- **Intent Mapper**: success (Mapped intent with LLM (Merged legacy arrays).)
- **Schema Normalizer**: success (Normalized data structure.)
- **Validator**: success (Found 0 issues.)
- **Generator**: success (Generated using schema-driven template mapping (9 day-N templates))

## Final Validation Status
- Valid: True
- Score: 1.0