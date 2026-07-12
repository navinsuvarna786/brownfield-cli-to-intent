# NX-OS LLM Fallback Evaluation — Results

Generated: 2026-05-01T19:30:24.513355
Total configs: 15  |  Wall-clock: 221.6s

## Validity Summary

| Metric | Value |
|--------|-------|
| Schema validity | 100.0% (15/15) |
| Semantic validity | 100.0% (15/15) |
| Median latency | 14355 ms |
| Macro F1 (GT subset, n=12) | 0.217 |

## Outcome Distribution

| Outcome | Count |
|---------|-------|
| auto_corrected | 14 |
| no_validation_result | 1 |

## Rules Fired

| Rule ID | Count |
|---------|-------|

## Field-Level F1 by Config (GT subset)

| Config | Role | Precision | Recall | F1 | OC |
|--------|------|-----------|--------|----|----|
| campus-nx-access01 | access-nac | 0.145 | 0.198 | 0.167 | 0.284 |
| campus-nx-access02 | access-nac | 0.175 | 0.225 | 0.197 | 0.319 |
| campus-nx-access03 | access-no-nac | 0.181 | 0.244 | 0.208 | 0.366 |
| campus-nx-access04 | access-nac | 0.166 | 0.217 | 0.188 | 0.322 |
| campus-nx-core01 | core | 0.185 | 0.449 | 0.262 | 0.564 |
| campus-nx-dist01 | distribution | 0.171 | 0.360 | 0.232 | 0.474 |
| campus-nx-dist02 | distribution | 0.157 | 0.325 | 0.212 | 0.439 |
| campus-nx-dist03 | distribution-vpc | 0.176 | 0.371 | 0.239 | 0.495 |
| campus-nx-dist04 | distribution-vpc | 0.179 | 0.371 | 0.241 | 0.495 |
| campus-nx-oob01 | oob-server | 0.102 | 0.170 | 0.127 | 0.372 |
| campus-nx-remote01 | remote-edge | 0.217 | 0.310 | 0.255 | 0.420 |
| campus-nx-wan01 | wan-aggregation | 0.206 | 0.416 | 0.276 | 0.545 |

## Per-Config Pipeline Results

| Config | Role | Path | Iters | Outcome | Schema | Sem | Lat (ms) |
|--------|------|------|-------|---------|--------|-----|----------|
| DATACTR-NXOS-SW01.txt | oob-server | llm→norm→val | 1 | auto_corrected | ✓ | ✓ | 13736 |
| DATACTR-NXOS-SW02.txt | oob-server | llm→norm→val | 1 | auto_corrected | ✓ | ✓ | 14518 |
| DATACTR-NXOS-SW03.txt | oob-server | llm→norm→val | 1 | auto_corrected | ✓ | ✓ | 14355 |
| CAMPUS-NX-ACCESS01.txt | access-nac | llm→norm→val | 1 | auto_corrected | ✓ | ✓ | 17315 |
| CAMPUS-NX-ACCESS02.txt | access-nac | llm→norm→val | 1 | auto_corrected | ✓ | ✓ | 13986 |
| CAMPUS-NX-ACCESS03.txt | access-no-nac | llm→norm→val | 1 | auto_corrected | ✓ | ✓ | 12907 |
| CAMPUS-NX-ACCESS04.txt | access-nac | llm→norm→val | 1 | auto_corrected | ✓ | ✓ | 14653 |
| CAMPUS-NX-DIST01.txt | distribution | llm→norm→val | 1 | auto_corrected | ✓ | ✓ | 16594 |
| CAMPUS-NX-DIST02.txt | distribution | llm→norm→val | 1 | no_validation_result | ✓ | ✓ | 15494 |
| CAMPUS-NX-DIST03.txt | distribution-vpc | llm→norm→val | 1 | auto_corrected | ✓ | ✓ | 15650 |
| CAMPUS-NX-DIST04.txt | distribution-vpc | llm→norm→val | 1 | auto_corrected | ✓ | ✓ | 14016 |
| CAMPUS-NX-CORE01.txt | core | llm→norm→val | 1 | auto_corrected | ✓ | ✓ | 12426 |
| CAMPUS-NX-OOB01.txt | oob-server | llm→norm→val | 1 | auto_corrected | ✓ | ✓ | 23365 |
| CAMPUS-NX-REMOTE01.txt | remote-edge | llm→norm→val | 1 | auto_corrected | ✓ | ✓ | 10900 |
| CAMPUS-NX-WAN01.txt | wan-aggregation | llm→norm→val | 1 | auto_corrected | ✓ | ✓ | 11606 |
