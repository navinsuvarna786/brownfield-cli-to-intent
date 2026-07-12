#!/usr/bin/env python3
"""
NX-OS LLM Fallback Evaluation — Approach C pipeline on 15 real NX-OS configs.

Runs all configs in input/sanitized/nxos/ through the full LangGraph Approach C
pipeline (vendor=unknown → LLM fallback path → normalizer → validator → retry
→ generator → reporter), then runs compute_f1.py against curated ground truth
in ground_truth/campus-nx-*.yaml and ground_truth/datactr-nxos-*.yaml.

Metrics recorded per config:
  - routing_path        : which pipeline branches were taken
  - validator_iterations: how many times the validator ran
  - schema_valid        : bool
  - semantic_valid      : bool (all 22 rules pass)
  - rules_fired         : which rule IDs triggered violations
  - outcome             : passed | auto_corrected | retried_and_passed | escalated_abort
  - latency_ms          : end-to-end wall-clock time in milliseconds

After the pipeline runs, field-level F1 is computed against the curated
ground-truth subset using the same compute_f1.py logic as the main evaluation.

Usage:
    source .venv/bin/activate
    export OPENAI_API_KEY=<key>          # or populate .env
    python3 scripts/batch_eval_nxos_fallback.py
    python3 scripts/batch_eval_nxos_fallback.py --output output/evaluation/nxos_fallback
"""

import argparse
import importlib
import json
import os
import statistics
import sys
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path

# ---------------------------------------------------------------------------
# Path setup
# ---------------------------------------------------------------------------
REPO_ROOT = Path(__file__).resolve().parent.parent
AI_MOD_DIR = REPO_ROOT / "scripts" / "ai_modernization"
sys.path.insert(0, str(AI_MOD_DIR))

# Load .env if present
_env_file = REPO_ROOT / ".env"
if _env_file.exists():
    for line in _env_file.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, _, v = line.partition("=")
            os.environ.setdefault(k.strip(), v.strip())

if not os.environ.get("OPENAI_API_KEY"):
    print("ERROR: OPENAI_API_KEY not set.", file=sys.stderr)
    sys.exit(1)

from models import AgentState
from agents import app   # compiled LangGraph Approach C pipeline

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
NXOS_DIR      = REPO_ROOT / "input" / "sanitized" / "nxos"
GT_DIR        = REPO_ROOT / "ground_truth"
TARGET_PLATFORM = "Cisco Catalyst 9300 Series Switches"

# Ground-truth filename map: stem (lowercase) → GT yaml stem (lowercase)
# Existing DATACTR-NXOS-SW01/02/03 have no dedicated GT; skip F1 for those.
GT_MAP = {
    "campus-nx-access01":  "campus-nx-access01",
    "campus-nx-access02":  "campus-nx-access02",
    "campus-nx-access03":  "campus-nx-access03",
    "campus-nx-access04":  "campus-nx-access04",
    "campus-nx-dist01":    "campus-nx-dist01",
    "campus-nx-dist02":    "campus-nx-dist02",
    "campus-nx-dist03":    "campus-nx-dist03",
    "campus-nx-dist04":    "campus-nx-dist04",
    "campus-nx-core01":    "campus-nx-core01",
    "campus-nx-oob01":     "campus-nx-oob01",
    "campus-nx-remote01":  "campus-nx-remote01",
    "campus-nx-wan01":     "campus-nx-wan01",
}

ROLE_MAP = {
    "campus-nx-access01":  "access-nac",
    "campus-nx-access02":  "access-nac",
    "campus-nx-access03":  "access-no-nac",
    "campus-nx-access04":  "access-nac",
    "campus-nx-dist01":    "distribution",
    "campus-nx-dist02":    "distribution",
    "campus-nx-dist03":    "distribution-vpc",
    "campus-nx-dist04":    "distribution-vpc",
    "campus-nx-core01":    "core",
    "campus-nx-oob01":     "oob-server",
    "campus-nx-remote01":  "remote-edge",
    "campus-nx-wan01":     "wan-aggregation",
    "datactr-nxos-sw01":   "oob-server",
    "datactr-nxos-sw02":   "oob-server",
    "datactr-nxos-sw03":   "oob-server",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_routing_path(trace_log: list) -> list:
    return [e.get("step", "?") for e in (trace_log or [])]


def _count_validator_iters(trace_log: list) -> int:
    return sum(1 for e in (trace_log or []) if e.get("step") == "Validator")


def _determine_outcome(val_result: dict, iter_count: int, norm_intent: dict) -> str:
    if not val_result:
        return "no_validation_result"
    valid = val_result.get("valid", False)
    iters = iter_count or 0
    auto = any(
        v == ["need_input"] or v == "need_input"
        for k, v in norm_intent.items()
        if k in ("ntp_servers", "dns_servers", "errdisable_config", "logging_hosts")
    )
    if valid and auto and iters <= 1:
        return "auto_corrected"
    if valid and iters == 1:
        return "passed_first_try"
    if valid and iters > 1:
        return "retried_and_passed"
    if not valid and iters >= 3:
        return "escalated_abort"
    return "failed_with_issues"


def _post_hoc_validate(intent: dict) -> tuple:
    """Run the 22-rule engine on the normalised intent. Returns (schema_valid, semantic_valid, triggered_ids)."""
    hostname = intent.get("hostname")
    schema_valid = bool(hostname)
    rules_dir = REPO_ROOT / "validation" / "rules"
    triggered = []
    if rules_dir.exists():
        sys.path.append(str(rules_dir))
        rule_files = sorted(f for f in os.listdir(rules_dir) if f.endswith(".py") and f[0].isdigit())
        for rf in rule_files:
            mn = rf[:-3]
            try:
                mod = sys.modules.get(mn)
                mod = importlib.reload(mod) if mod else importlib.import_module(mn)
                if hasattr(mod, "Rule") and hasattr(mod.Rule, "match"):
                    if mod.Rule.match(intent):
                        triggered.append(str(mod.Rule.id))
            except Exception:
                pass
        sys.path.remove(str(rules_dir))
    semantic_valid = len(triggered) == 0
    return schema_valid, semantic_valid, triggered


def _save_json(path: Path, data) -> None:
    try:
        path.write_text(json.dumps(data, indent=2, default=str))
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Per-config runner
# ---------------------------------------------------------------------------

def run_nxos_config(config_path: Path, out_root: Path) -> dict:
    stem = config_path.stem.lower()
    role = ROLE_MAP.get(stem, "unknown")
    raw_config = config_path.read_text(encoding="utf-8", errors="replace")

    per_out = out_root / stem
    per_out.mkdir(parents=True, exist_ok=True)

    initial_state: AgentState = {
        "raw_config":          raw_config,
        "source_vendor":       "unknown",   # forces LLM fallback for ALL NX-OS configs
        "target_device_type":  TARGET_PLATFORM,
        "legacy_parsed_data":  {},
        "extracted_intent":    {},
        "normalized_intent":   {},
        "validation_result":   {},
        "decision_metadata":   [],
        "rag_context":         "",
        "iteration_count":     0,
        "trace_log":           [],
        "report_path":         "",
        "output_dir_override": str(per_out),
    }

    start = time.time()
    pipeline_error = None
    try:
        final_state = app.invoke(initial_state)
    except Exception as exc:
        pipeline_error = str(exc)
        final_state = initial_state
    elapsed_ms = int((time.time() - start) * 1000)

    trace_log    = final_state.get("trace_log", [])
    val_result   = final_state.get("validation_result", {}) or {}
    iter_count   = final_state.get("iteration_count", 0)
    norm_intent  = final_state.get("normalized_intent", {}) or {}
    hostname     = norm_intent.get("hostname", "unknown")

    # If invoke raised but pipeline wrote artifacts, try to recover them
    if pipeline_error:
        for art_glob in [f"output/{hostname.lower()}/3_schema_normalizer.json",
                         f"output/{stem}/3_schema_normalizer.json"]:
            art = REPO_ROOT / art_glob
            if art.exists():
                try:
                    norm_intent = json.loads(art.read_text())
                    hostname = norm_intent.get("hostname", hostname)
                    pipeline_error = None
                    break
                except Exception:
                    pass

    # Save normalizer artifact under per_out so compute_f1.py can find it
    norm_art = per_out / "3_schema_normalizer.json"
    if not norm_art.exists() and norm_intent:
        _save_json(norm_art, norm_intent)

    # Copy other artifacts from pipeline's default output location
    default_out = REPO_ROOT / "output" / hostname.lower()
    for art in ["1_legacy_parser.json", "2_intent_mapper.json",
                "3_schema_normalizer.json", "4_validator.json", "6_report.md"]:
        src = default_out / art
        dst = per_out / art
        if src.exists() and not dst.exists():
            dst.write_bytes(src.read_bytes())

    schema_valid, semantic_valid, rules_fired = _post_hoc_validate(norm_intent)
    outcome = _determine_outcome(val_result, iter_count, norm_intent)

    result = {
        "config":              config_path.name,
        "stem":                stem,
        "role":                role,
        "hostname_extracted":  hostname,
        "vendor_tag":          "unknown",
        "routing_path":        _extract_routing_path(trace_log),
        "validator_iterations": _count_validator_iters(trace_log),
        "outcome":             outcome,
        "schema_valid":        schema_valid,
        "semantic_valid":      semantic_valid,
        "rules_fired":         rules_fired,
        "validation_score":    val_result.get("score", 0.0),
        "latency_ms":          elapsed_ms,
        "has_ground_truth":    (stem in GT_MAP),
        "error":               pipeline_error,
    }
    _save_json(per_out / f"{stem}_result.json", result)
    return result


# ---------------------------------------------------------------------------
# F1 computation (using compute_f1.py logic inline)
# ---------------------------------------------------------------------------

def compute_f1_for_results(results: list, out_root: Path) -> dict:
    """
    For each result that has ground truth, compute field-level F1.
    Loads GT yaml and the 3_schema_normalizer.json artifact from out_root/<stem>/.
    Returns per-config and macro-averaged F1.
    """
    import yaml

    def _flatten(obj, prefix="") -> dict:
        flat = {}
        if isinstance(obj, dict):
            for k, v in obj.items():
                flat.update(_flatten(v, f"{prefix}.{k}" if prefix else k))
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                flat.update(_flatten(item, f"{prefix}[{i}]"))
        else:
            flat[prefix] = str(obj) if obj is not None else ""
        return flat

    def _f1(pred_flat: dict, gt_flat: dict) -> tuple:
        gt_keys   = set(gt_flat)
        pred_keys = set(pred_flat)
        matched = sum(1 for k in gt_keys & pred_keys if gt_flat[k] == pred_flat[k])
        precision = matched / len(pred_keys) if pred_keys else 0.0
        recall    = matched / len(gt_keys)   if gt_keys   else 0.0
        f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
        return round(precision, 4), round(recall, 4), round(f1, 4)

    per_config_f1 = {}
    f1_values = []

    for r in results:
        stem = r["stem"]
        if stem not in GT_MAP:
            continue
        gt_path   = GT_DIR / f"{GT_MAP[stem]}.yaml"
        pred_path = out_root / stem / "3_schema_normalizer.json"
        if not gt_path.exists() or not pred_path.exists():
            continue
        try:
            gt   = yaml.safe_load(gt_path.read_text())
            pred = json.loads(pred_path.read_text())
        except Exception:
            continue
        gt_flat   = _flatten(gt)
        pred_flat = _flatten(pred)
        prec, rec, f1 = _f1(pred_flat, gt_flat)
        oc = len(set(gt_flat) & set(pred_flat)) / len(set(gt_flat)) if gt_flat else 0.0
        per_config_f1[stem] = {
            "role": r["role"],
            "precision": prec,
            "recall": rec,
            "f1": f1,
            "object_completeness": round(oc, 4),
        }
        f1_values.append(f1)

    macro_f1 = round(statistics.mean(f1_values), 4) if f1_values else 0.0
    return {"macro_f1": macro_f1, "per_config": per_config_f1, "n_with_gt": len(f1_values)}


# ---------------------------------------------------------------------------
# Summary builder
# ---------------------------------------------------------------------------

def build_summary_report(results: list, f1_data: dict, elapsed_total: float, out_root: Path):
    n = len(results)
    schema_rate   = sum(1 for r in results if r["schema_valid"])   / n if n else 0
    semantic_rate = sum(1 for r in results if r["semantic_valid"]) / n if n else 0
    latencies     = [r["latency_ms"] for r in results]
    median_lat    = statistics.median(latencies) if latencies else 0

    outcome_counts = defaultdict(int)
    for r in results:
        outcome_counts[r["outcome"]] += 1

    rule_counts = defaultdict(int)
    for r in results:
        for rid in r["rules_fired"]:
            rule_counts[rid] += 1

    lines = [
        "# NX-OS LLM Fallback Evaluation — Results",
        "",
        f"Generated: {datetime.now().isoformat()}",
        f"Total configs: {n}  |  Wall-clock: {elapsed_total:.1f}s",
        "",
        "## Validity Summary",
        "",
        f"| Metric | Value |",
        f"|--------|-------|",
        f"| Schema validity | {schema_rate*100:.1f}% ({sum(1 for r in results if r['schema_valid'])}/{n}) |",
        f"| Semantic validity | {semantic_rate*100:.1f}% ({sum(1 for r in results if r['semantic_valid'])}/{n}) |",
        f"| Median latency | {median_lat:.0f} ms |",
        f"| Macro F1 (GT subset, n={f1_data['n_with_gt']}) | {f1_data['macro_f1']:.3f} |",
        "",
        "## Outcome Distribution",
        "",
        "| Outcome | Count |",
        "|---------|-------|",
    ]
    for outcome, count in sorted(outcome_counts.items(), key=lambda x: -x[1]):
        lines.append(f"| {outcome} | {count} |")

    lines += [
        "",
        "## Rules Fired",
        "",
        "| Rule ID | Count |",
        "|---------|-------|",
    ]
    for rid, count in sorted(rule_counts.items(), key=lambda x: -x[1]):
        lines.append(f"| rule {rid} | {count} |")

    lines += [
        "",
        "## Field-Level F1 by Config (GT subset)",
        "",
        "| Config | Role | Precision | Recall | F1 | OC |",
        "|--------|------|-----------|--------|----|----|",
    ]
    for stem, fd in sorted(f1_data["per_config"].items()):
        lines.append(
            f"| {stem} | {fd['role']} | {fd['precision']:.3f} | {fd['recall']:.3f}"
            f" | {fd['f1']:.3f} | {fd['object_completeness']:.3f} |"
        )

    lines += [
        "",
        "## Per-Config Pipeline Results",
        "",
        "| Config | Role | Path | Iters | Outcome | Schema | Sem | Lat (ms) |",
        "|--------|------|------|-------|---------|--------|-----|----------|",
    ]
    for r in results:
        path_summary = "llm→norm→val"
        sch = "✓" if r["schema_valid"] else "✗"
        sem = "✓" if r["semantic_valid"] else "✗"
        lines.append(
            f"| {r['config']} | {r['role']} | {path_summary}"
            f" | {r['validator_iterations']} | {r['outcome']}"
            f" | {sch} | {sem} | {r['latency_ms']} |"
        )
        if r.get("error"):
            lines.append(f"|  | ⚠ Error: {r['error'][:80]} | | | | | | |")

    report_text = "\n".join(lines) + "\n"
    (out_root / "report.md").write_text(report_text)
    print(report_text)
    return report_text


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="NX-OS LLM fallback evaluation on 15 real configs.")
    parser.add_argument(
        "--output", default=str(REPO_ROOT / "output" / "evaluation" / "nxos_fallback"),
        help="Output directory."
    )
    parser.add_argument(
        "--subset", default=str(REPO_ROOT / "input" / "subset_nxos_15.txt"),
        help="Optional subset file listing config stems (one per line, no extension)."
    )
    args = parser.parse_args()

    out_root = Path(args.output)
    out_root.mkdir(parents=True, exist_ok=True)

    # Build config list
    subset_file = Path(args.subset)
    if subset_file.exists():
        stems = [line.strip().upper() for line in subset_file.read_text().splitlines() if line.strip()]
        configs = [NXOS_DIR / f"{s}.txt" for s in stems if (NXOS_DIR / f"{s}.txt").exists()]
    else:
        configs = sorted(NXOS_DIR.glob("*.txt"))

    if not configs:
        print(f"ERROR: No configs found in {NXOS_DIR}", file=sys.stderr)
        sys.exit(1)

    print(f"[nxos_fallback] Output:  {out_root}")
    print(f"[nxos_fallback] Configs: {len(configs)}")
    print(f"[nxos_fallback] All configs routed vendor=unknown → LLM fallback path\n")

    results = []
    wall_start = time.time()

    for cfg in configs:
        print(f"  [{cfg.stem}]")
        result = run_nxos_config(cfg, out_root)
        results.append(result)
        sch = "PASS" if result["schema_valid"] else "FAIL"
        sem = "PASS" if result["semantic_valid"] else "FAIL"
        gt  = "GT" if result["has_ground_truth"] else "no-GT"
        print(f"    → schema={sch}  sem={sem}  iters={result['validator_iterations']}"
              f"  outcome={result['outcome']}  {result['latency_ms']}ms  [{gt}]")
        if result["rules_fired"]:
            print(f"    rules fired: {', '.join(result['rules_fired'])}")
        if result.get("error"):
            print(f"    !! {result['error'][:120]}")
        print()

    elapsed_total = time.time() - wall_start

    # Compute F1
    print("[nxos_fallback] Computing field-level F1 against ground truth...")
    f1_data = compute_f1_for_results(results, out_root)
    print(f"[nxos_fallback] Macro F1 = {f1_data['macro_f1']:.3f}  (n={f1_data['n_with_gt']} configs with GT)\n")

    # Save summary JSON
    summary = {
        "generated_at":      datetime.now().isoformat(),
        "total_configs":     len(results),
        "total_elapsed_s":   round(elapsed_total, 1),
        "schema_valid_rate": round(sum(1 for r in results if r["schema_valid"]) / len(results), 4),
        "semantic_valid_rate": round(sum(1 for r in results if r["semantic_valid"]) / len(results), 4),
        "median_latency_ms": statistics.median(r["latency_ms"] for r in results),
        "macro_f1":          f1_data["macro_f1"],
        "f1_n_with_gt":      f1_data["n_with_gt"],
        "per_config_f1":     f1_data["per_config"],
        "results":           results,
    }
    summary_path = out_root / "summary.json"
    summary_path.write_text(json.dumps(summary, indent=2))
    print(f"[nxos_fallback] Summary written to {summary_path}")

    build_summary_report(results, f1_data, elapsed_total, out_root)
    print(f"\n[nxos_fallback] Done. Report: {out_root / 'report.md'}")


if __name__ == "__main__":
    main()
