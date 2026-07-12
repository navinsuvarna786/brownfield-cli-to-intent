#!/usr/bin/env python3
"""
Approach B — Single-pass LLM evaluation.

This script implements the LLM-only baseline (Approach B) for the
brownfield-to-intent paper A/B/C comparison. It runs:

    legacy_parser → llm_mapper → generator

with NO schema normalizer, NO validator, and NO retry loop.
The generator receives the raw LLM output directly.

"Single-pass LLM" means: one GPT-4 call per config, no guardrails,
no self-correction. The raw LLM dict is fed straight to the generator.
Generator failure rate and field accuracy compared against C isolates
the value of the normalizer + validator guardrails.

Metrics recorded per config (matching Approach C column names):
  - yaml_generated      : bool
  - schema_valid        : bool (post-hoc: hostname present at root)
  - semantic_valid      : bool (post-hoc: all 20 rules pass)
  - triggered_rules     : list of rule IDs that fired violations
  - latency_ms          : end-to-end wall-clock time in milliseconds
  - stage_times         : parse_s, llm_s, generate_s
  - llm_invoked         : True

Requires:
  OPENAI_API_KEY environment variable (or .env file at repo root)

Usage:
    export OPENAI_API_KEY=<key>
    python3 scripts/batch_eval_approach_b.py [--output output/evaluation/approach_b]
    python3 scripts/batch_eval_approach_b.py --subset input/subset_17.txt
"""

import argparse
import json
import os
import sys
import time
import statistics
import importlib
from collections import defaultdict
from datetime import datetime
from pathlib import Path

# ---------------------------------------------------------------------------
# Path setup
# ---------------------------------------------------------------------------
REPO_ROOT = Path(__file__).resolve().parent.parent
AI_MOD_DIR = REPO_ROOT / "scripts" / "ai_modernization"
sys.path.insert(0, str(AI_MOD_DIR))

# Load .env if present (picks up OPENAI_API_KEY without shell export)
_env_file = REPO_ROOT / ".env"
if _env_file.exists():
    for line in _env_file.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, _, v = line.partition("=")
            os.environ.setdefault(k.strip(), v.strip())

if not os.environ.get("OPENAI_API_KEY"):
    print("ERROR: OPENAI_API_KEY is not set. Cannot run Approach B.", file=sys.stderr)
    print("       Set it via: export OPENAI_API_KEY=<key>", file=sys.stderr)
    print("       Or create a .env file at the repo root (see .env.example).", file=sys.stderr)
    sys.exit(1)

from models import AgentState
from agents import (
    agent_legacy_parser,
    agent_intent_mapper,   # LLM mapper — the only LLM call in Approach B
    agent_generator,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
CISCO_DIR = REPO_ROOT / "input" / "sanitized" / "cisco"
ARISTA_DIR = REPO_ROOT / "input" / "sanitized" / "arista"
TARGET_PLATFORM = "Cisco Catalyst 9300 Series Switches"

ALL_TEMPLATE_TYPES = [
    "EDGE_PNP_template",
    "EDGE_SYSTEM_template",
    "EDGE_VLAN_template",
    "EDGE_MGMT_template",
    "EDGE_ACL_template",
    "EDGE_UPLINK_template",
    "EDGE_SNMP_template",
    "EDGE_AAA_template",
    "EDGE_NAC_template",
    "EDGE_ACCESS_PORT_template",
    "EDGE_ROUTED_PORT_template",
]


def _classify_group(filename: str) -> str:
    fn = filename.upper()
    if fn.startswith("BLDG-FR") or fn.startswith("BLDG-A") or fn.startswith("BLDG-B") or fn.startswith("BLDG-C"):
        return "access-nac"
    if fn.startswith("DATACTR"):
        return "oob-server"
    if fn.startswith("DIST-"):
        return "distribution"
    if fn.startswith("EDGE-SW-REMOTE"):
        return "remote-edge"
    if fn.startswith("BLDG-VA"):
        return "building-simple"
    if fn.startswith("CAMPUS"):
        return "arista-distribution"
    return "other"


# ---------------------------------------------------------------------------
# Post-hoc validation (same rule engine as Approach C for fair comparison)
# ---------------------------------------------------------------------------

def _post_hoc_validate(intent: dict) -> tuple[bool, bool, list[str]]:
    """
    Run structural + semantic rule engine on the raw LLM output dict.
    Returns (schema_valid, semantic_valid, triggered_rule_ids).
    """
    hostname = intent.get("hostname") or (
        intent.get("system", {}).get("hostname")
        if isinstance(intent.get("system"), dict) else None
    )
    schema_valid = bool(hostname)

    rules_dir = REPO_ROOT / "validation" / "rules"
    triggered: list[str] = []

    if rules_dir.exists():
        sys.path.append(str(rules_dir))
        rule_files = sorted(
            f for f in os.listdir(rules_dir)
            if f.endswith(".py") and f[0].isdigit()
        )
        for rf in rule_files:
            module_name = rf[:-3]
            try:
                if module_name in sys.modules:
                    module = importlib.reload(sys.modules[module_name])
                else:
                    module = importlib.import_module(module_name)
                if hasattr(module, "Rule") and hasattr(module.Rule, "match"):
                    results = module.Rule.match(intent)
                    if results:
                        triggered.append(str(module.Rule.id))
            except Exception:
                pass
        sys.path.remove(str(rules_dir))

    semantic_valid = len(triggered) == 0
    return schema_valid, semantic_valid, triggered


# ---------------------------------------------------------------------------
# Per-config runner
# ---------------------------------------------------------------------------

def run_config_approach_b(config_path: Path, vendor: str, output_subdir: Path) -> dict:
    """
    Single-pass LLM path: legacy_parser → llm_mapper → generator.
    No normalizer. No validator. No retry.
    """
    filename = config_path.name
    stem = config_path.stem.lower()
    group = _classify_group(filename)

    try:
        raw_config = config_path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return _error_record(filename, vendor, group, str(exc))

    # Build per-device output directory (mirrors batch_eval.py convention)
    device_out_dir = output_subdir / stem
    device_out_dir.mkdir(parents=True, exist_ok=True)

    state: AgentState = {
        "raw_config": raw_config,
        "source_filename": filename,
        "target_device_type": TARGET_PLATFORM,
        "source_vendor": vendor,
        "output_dir": str(device_out_dir),
        "trace_log": [],
        "legacy_parsed_data": {},
        "extracted_intent": {},
        "decision_metadata": [],
        "normalized_intent": {},
        "validation_result": None,
        "iteration_count": 0,
        "rag_context": "",
        "final_yaml_output": "",
        "final_output_path": "",
        "report_path": "",
    }
    state = dict(state)

    stage_times: dict = {}

    # --- Stage 1: Legacy parser (provides structured context for LLM) ---
    t0 = time.perf_counter()
    try:
        state.update(agent_legacy_parser(state))
        stage_times["parse_s"] = round(time.perf_counter() - t0, 4)
    except Exception as exc:
        return _error_record(filename, vendor, group, f"parse stage: {exc}")

    # --- Stage 2: Single LLM call (no retry, no feedback injection) ---
    # Ensure validation_result is None so llm_mapper injects no feedback
    state["validation_result"] = None
    t1 = time.perf_counter()
    try:
        state.update(agent_intent_mapper(state))
        stage_times["llm_s"] = round(time.perf_counter() - t1, 4)
    except Exception as exc:
        stage_times["llm_s"] = round(time.perf_counter() - t1, 4)
        return _error_record(filename, vendor, group, f"llm_mapper stage: {exc}")

    # Approach B: feed raw LLM output directly to generator — no normalizer
    raw_llm_output = state.get("extracted_intent") or state.get("legacy_parsed_data") or {}
    state["normalized_intent"] = raw_llm_output

    # Save raw LLM output for inspection / ground-truth comparison
    _save_json(device_out_dir / "2_llm_mapper_raw.json", raw_llm_output)
    # Also save as 3_schema_normalizer.json so compute_f1.py can find it
    _save_json(device_out_dir / "3_schema_normalizer.json", raw_llm_output)

    # --- Stage 3: Generator (raw LLM dict, no guardrails) ---
    t2 = time.perf_counter()
    yaml_generated = False
    generated_templates: list[str] = []
    generator_error = None
    try:
        state.update(agent_generator(state))
        stage_times["generate_s"] = round(time.perf_counter() - t2, 4)
        yaml_generated = bool(state.get("final_output_path"))
        generated_templates = _extract_template_names(state)
    except Exception as exc:
        stage_times["generate_s"] = round(time.perf_counter() - t2, 4)
        generator_error = str(exc)

    total_elapsed = round(time.perf_counter() - t0, 4)

    # --- Post-hoc validity on raw LLM output ---
    schema_valid, semantic_valid, triggered_rules = _post_hoc_validate(raw_llm_output)

    return {
        "file": filename,
        "vendor": vendor,
        "group": group,
        "path": "llm_single_pass",
        "approach": "B",
        "llm_invoked": True,
        "total_elapsed_s": total_elapsed,
        "stage_times": stage_times,
        "schema_valid": schema_valid,
        "semantic_valid": semantic_valid,
        "rules_fired": triggered_rules,
        "yaml_generated": yaml_generated,
        "templates_generated": generated_templates,
        "template_count": len(generated_templates),
        "generator_error": generator_error,
    }


def _save_json(path: Path, data: dict) -> None:
    try:
        path.write_text(json.dumps(data, indent=2, default=str))
    except Exception:
        pass


def _extract_template_names(state: dict) -> list:
    yaml_str = state.get("final_yaml_output", "") or ""
    found = [t for t in ALL_TEMPLATE_TYPES if t in yaml_str]
    if not found and state.get("final_output_path"):
        try:
            import yaml as _yaml
            with open(state["final_output_path"]) as fh:
                data = _yaml.safe_load(fh)
            raw = json.dumps(data or {})
            found = [t for t in ALL_TEMPLATE_TYPES if t in raw]
        except Exception:
            pass
    return found


def _error_record(filename: str, vendor: str, group: str, msg: str) -> dict:
    return {
        "file": filename,
        "vendor": vendor,
        "group": group,
        "path": "error",
        "approach": "B",
        "llm_invoked": False,
        "total_elapsed_s": 0.0,
        "stage_times": {},
        "schema_valid": False,
        "semantic_valid": False,
        "rules_fired": [],
        "yaml_generated": False,
        "templates_generated": [],
        "template_count": 0,
        "generator_error": msg,
    }


# ---------------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------------

def compute_summary(results: list) -> dict:
    n = len(results)
    if n == 0:
        return {}

    latencies = [r["total_elapsed_s"] for r in results]
    llm_latencies = [r["stage_times"].get("llm_s", 0.0) for r in results if r["llm_invoked"]]
    schema_pass = [r for r in results if r["schema_valid"]]
    semantic_pass = [r for r in results if r["semantic_valid"]]
    yaml_ok = [r for r in results if r["yaml_generated"]]
    errors = [r for r in results if r["path"] == "error"]

    rule_counts: dict[str, int] = defaultdict(int)
    for r in results:
        for rule_id in r["rules_fired"]:
            rule_counts[rule_id] += 1

    template_counts: dict[str, int] = defaultdict(int)
    for r in results:
        for t in r["templates_generated"]:
            template_counts[t] += 1

    groups: dict[str, list] = defaultdict(list)
    for r in results:
        groups[r["group"]].append(r)

    group_stats = {}
    for grp, grp_results in sorted(groups.items()):
        gn = len(grp_results)
        group_stats[grp] = {
            "n": gn,
            "schema_valid_rate": round(sum(1 for r in grp_results if r["schema_valid"]) / gn, 3),
            "semantic_valid_rate": round(sum(1 for r in grp_results if r["semantic_valid"]) / gn, 3),
            "yaml_generated_rate": round(sum(1 for r in grp_results if r["yaml_generated"]) / gn, 3),
            "mean_latency_s": round(statistics.mean(r["total_elapsed_s"] for r in grp_results), 4),
            "mean_llm_latency_s": round(
                statistics.mean(r["stage_times"].get("llm_s", 0.0) for r in grp_results), 4
            ),
        }

    vendor_stats = {}
    for vendor in ("cisco", "arista"):
        vr = [r for r in results if r["vendor"] == vendor]
        if vr:
            vlat = [r["total_elapsed_s"] for r in vr]
            vendor_stats[vendor] = {
                "n": len(vr),
                "schema_valid_rate": round(sum(1 for r in vr if r["schema_valid"]) / len(vr), 3),
                "semantic_valid_rate": round(sum(1 for r in vr if r["semantic_valid"]) / len(vr), 3),
                "yaml_generated_rate": round(sum(1 for r in vr if r["yaml_generated"]) / len(vr), 3),
                "mean_latency_s": round(statistics.mean(vlat), 4),
                "median_latency_s": round(statistics.median(vlat), 4),
            }

    return {
        "approach": "B",
        "description": "Single-pass LLM: legacy_parser + llm_mapper + generator; no normalizer, no validator",
        "run_timestamp": datetime.now().isoformat(),
        "n_total": n,
        "n_cisco": sum(1 for r in results if r["vendor"] == "cisco"),
        "n_arista": sum(1 for r in results if r["vendor"] == "arista"),
        "n_llm_invoked": sum(1 for r in results if r["llm_invoked"]),
        "n_errors": len(errors),
        "schema_valid_count": len(schema_pass),
        "schema_valid_rate": round(len(schema_pass) / n, 4),
        "semantic_valid_count": len(semantic_pass),
        "semantic_valid_rate": round(len(semantic_pass) / n, 4),
        "yaml_generated_count": len(yaml_ok),
        "yaml_generated_rate": round(len(yaml_ok) / n, 4),
        "latency": {
            "mean_s": round(statistics.mean(latencies), 4),
            "median_s": round(statistics.median(latencies), 4),
            "stdev_s": round(statistics.stdev(latencies) if n > 1 else 0.0, 4),
            "min_s": round(min(latencies), 4),
            "max_s": round(max(latencies), 4),
        },
        "llm_latency": {
            "mean_s": round(statistics.mean(llm_latencies), 4) if llm_latencies else 0.0,
            "median_s": round(statistics.median(llm_latencies), 4) if llm_latencies else 0.0,
            "max_s": round(max(llm_latencies), 4) if llm_latencies else 0.0,
        },
        "rule_violation_summary": {
            rule_id: {"configs_affected": cnt}
            for rule_id, cnt in sorted(rule_counts.items())
        },
        "template_coverage": {
            t: {"count": template_counts.get(t, 0), "rate": round(template_counts.get(t, 0) / n, 3)}
            for t in ALL_TEMPLATE_TYPES
        },
        "by_vendor": vendor_stats,
        "by_group": group_stats,
    }


def format_report(summary: dict, results: list) -> str:
    lines = []
    n = summary["n_total"]
    lines.append("=" * 72)
    lines.append("  APPROACH B — Single-Pass LLM Evaluation")
    lines.append("  (no normalizer, no validator, no retry loop)")
    lines.append(f"  Run: {summary.get('run_timestamp', '')}")
    lines.append("=" * 72)
    lines.append(f"\nDataset : {n} configs ({summary['n_cisco']} Cisco, {summary['n_arista']} Arista)")
    lines.append(f"LLM calls: {summary['n_llm_invoked']} (1 per config, no retries)")
    lines.append(f"Errors  : {summary['n_errors']} pipeline errors\n")

    sv = summary["schema_valid_rate"]
    semv = summary["semantic_valid_rate"]
    yg = summary["yaml_generated_rate"]
    lines.append("VALIDITY RATES (post-hoc, over all configs):")
    lines.append(f"  Schema valid   : {sv:.1%}  ({summary['schema_valid_count']}/{n})")
    lines.append(f"  Semantic valid : {semv:.1%}  ({summary['semantic_valid_count']}/{n})")
    lines.append(f"  YAML generated : {yg:.1%}  ({summary['yaml_generated_count']}/{n})\n")

    lat = summary["latency"]
    llm_lat = summary.get("llm_latency", {})
    lines.append(f"TOTAL LATENCY: mean={lat['mean_s']:.3f}s  median={lat['median_s']:.3f}s  "
                 f"stdev={lat['stdev_s']:.3f}s  min={lat['min_s']:.3f}s  max={lat['max_s']:.3f}s")
    lines.append(f"LLM LATENCY:  mean={llm_lat.get('mean_s',0):.3f}s  "
                 f"median={llm_lat.get('median_s',0):.3f}s  max={llm_lat.get('max_s',0):.3f}s\n")

    lines.append("BY DEPLOYMENT GROUP:")
    for grp, gs in summary.get("by_group", {}).items():
        lines.append(f"  {grp:<22}  n={gs['n']:2d}  schema={gs['schema_valid_rate']:.1%}  "
                     f"semantic={gs['semantic_valid_rate']:.1%}  "
                     f"lat={gs['mean_latency_s']:.3f}s  llm={gs['mean_llm_latency_s']:.3f}s")
    lines.append("")

    rvs = summary.get("rule_violation_summary", {})
    lines.append("SEMANTIC RULE VIOLATIONS (post-hoc, rules 101-120):")
    if not rvs:
        lines.append("  None.")
    else:
        for rule_id, rv in sorted(rvs.items()):
            lines.append(f"  Rule {rule_id}: {rv['configs_affected']} config(s) affected")
    lines.append("")

    lines.append("PER-CONFIG DETAIL:")
    lines.append(f"  {'File':<36}  {'Grp':<20}  {'Tot(s)':>7}  {'LLM(s)':>7}  "
                 f"{'Sch':>4}  {'Sem':>4}  {'YAML':>4}  Rules")
    lines.append("  " + "-" * 115)
    for r in results:
        sch = "OK" if r["schema_valid"] else "FAIL"
        sem = "OK" if r["semantic_valid"] else "FAIL"
        yml = "YES" if r["yaml_generated"] else "NO"
        llm_s = r["stage_times"].get("llm_s", 0.0)
        rules = ",".join(r["rules_fired"]) if r["rules_fired"] else "-"
        gerr = f"  [gen_err: {r['generator_error'][:30]}]" if r.get("generator_error") else ""
        lines.append(f"  {r['file']:<36}  {r['group']:<20}  {r['total_elapsed_s']:>7.3f}  "
                     f"{llm_s:>7.3f}  {sch:>4}  {sem:>4}  {yml:>4}  {rules}{gerr}")
    lines.append("\n" + "=" * 72)
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Approach B (single-pass LLM) batch evaluation"
    )
    parser.add_argument("--output", default="output/evaluation/approach_b",
                        help="Directory to write results (default: output/evaluation/approach_b)")
    parser.add_argument("--cisco-dir", default=str(CISCO_DIR))
    parser.add_argument("--arista-dir", default=str(ARISTA_DIR))
    parser.add_argument(
        "--subset",
        default=None,
        help="Path to a file listing config stems (one per line) to evaluate. "
             "If omitted, all configs in cisco-dir and arista-dir are evaluated. "
             "Recommended: --subset input/subset_17.txt",
    )
    args = parser.parse_args()

    out_dir = REPO_ROOT / args.output
    out_dir.mkdir(parents=True, exist_ok=True)

    cisco_dir = Path(args.cisco_dir)
    arista_dir = Path(args.arista_dir)

    # Build full config list
    all_configs: list[tuple[Path, str]] = []
    if cisco_dir.exists():
        for p in sorted(cisco_dir.glob("*.txt")):
            all_configs.append((p, "cisco"))
    if arista_dir.exists():
        for p in sorted(arista_dir.glob("*.txt")):
            all_configs.append((p, "arista"))

    # Apply subset filter if provided
    if args.subset:
        subset_path = Path(args.subset)
        if not subset_path.exists():
            print(f"ERROR: subset file not found: {subset_path}", file=sys.stderr)
            sys.exit(1)
        stems = {
            Path(line.strip()).stem.upper()
            for line in subset_path.read_text().splitlines()
            if line.strip() and not line.startswith("#")
        }
        all_configs = [
            (p, v) for p, v in all_configs
            if p.stem.upper() in stems
        ]
        print(f"Subset filter applied: {len(all_configs)} configs selected from {subset_path.name}")

    configs = all_configs
    n_total = len(configs)
    if n_total == 0:
        print("ERROR: No configs found. Check --cisco-dir / --arista-dir / --subset.", file=sys.stderr)
        sys.exit(1)

    print(f"\nApproach B evaluation: {n_total} configs "
          f"({sum(1 for _, v in configs if v == 'cisco')} Cisco, "
          f"{sum(1 for _, v in configs if v == 'arista')} Arista)")
    print("  Single LLM pass per config. No normalizer. No validator. No retry.\n")

    results = []
    for i, (cfg_path, vendor) in enumerate(configs, 1):
        print(f"[{i:2d}/{n_total}] {cfg_path.name:<40}  vendor={vendor}", end="", flush=True)
        result = run_config_approach_b(cfg_path, vendor, out_dir)
        elapsed = result["total_elapsed_s"]
        llm_s = result["stage_times"].get("llm_s", 0.0)
        sch = "OK" if result["schema_valid"] else "FAIL"
        sem = "OK" if result["semantic_valid"] else "FAIL"
        yml = "GEN" if result["yaml_generated"] else "---"
        rules_str = f" rules={','.join(result['rules_fired'])}" if result["rules_fired"] else ""
        gerr_str = " gen_err!" if result.get("generator_error") else ""
        print(f"  {elapsed:.2f}s (llm={llm_s:.2f}s)  sch:{sch}  sem:{sem}  yaml:{yml}{rules_str}{gerr_str}")
        results.append(result)

    print(f"\nAll {n_total} configs processed.")
    summary = compute_summary(results)

    (out_dir / "per_config_results.json").write_text(json.dumps(results, indent=2, default=str))
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2, default=str))
    report_text = format_report(summary, results)
    (out_dir / "summary.txt").write_text(report_text)

    print(f"\nResults written to {out_dir}/")
    print(report_text)


if __name__ == "__main__":
    main()
