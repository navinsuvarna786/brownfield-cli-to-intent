#!/usr/bin/env python3
"""
Approach A — Rules-only baseline evaluation.

This script implements the rules-only baseline (Approach A) for the
brownfield-to-intent paper A/B/C comparison. It runs:

    parser → mapper → generator

skipping agent_schema_normalizer and agent_validator entirely. After
generation, schema validity and semantic validity are assessed post-hoc using
the same rule engine as Approach C, so that the comparison is fair.

"Rules-only" means: no LLM invocation, no schema normalization, no inline
validation guardrail. The generator receives the raw (un-normalized) mapped
intent and produces YAML directly from it.

Metrics recorded per config (matching Approach C column names):
  - yaml_generated      : bool
  - schema_valid        : bool (post-hoc: hostname present at root)
  - semantic_valid      : bool (post-hoc: all 20 rules pass)
  - triggered_rules     : list of rule IDs that fired violations
  - latency_ms          : end-to-end wall-clock time in milliseconds
  - stage_times         : parse_map_s, generate_s (no normalizer/validator stages)

Usage:
    python3 scripts/batch_eval_approach_a.py [--output output/evaluation/approach_a]
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

# Set a placeholder API key so agents.py initialises without raising at import.
# The LLM object (llm) is never called by Approach A.
os.environ.setdefault("OPENAI_API_KEY", "approach-a-no-llm-placeholder")

from models import AgentState
from agents import (
    agent_legacy_parser,
    agent_cisco_mapper,
    agent_arista_parser,
    agent_generator,
)

# ---------------------------------------------------------------------------
# Constants (mirror batch_eval.py)
# ---------------------------------------------------------------------------
CISCO_DIR = REPO_ROOT / "input" / "sanitized" / "cisco"
ARISTA_DIR = REPO_ROOT / "input" / "sanitized" / "arista"
TARGET_PLATFORM = "Cisco Catalyst 9300 Series Switches"
SOURCE_DEVICE_CISCO = "Cisco Catalyst 3850 Series Switches (Legacy)"
SOURCE_DEVICE_ARISTA = "Arista CCS-720XP-24ZY4"

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
# Post-hoc validation (mirrors validate_semantics in agents.py)
# ---------------------------------------------------------------------------

def _post_hoc_validate(intent: dict) -> tuple[bool, bool, list[str]]:
    """
    Run structural check + semantic rule engine on a (possibly un-normalized)
    intent dict. Returns (schema_valid, semantic_valid, triggered_rule_ids).
    """
    # Structural: hostname present at root
    hostname = intent.get("hostname") or (
        intent.get("system", {}).get("hostname")
        if isinstance(intent.get("system"), dict) else None
    )
    schema_valid = bool(hostname)

    # Semantic: load and run rules 101-120
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

def run_config_approach_a(config_path: Path, vendor: str) -> dict:
    """
    Rules-only path: parse → map → generate (no normalizer, no validator).
    Post-hoc validity is assessed after generation.
    """
    filename = config_path.name
    group = _classify_group(filename)

    try:
        raw_config = config_path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return _error_record(filename, vendor, group, str(exc))

    state: AgentState = {
        "raw_config": raw_config,
        "source_filename": filename,
        "target_device_type": TARGET_PLATFORM,
        "source_vendor": vendor,
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

    # --- Stage 1+2: Parse + Map ---
    t0 = time.perf_counter()
    try:
        if vendor == "cisco":
            state.update(agent_legacy_parser(state))
            state.update(agent_cisco_mapper(state))
            path = "cisco_deterministic_no_norm"
        elif vendor == "arista":
            state.update(agent_arista_parser(state))
            path = "arista_deterministic_no_norm"
        else:
            return _error_record(filename, vendor, group, f"Unknown vendor: {vendor}")
        stage_times["parse_map_s"] = round(time.perf_counter() - t0, 4)
    except Exception as exc:
        return _error_record(filename, vendor, group, f"parse/map stage: {exc}")

    # Approach A: the "normalized_intent" is the raw extracted_intent —
    # no normalization pass applied. The generator receives whatever the
    # mapper produced directly.
    raw_mapped = state.get("extracted_intent") or state.get("legacy_parsed_data") or {}
    state["normalized_intent"] = raw_mapped

    # --- Stage 3: Generator (directly on un-normalized intent) ---
    t1 = time.perf_counter()
    yaml_generated = False
    generated_templates: list[str] = []
    generator_error = None
    try:
        state.update(agent_generator(state))
        stage_times["generate_s"] = round(time.perf_counter() - t1, 4)
        yaml_generated = bool(state.get("final_output_path"))
        generated_templates = _extract_template_names(state)
    except Exception as exc:
        stage_times["generate_s"] = round(time.perf_counter() - t1, 4)
        generator_error = str(exc)

    total_elapsed = round(time.perf_counter() - t0, 4)

    # --- Post-hoc validity: run rule engine on the un-normalized intent ---
    schema_valid, semantic_valid, triggered_rules = _post_hoc_validate(raw_mapped)

    return {
        "file": filename,
        "vendor": vendor,
        "group": group,
        "path": path,
        "approach": "A",
        "llm_invoked": False,
        "total_elapsed_s": total_elapsed,
        "stage_times": stage_times,
        "schema_valid": schema_valid,
        "semantic_valid": semantic_valid,
        "rules_fired": triggered_rules,
        "yaml_generated": yaml_generated,
        "templates_generated": generated_templates,
        "template_count": len(generated_templates),
        "generator_error": generator_error,
        "_extracted_intent": raw_mapped,
    }


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
        "approach": "A",
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
    schema_pass = [r for r in results if r["schema_valid"]]
    semantic_pass = [r for r in results if r["semantic_valid"]]
    yaml_ok = [r for r in results if r["yaml_generated"]]
    errors = [r for r in results if r["path"] == "error"]

    rule_counts: dict[str, int] = defaultdict(int)
    rule_config_counts: dict[str, int] = defaultdict(int)
    for r in results:
        for rule_id in r["rules_fired"]:
            rule_counts[rule_id] += 1
            rule_config_counts[rule_id] += 1

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
        "approach": "A",
        "description": "Rules-only baseline: parse + map + generate; no normalizer, no validator",
        "run_timestamp": datetime.now().isoformat(),
        "n_total": n,
        "n_cisco": sum(1 for r in results if r["vendor"] == "cisco"),
        "n_arista": sum(1 for r in results if r["vendor"] == "arista"),
        "n_llm_invoked": 0,
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
        "rule_violation_summary": {
            rule_id: {"configs_affected": rule_config_counts[rule_id]}
            for rule_id in sorted(rule_counts.keys())
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
    lines.append("  APPROACH A — Rules-Only Baseline Evaluation")
    lines.append("  (no schema normalization, no inline validation guardrail)")
    lines.append(f"  Run: {summary.get('run_timestamp', '')}")
    lines.append("=" * 72)
    lines.append(f"\nDataset : {n} configs ({summary['n_cisco']} Cisco, {summary['n_arista']} Arista, 0 LLM)")
    lines.append(f"Errors  : {summary['n_errors']} pipeline errors\n")

    sv = summary["schema_valid_rate"]
    semv = summary["semantic_valid_rate"]
    yg = summary["yaml_generated_rate"]
    lines.append("VALIDITY RATES (post-hoc, over all configs):")
    lines.append(f"  Schema valid   : {sv:.1%}  ({summary['schema_valid_count']}/{n})")
    lines.append(f"  Semantic valid : {semv:.1%}  ({summary['semantic_valid_count']}/{n})")
    lines.append(f"  YAML generated : {yg:.1%}  ({summary['yaml_generated_count']}/{n})\n")

    lat = summary["latency"]
    lines.append(f"LATENCY: mean={lat['mean_s']:.3f}s  median={lat['median_s']:.3f}s  "
                 f"stdev={lat['stdev_s']:.3f}s  min={lat['min_s']:.3f}s  max={lat['max_s']:.3f}s\n")

    lines.append("BY DEPLOYMENT GROUP:")
    for grp, gs in summary.get("by_group", {}).items():
        lines.append(f"  {grp:<22}  n={gs['n']:2d}  schema={gs['schema_valid_rate']:.1%}  "
                     f"semantic={gs['semantic_valid_rate']:.1%}  lat={gs['mean_latency_s']:.3f}s")
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
    lines.append(f"  {'File':<36}  {'Grp':<20}  {'Lat(s)':>7}  {'Sch':>4}  {'Sem':>4}  {'YAML':>4}  Rules")
    lines.append("  " + "-" * 105)
    for r in results:
        sch = "OK" if r["schema_valid"] else "FAIL"
        sem = "OK" if r["semantic_valid"] else "FAIL"
        yml = "YES" if r["yaml_generated"] else "NO"
        rules = ",".join(r["rules_fired"]) if r["rules_fired"] else "-"
        gerr = f"  [gen_err: {r['generator_error'][:30]}]" if r.get("generator_error") else ""
        lines.append(f"  {r['file']:<36}  {r['group']:<20}  {r['total_elapsed_s']:>7.3f}  "
                     f"{sch:>4}  {sem:>4}  {yml:>4}  {rules}{gerr}")
    lines.append("\n" + "=" * 72)
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Approach A (rules-only baseline) batch evaluation"
    )
    parser.add_argument("--output", default="output/evaluation/approach_a",
                        help="Directory to write results (default: output/evaluation/approach_a)")
    parser.add_argument("--cisco-dir", default=str(CISCO_DIR))
    parser.add_argument("--arista-dir", default=str(ARISTA_DIR))
    args = parser.parse_args()

    out_dir = REPO_ROOT / args.output
    out_dir.mkdir(parents=True, exist_ok=True)

    cisco_dir = Path(args.cisco_dir)
    arista_dir = Path(args.arista_dir)

    configs: list[tuple[Path, str]] = []
    if cisco_dir.exists():
        for p in sorted(cisco_dir.glob("*.txt")):
            configs.append((p, "cisco"))
    else:
        print(f"WARNING: Cisco dir not found: {cisco_dir}", file=sys.stderr)

    if arista_dir.exists():
        for p in sorted(arista_dir.glob("*.txt")):
            configs.append((p, "arista"))
    else:
        print(f"WARNING: Arista dir not found: {arista_dir}", file=sys.stderr)

    n_total = len(configs)
    print(f"\nApproach A evaluation: {n_total} configs "
          f"({sum(1 for _, v in configs if v == 'cisco')} Cisco, "
          f"{sum(1 for _, v in configs if v == 'arista')} Arista)\n")

    results = []
    for i, (cfg_path, vendor) in enumerate(configs, 1):
        print(f"[{i:2d}/{n_total}] {cfg_path.name:<40}  vendor={vendor}", end="", flush=True)
        result = run_config_approach_a(cfg_path, vendor)
        # Save per-config extracted_intent for compute_f1.py
        stem = cfg_path.stem.lower()
        config_out_dir = out_dir / stem
        config_out_dir.mkdir(parents=True, exist_ok=True)
        intent = result.pop("_extracted_intent", {})
        (config_out_dir / "3_schema_normalizer.json").write_text(
            json.dumps(intent, indent=2, default=str)
        )
        elapsed = result["total_elapsed_s"]
        sch = "OK" if result["schema_valid"] else "FAIL"
        sem = "OK" if result["semantic_valid"] else "FAIL"
        yml = "GEN" if result["yaml_generated"] else "---"
        rules_str = f" rules={','.join(result['rules_fired'])}" if result["rules_fired"] else ""
        gerr_str = " gen_err!" if result.get("generator_error") else ""
        print(f"  {elapsed:.2f}s  sch:{sch}  sem:{sem}  yaml:{yml}{rules_str}{gerr_str}")
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
