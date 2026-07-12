#!/usr/bin/env python3
"""
Batch evaluation script for the brownfield intent translation pipeline.

Metrics collected (all fully automated -- no ground truth required):
  - Wall-clock latency per config and per pipeline stage
  - Schema validity (combined structural + rule-based: 0/1 per config)
  - Semantic validity (rule engine pass/fail: 0/1 per config)
  - Per-rule violation counts (rules 101-120, broken down by rule ID)
  - Template block coverage (which EDGE_* blocks were generated)
  - Execution path (cisco_deterministic / arista_deterministic)
  - LLM invoked (always False on this dataset; recorded for completeness)

Field-level accuracy against manually curated ground truth is out of scope
for this script and is deferred to future work (see paper Section VI).

Usage:
    python3 scripts/batch_eval.py [--output output/evaluation]
"""

import argparse
import json
import os
import sys
import time
import statistics
import textwrap
from collections import defaultdict
from datetime import datetime
from pathlib import Path

# ---------------------------------------------------------------------------
# Path setup: add the ai_modernization module directory to sys.path
# ---------------------------------------------------------------------------
REPO_ROOT = Path(__file__).resolve().parent.parent
AI_MOD_DIR = REPO_ROOT / "scripts" / "ai_modernization"
sys.path.insert(0, str(AI_MOD_DIR))

# Import pipeline agents directly (avoids running the full LangGraph graph and
# its deterministic-path infinite-retry loop for validation failures).
from models import AgentState
from agents import (
    agent_legacy_parser,
    agent_cisco_mapper,
    agent_arista_parser,
    agent_schema_normalizer,
    agent_validator,
    agent_generator,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
CISCO_DIR = REPO_ROOT / "input" / "sanitized" / "cisco"
ARISTA_DIR = REPO_ROOT / "input" / "sanitized" / "arista"
TARGET_PLATFORM = "Cisco Catalyst 9300 Series Switches"
SOURCE_DEVICE_CISCO = "Cisco Catalyst 3850 Series Switches (Legacy)"
SOURCE_DEVICE_ARISTA = "Arista CCS-720XP-24ZY4"

# The 11 EDGE_* template types the generator can produce
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

# Config groups for stratified analysis
def _classify_group(filename: str) -> str:
    """Return a deployment-role group label for a config filename."""
    fn = filename.upper()
    # Access-edge with 802.1X/NAC: all BLDG-* configs (original 3850 + new 9300)
    if fn.startswith("BLDG-"):
        return "access-nac"
    # OOB server-room (Cisco + Arista OOB)
    if fn.startswith("DATACTR-OOBSW"):
        return "oob-server"
    # Arista spine/core
    if fn.startswith("CAMPUS-SPINE") or fn.startswith("DATACTR-SPINE"):
        return "arista-spine"
    # Arista access (CAMPUS-ACCESS-*)
    if fn.startswith("CAMPUS-ACCESS"):
        return "arista-access"
    # Distribution: IOS-XE (DIST-SW-*, CAMPUS-DIST-* with Cisco naming)
    if fn.startswith("DIST-SW-") or fn.startswith("CAMPUS-DIST-SW0"):
        return "distribution"
    # Arista distribution (CAMPUS-DIST-* — treated same as distribution for metrics)
    if fn.startswith("CAMPUS-DIST"):
        return "arista-distribution"
    # Remote-edge
    if fn.startswith("EDGE-SW-REMOTE"):
        return "remote-edge"
    # Simple building-edge (BLDG-VA original)
    if fn.startswith("BLDG-VA"):
        return "building-simple"
    return "other"


# ---------------------------------------------------------------------------
# Per-config runner
# ---------------------------------------------------------------------------

def run_config(config_path: Path, vendor: str, device_type: str) -> dict:
    """
    Run pipeline agents sequentially on a single config file and collect
    empirical metrics.  The LangGraph graph is NOT used here to avoid the
    deterministic-path retry-loop issue (cisco_mapper always resets
    iteration_count to 1, which prevents the abort condition from firing).
    The agent functions are called in the same order the graph would execute:
      Cisco : parser → cisco_mapper → normalizer → validator → generator
      Arista: arista_parser → normalizer → validator → generator
    """
    filename = config_path.name
    group = _classify_group(filename)

    try:
        raw_config = config_path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return _error_record(filename, vendor, group, str(exc))

    initial_state: AgentState = {
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

    state = dict(initial_state)
    stage_times: dict = {}
    error_msg = None

    # --- Stage 1+2: Parse + Map (deterministic, vendor-specific) ---
    t0 = time.perf_counter()
    try:
        if vendor == "cisco":
            state.update(agent_legacy_parser(state))
            state.update(agent_cisco_mapper(state))
            path = "cisco_deterministic"
        elif vendor == "arista":
            state.update(agent_arista_parser(state))
            path = "arista_deterministic"
        else:
            # Unknown vendor would use LLM; not in our dataset
            state.update(agent_legacy_parser(state))
            path = "llm_fallback"
        stage_times["parse_map_s"] = round(time.perf_counter() - t0, 4)
    except Exception as exc:
        return _error_record(filename, vendor, group, f"parse/map stage: {exc}")

    # --- Stage 3: Schema Normalizer ---
    t1 = time.perf_counter()
    try:
        state.update(agent_schema_normalizer(state))
        stage_times["normalize_s"] = round(time.perf_counter() - t1, 4)
    except Exception as exc:
        return _error_record(filename, vendor, group, f"normalizer stage: {exc}")

    # --- Stage 4: Validator ---
    t2 = time.perf_counter()
    try:
        state.update(agent_validator(state))
        stage_times["validate_s"] = round(time.perf_counter() - t2, 4)
    except Exception as exc:
        return _error_record(filename, vendor, group, f"validator stage: {exc}")

    # --- Stage 5: Generator ---
    t3 = time.perf_counter()
    yaml_generated = False
    generated_templates = []
    try:
        state.update(agent_generator(state))
        stage_times["generate_s"] = round(time.perf_counter() - t3, 4)
        yaml_generated = bool(state.get("final_output_path"))
        generated_templates = _extract_template_names(state)
    except Exception as exc:
        stage_times["generate_s"] = round(time.perf_counter() - t3, 4)
        error_msg = f"generator stage: {exc}"  # non-fatal; record but continue

    total_elapsed = round(time.perf_counter() - t0, 4)

    # --- Collect validation metrics ---
    val = state.get("validation_result") or {}
    issues = val.get("issues", [])
    validation_score = round(val.get("score", 0.0), 4)
    overall_valid = val.get("valid", False)

    # Separate structural vs rule-based issues
    structural_errors = []
    rule_violations_by_id: dict[str, list] = defaultdict(list)

    for issue in issues:
        field = issue.get("field", "")
        msg = issue.get("message", "")
        sev = issue.get("severity", "error")
        if "Rule" in field:
            # field format: "Rule 117 (description...)"
            parts = field.split()
            rule_id = parts[1] if len(parts) > 1 else "unknown"
            rule_violations_by_id[rule_id].append({"message": msg, "severity": sev})
        else:
            structural_errors.append({"field": field, "message": msg, "severity": sev})

    schema_valid = len(structural_errors) == 0
    semantic_valid = len(rule_violations_by_id) == 0
    rules_fired = sorted(rule_violations_by_id.keys())

    # Counts from normalized intent (topology summary)
    ni = state.get("normalized_intent", {})
    topo = {
        "vlans": len(ni.get("vlans", []) or []),
        "access_interfaces": len(ni.get("access_interfaces", []) or []),
        "uplinks": len(ni.get("uplinks", []) or []),
        "routed_interfaces": len(ni.get("routed_interfaces", []) or []),
        "acls": len(ni.get("acls", []) or []),
        "has_aaa": bool(ni.get("aaa_config", {}) or ni.get("nac_config", {})),
        "has_snmp": bool(ni.get("snmp_config", {})),
        "has_nac": bool(ni.get("nac_config", {})),
    }

    return {
        "file": filename,
        "vendor": vendor,
        "group": group,
        "path": path,
        "llm_invoked": path == "llm_fallback",
        "total_elapsed_s": total_elapsed,
        "stage_times": stage_times,
        "overall_valid": overall_valid,
        "schema_valid": schema_valid,
        "semantic_valid": semantic_valid,
        "validation_score": validation_score,
        "structural_errors": structural_errors,
        "rule_violations": {k: v for k, v in rule_violations_by_id.items()},
        "rules_fired": rules_fired,
        "total_issues": len(issues),
        "yaml_generated": yaml_generated,
        "templates_generated": generated_templates,
        "template_count": len(generated_templates),
        "topology": topo,
        "generator_error": error_msg,
    }


def _extract_template_names(state: dict) -> list:
    """Return list of EDGE_*_template names present in the generator output."""
    # agent_generator writes to state["final_yaml_output"] as a YAML string
    yaml_str = state.get("final_yaml_output", "") or ""
    found = []
    for t in ALL_TEMPLATE_TYPES:
        if t in yaml_str:
            found.append(t)
    # Fallback: check the device_config written to disk if yaml_str is empty
    if not found and state.get("final_output_path"):
        try:
            import yaml
            with open(state["final_output_path"]) as fh:
                data = yaml.safe_load(fh)
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
        "llm_invoked": False,
        "total_elapsed_s": 0.0,
        "stage_times": {},
        "overall_valid": False,
        "schema_valid": False,
        "semantic_valid": False,
        "validation_score": 0.0,
        "structural_errors": [{"field": "pipeline", "message": msg, "severity": "error"}],
        "rule_violations": {},
        "rules_fired": [],
        "total_issues": 1,
        "yaml_generated": False,
        "templates_generated": [],
        "template_count": 0,
        "topology": {},
        "generator_error": msg,
    }


# ---------------------------------------------------------------------------
# Aggregation helpers
# ---------------------------------------------------------------------------

def compute_summary(results: list) -> dict:
    """Compute aggregate statistics across all config results."""
    n = len(results)
    if n == 0:
        return {}

    latencies = [r["total_elapsed_s"] for r in results]
    parse_map = [r["stage_times"].get("parse_map_s", 0) for r in results]
    validate = [r["stage_times"].get("validate_s", 0) for r in results]
    generate = [r["stage_times"].get("generate_s", 0) for r in results]

    schema_pass = [r for r in results if r["schema_valid"]]
    semantic_pass = [r for r in results if r["semantic_valid"]]
    overall_pass = [r for r in results if r["overall_valid"]]
    yaml_ok = [r for r in results if r["yaml_generated"]]

    # Rule violation counts
    rule_counts: dict[str, int] = defaultdict(int)
    rule_config_counts: dict[str, int] = defaultdict(int)
    for r in results:
        for rule_id, viols in r["rule_violations"].items():
            rule_counts[rule_id] += len(viols)
            rule_config_counts[rule_id] += 1

    # Template coverage
    template_counts: dict[str, int] = defaultdict(int)
    for r in results:
        for t in r["templates_generated"]:
            template_counts[t] += 1

    # Group-level breakdown
    groups: dict[str, list] = defaultdict(list)
    for r in results:
        groups[r["group"]].append(r)

    group_stats = {}
    for grp, grp_results in sorted(groups.items()):
        grp_n = len(grp_results)
        group_stats[grp] = {
            "n": grp_n,
            "schema_valid_rate": round(sum(1 for r in grp_results if r["schema_valid"]) / grp_n, 3),
            "semantic_valid_rate": round(sum(1 for r in grp_results if r["semantic_valid"]) / grp_n, 3),
            "yaml_generated_rate": round(sum(1 for r in grp_results if r["yaml_generated"]) / grp_n, 3),
            "mean_latency_s": round(statistics.mean(r["total_elapsed_s"] for r in grp_results), 4),
        }

    # Vendor breakdown
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
                "min_latency_s": round(min(vlat), 4),
                "max_latency_s": round(max(vlat), 4),
            }

    return {
        "run_timestamp": datetime.now().isoformat(),
        "n_total": n,
        "n_cisco": sum(1 for r in results if r["vendor"] == "cisco"),
        "n_arista": sum(1 for r in results if r["vendor"] == "arista"),
        "n_llm_invoked": sum(1 for r in results if r["llm_invoked"]),
        "n_errors": sum(1 for r in results if r["path"] == "error"),
        "schema_valid_count": len(schema_pass),
        "schema_valid_rate": round(len(schema_pass) / n, 4),
        "semantic_valid_count": len(semantic_pass),
        "semantic_valid_rate": round(len(semantic_pass) / n, 4),
        "overall_valid_count": len(overall_pass),
        "overall_valid_rate": round(len(overall_pass) / n, 4),
        "yaml_generated_count": len(yaml_ok),
        "yaml_generated_rate": round(len(yaml_ok) / n, 4),
        "latency": {
            "mean_s": round(statistics.mean(latencies), 4),
            "median_s": round(statistics.median(latencies), 4),
            "stdev_s": round(statistics.stdev(latencies) if n > 1 else 0.0, 4),
            "min_s": round(min(latencies), 4),
            "max_s": round(max(latencies), 4),
        },
        "stage_latency": {
            "parse_map": {
                "mean_s": round(statistics.mean(parse_map), 4),
                "median_s": round(statistics.median(parse_map), 4),
            },
            "validate": {
                "mean_s": round(statistics.mean(validate), 4),
                "median_s": round(statistics.median(validate), 4),
            },
            "generate": {
                "mean_s": round(statistics.mean(generate), 4),
                "median_s": round(statistics.median(generate), 4),
            },
        },
        "rule_violation_summary": {
            rule_id: {
                "configs_affected": rule_config_counts[rule_id],
                "total_violations": rule_counts[rule_id],
            }
            for rule_id in sorted(rule_counts.keys())
        },
        "template_coverage": {
            t: {"count": template_counts.get(t, 0), "rate": round(template_counts.get(t, 0) / n, 3)}
            for t in ALL_TEMPLATE_TYPES
        },
        "by_vendor": vendor_stats,
        "by_group": group_stats,
    }


# ---------------------------------------------------------------------------
# Human-readable report
# ---------------------------------------------------------------------------

def format_report(summary: dict, results: list) -> str:
    lines = []
    ts = summary.get("run_timestamp", "")
    n = summary["n_total"]

    lines.append("=" * 72)
    lines.append("  BATCH EVALUATION REPORT — Brownfield Intent Translation Pipeline")
    lines.append(f"  Run: {ts}")
    lines.append("=" * 72)
    lines.append("")

    lines.append(f"Dataset : {n} configs  "
                 f"({summary['n_cisco']} Cisco deterministic, "
                 f"{summary['n_arista']} Arista deterministic, "
                 f"{summary['n_llm_invoked']} LLM invoked)")
    lines.append(f"Errors  : {summary['n_errors']} pipeline errors (excluded from rates below)")
    lines.append("")

    # Validity
    lines.append("VALIDITY RATES (over all configs):")
    sv = summary["schema_valid_rate"]
    semv = summary["semantic_valid_rate"]
    ov = summary["overall_valid_rate"]
    yg = summary["yaml_generated_rate"]
    lines.append(f"  Schema valid (structural YAML integrity)  : {sv:.1%}  ({summary['schema_valid_count']}/{n})")
    lines.append(f"  Semantic valid (rules 101-120, no errors) : {semv:.1%}  ({summary['semantic_valid_count']}/{n})")
    lines.append(f"  Overall valid (structural + semantic)     : {ov:.1%}  ({summary['overall_valid_count']}/{n})")
    lines.append(f"  YAML output generated                     : {yg:.1%}  ({summary['yaml_generated_count']}/{n})")
    lines.append("")

    # Latency
    lat = summary["latency"]
    lines.append("LATENCY (wall-clock, start-to-YAML-generation):")
    lines.append(f"  Mean   : {lat['mean_s']:.3f} s")
    lines.append(f"  Median : {lat['median_s']:.3f} s")
    lines.append(f"  Stdev  : {lat['stdev_s']:.3f} s")
    lines.append(f"  Min    : {lat['min_s']:.3f} s")
    lines.append(f"  Max    : {lat['max_s']:.3f} s")
    lines.append("")

    slat = summary["stage_latency"]
    lines.append("STAGE LATENCY BREAKDOWN (mean / median):")
    lines.append(f"  Parse + Map  : {slat['parse_map']['mean_s']:.3f} s / {slat['parse_map']['median_s']:.3f} s")
    lines.append(f"  Validate     : {slat['validate']['mean_s']:.3f} s / {slat['validate']['median_s']:.3f} s")
    lines.append(f"  Generate     : {slat['generate']['mean_s']:.3f} s / {slat['generate']['median_s']:.3f} s")
    lines.append("")

    # By vendor
    lines.append("BY VENDOR:")
    for vname, vs in summary.get("by_vendor", {}).items():
        lines.append(f"  {vname.capitalize():<8}  n={vs['n']}  "
                     f"schema={vs['schema_valid_rate']:.1%}  "
                     f"semantic={vs['semantic_valid_rate']:.1%}  "
                     f"yaml={vs['yaml_generated_rate']:.1%}  "
                     f"lat={vs['mean_latency_s']:.3f}s (mean)")
    lines.append("")

    # By group
    lines.append("BY DEPLOYMENT GROUP:")
    fmt = "  {:<22}  n={:2d}  schema={:.1%}  semantic={:.1%}  lat={:.3f}s"
    for grp, gs in summary.get("by_group", {}).items():
        lines.append(fmt.format(grp, gs["n"],
                                gs["schema_valid_rate"],
                                gs["semantic_valid_rate"],
                                gs["mean_latency_s"]))
    lines.append("")

    # Rule violations
    rvs = summary.get("rule_violation_summary", {})
    lines.append("SEMANTIC RULE VIOLATIONS (rules 101-120):")
    if not rvs:
        lines.append("  None — all configs passed all 20 semantic rules.")
    else:
        lines.append(f"  {'Rule ID':<10} {'Configs affected':>18} {'Total violations':>18}")
        lines.append("  " + "-" * 50)
        for rule_id, rv in sorted(rvs.items()):
            lines.append(f"  {rule_id:<10} {rv['configs_affected']:>18}  {rv['total_violations']:>17}")
    lines.append("")

    # Template coverage
    lines.append("TEMPLATE BLOCK COVERAGE (EDGE_* template types generated):")
    tc = summary.get("template_coverage", {})
    for tname, tinfo in tc.items():
        bar = "#" * int(tinfo["rate"] * 20)
        lines.append(f"  {tname:<30}  {tinfo['count']:3d}/{n}  [{bar:<20}]  {tinfo['rate']:.1%}")
    lines.append("")

    # Per-config detail
    lines.append("PER-CONFIG DETAIL:")
    hdr = f"  {'File':<36}  {'Grp':<20}  {'Lat(s)':>7}  {'Sch':>4}  {'Sem':>4}  {'YAML':>4}  {'Rules fired'}"
    lines.append(hdr)
    lines.append("  " + "-" * 110)
    for r in results:
        sch = "OK" if r["schema_valid"] else "FAIL"
        sem = "OK" if r["semantic_valid"] else "FAIL"
        yml = "YES" if r["yaml_generated"] else "NO"
        rules = ",".join(r["rules_fired"]) if r["rules_fired"] else "-"
        gerr = f"  [gen:{r['generator_error'][:40]}]" if r.get("generator_error") else ""
        lines.append(f"  {r['file']:<36}  {r['group']:<20}  {r['total_elapsed_s']:>7.3f}  "
                     f"{sch:>4}  {sem:>4}  {yml:>4}  {rules}{gerr}")
    lines.append("")
    lines.append("=" * 72)
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Batch evaluation for brownfield pipeline")
    parser.add_argument("--output", default="output/evaluation",
                        help="Directory to write results JSON and report (default: output/evaluation)")
    parser.add_argument("--cisco-dir", default=str(CISCO_DIR))
    parser.add_argument("--arista-dir", default=str(ARISTA_DIR))
    args = parser.parse_args()

    out_dir = REPO_ROOT / args.output
    out_dir.mkdir(parents=True, exist_ok=True)

    cisco_dir = Path(args.cisco_dir)
    arista_dir = Path(args.arista_dir)

    # Build config list
    configs: list[tuple[Path, str]] = []  # (path, vendor)

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
    print(f"\nBatch evaluation: {n_total} configs "
          f"({sum(1 for _,v in configs if v=='cisco')} Cisco, "
          f"{sum(1 for _,v in configs if v=='arista')} Arista)\n")

    results = []
    for i, (cfg_path, vendor) in enumerate(configs, 1):
        device_type = SOURCE_DEVICE_CISCO if vendor == "cisco" else SOURCE_DEVICE_ARISTA
        print(f"[{i:2d}/{n_total}] {cfg_path.name:<40}  vendor={vendor}", end="", flush=True)
        result = run_config(cfg_path, vendor, device_type)
        elapsed = result["total_elapsed_s"]
        sch = "OK" if result["schema_valid"] else "FAIL"
        sem = "OK" if result["semantic_valid"] else "FAIL"
        yml = "GEN" if result["yaml_generated"] else "---"
        rules_str = f" rules={','.join(result['rules_fired'])}" if result["rules_fired"] else ""
        gerr_str = f" gen_err!" if result.get("generator_error") else ""
        print(f"  {elapsed:.2f}s  sch:{sch}  sem:{sem}  yaml:{yml}{rules_str}{gerr_str}")
        results.append(result)

    print(f"\nAll {n_total} configs processed.")

    summary = compute_summary(results)

    # Write results
    per_config_file = out_dir / "per_config_results.json"
    summary_file = out_dir / "summary.json"
    report_file = out_dir / "summary.txt"

    per_config_file.write_text(json.dumps(results, indent=2, default=str))
    summary_file.write_text(json.dumps(summary, indent=2, default=str))

    report_text = format_report(summary, results)
    report_file.write_text(report_text)

    print(f"\nResults written to {out_dir}/")
    print(f"  {per_config_file.name}")
    print(f"  {summary_file.name}")
    print(f"  {report_file.name}")
    print()
    print(report_text)


if __name__ == "__main__":
    main()
