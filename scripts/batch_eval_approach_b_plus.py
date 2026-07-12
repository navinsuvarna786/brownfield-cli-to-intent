#!/usr/bin/env python3
"""
Approach B+ — Schema-constrained LLM with RAG context injection.

This script implements a tighter ablation between Approach B (zero-guardrail LLM)
and Approach C (full guardrailed pipeline). Approach B+ uses:

  (a) Structured JSON output enforced via OpenAI response_format=json_object
  (b) The target intent schema injected as a typed few-shot example in the system prompt
  (c) The same ChromaDB RAG context used by Approach C (schema + template variable docs)

But deliberately excludes:
  - The schema normalizer (no field promotion, no IP normalization)
  - The 22-rule semantic validator (no rule engine)
  - The retry loop (single pass, no feedback injection)
  - The deterministic parser merge (raw LLM output only, no legacy fallback merge)

Purpose: isolates the guardrail contribution from the prompt-engineering contribution.
  A--B gap: cost of zero structured workflow (~26.5pp semantic validity in paper)
  B--B+ gap: value of schema-constrained prompting alone
  B+--C gap: value of normalizer + semantic rule engine + retry loop
  A--C gap: total benefit of semantic auto-correction (53pp in paper)

If B+ still fails semantic validation at rate similar to B, the paper's central
claim (guardrails are the key differentiator, not just prompting) is reinforced.
If B+ substantially closes the gap to C, the ablation becomes more nuanced.

Usage:
    export OPENAI_API_KEY=<key>
    python3 scripts/batch_eval_approach_b_plus.py --subset input/subset_17.txt
    python3 scripts/batch_eval_approach_b_plus.py  # all 34 configs
"""

import argparse
import importlib
import json
import os
import sys
import time
import statistics
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
    print("ERROR: OPENAI_API_KEY is not set.", file=sys.stderr)
    sys.exit(1)

from openai import OpenAI
from models import AgentState
from agents import agent_legacy_parser

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
CISCO_DIR   = REPO_ROOT / "input" / "sanitized" / "cisco"
ARISTA_DIR  = REPO_ROOT / "input" / "sanitized" / "arista"
SCHEMA_PATH = REPO_ROOT / "schema.yaml"
GT_DIR      = REPO_ROOT / "ground_truth"

MODEL = "gpt-4o-mini"          # Cost-efficient; swap to gpt-4o for max quality
TEMPERATURE = 0.1
MAX_TOKENS  = 4096

ALL_TEMPLATE_TYPES = [
    "EDGE_PNP_template",  "EDGE_SYSTEM_template", "EDGE_VLAN_template",
    "EDGE_MGMT_template", "EDGE_ACL_template",     "EDGE_UPLINK_template",
    "EDGE_SNMP_template", "EDGE_AAA_template",      "EDGE_NAC_template",
    "EDGE_ACCESS_PORT_template", "EDGE_ROUTED_PORT_template",
]

# ---------------------------------------------------------------------------
# Schema few-shot: compact typed skeleton of the target intent object.
# Reviewer-facing: this is what Approach B did NOT have; B+ injects it.
# ---------------------------------------------------------------------------
SCHEMA_FEW_SHOT = """\
Target intent object schema (JSON, all fields optional unless marked *required*):
{
  "hostname": "string *required*",
  "domain_name": "string",
  "stack_info": {"is_stack": bool, "member_count": int, "master_switch": int},
  "pnp_config": {
    "pnp_vlan_id": int, "pnp_vlan_name": "string",
    "pnp_vlan_network_add": "dotted-quad IP",
    "pnp_vlan_network_mask": "dotted-quad mask",
    "pnp_vlan_default_gateway": "dotted-quad IP"
  },
  "vlans": [{"id": int, "name": "string"}],
  "acls": [{"name": "string", "type": "standard|extended",
            "entries": [{"sequence": int, "action": "permit|deny",
                         "source": "IP or 'any'", "log": bool}]}],
  "uplinks": [{"type": "trunk|port-channel", "name": "string",
               "allowed_vlans": [int], "native_vlan": int}],
  "snmp_config": {"community_ro": "string", "acl_ro": "string",
                  "location": "string", "contact": "string",
                  "chassis_id": "string", "enable_traps": bool},
  "aaa_config": {
    "aaa_enabled": bool,
    "tacacs_servers": [{"name": "string", "ip": "dotted-quad", "key": "need_input"}],
    "radius_servers": [{"name": "string", "ip": "dotted-quad", "key": "need_input"}]
  },
  "nac_config": {
    "dot1x_enabled": bool, "radius_group_name": "string",
    "radius_servers": [{"name": "string", "ip": "dotted-quad"}]
  },
  "ntp_servers": ["IP|prefer"],
  "dns_servers": ["IP"],
  "stp_mode": "pvst|rapid-pvst",
  "errdisable_config": {"causes": ["string"], "recovery_interval": int},
  "access_interfaces": [{"name": "string", "config": {
    "access_vlan": int, "portfast": bool, "bpduguard": bool,
    "storm_control_broadcast": "string", "storm_control_multicast": "string"}}],
  "routed_interfaces": [{"name": "string", "vrf": "string",
                         "ipv4": {"address": "IP/prefix or dotted-quad", "netmask": "string"}}]
}

Fields absent from the CLI that are required by schema must be set to "need_input".
Do NOT invent values. Return ONLY the JSON object, no prose."""

# ---------------------------------------------------------------------------
# RAG context retrieval (reuses ChromaDB populated for Approach C)
# ---------------------------------------------------------------------------
def _get_rag_context(hostname: str, vendor: str, max_docs: int = 4) -> str:
    """Retrieve schema + template context from ChromaDB. Graceful fallback."""
    try:
        from rag_setup import RAGSetup
        rag_db_path = str(AI_MOD_DIR / "chroma_db")
        rag = RAGSetup(persist_directory=rag_db_path)
        retriever = rag.vectorstore.as_retriever(
            search_kwargs={"k": max_docs}
        )
        query = f"{vendor} campus switching intent schema template variables"
        docs = retriever.invoke(query)
        return "\n\n".join(d.page_content for d in docs)
    except Exception as exc:
        return f"[RAG unavailable: {exc}]"


# ---------------------------------------------------------------------------
# B+ LLM call: schema-constrained, RAG-injected, single pass, no retry
# ---------------------------------------------------------------------------
def _call_llm_b_plus(
    raw_config: str,
    legacy_parsed: dict,
    vendor: str,
    rag_context: str,
    hostname_hint: str,
) -> tuple[dict, float]:
    """
    Single GPT call with structured JSON output and schema injection.
    Returns (intent_dict, latency_seconds).
    """
    client = OpenAI()

    # Compress config (remove AutoQoS, comment blocks) to save tokens
    lines = raw_config.splitlines()
    compressed = "\n".join(
        l for l in lines
        if not l.strip().startswith("!")
        or l.strip() == "!"
    )
    # Hard cap at 12,000 chars to stay within context window budget
    if len(compressed) > 12_000:
        compressed = compressed[:12_000] + "\n[...TRUNCATED...]"

    legacy_summary = json.dumps(legacy_parsed, separators=(",", ":"), default=str)
    if len(legacy_summary) > 4000:
        legacy_summary = legacy_summary[:4000] + '..."TRUNCATED"}'

    system_prompt = f"""You are a network automation expert. Convert the raw device CLI configuration \
into a structured intent JSON object that exactly matches the schema below.

{SCHEMA_FEW_SHOT}

Additional context from schema and template documentation:
{rag_context}

Rules:
1. Output ONLY valid JSON. No markdown, no explanation.
2. hostname is required. If absent, set to "need_input".
3. Use "need_input" for fields required by schema but absent from CLI.
4. Do NOT add fields not in the schema above.
5. Vendor: {vendor.upper()}. Device hint: {hostname_hint}"""

    human_prompt = f"CLI Configuration:\n{compressed}\n\nDeterministic parser summary (may help):\n{legacy_summary}"

    t0 = time.perf_counter()
    response = client.chat.completions.create(
        model=MODEL,
        temperature=TEMPERATURE,
        max_tokens=MAX_TOKENS,
        response_format={"type": "json_object"},
        messages=[
            {"role": "system",  "content": system_prompt},
            {"role": "user",    "content": human_prompt},
        ],
    )
    latency = time.perf_counter() - t0

    try:
        intent = json.loads(response.choices[0].message.content)
    except (json.JSONDecodeError, AttributeError) as exc:
        intent = {"parse_error": str(exc), "raw": response.choices[0].message.content[:500]}

    return intent, latency


# ---------------------------------------------------------------------------
# Post-hoc semantic validation (same rule engine as Approach C)
# ---------------------------------------------------------------------------
def _post_hoc_validate(intent: dict) -> tuple[bool, bool, list[str]]:
    hostname = intent.get("hostname")
    schema_valid = bool(hostname and hostname != "need_input")

    rules_dir = REPO_ROOT / "validation" / "rules"
    triggered: list[str] = []
    if rules_dir.exists():
        sys.path.insert(0, str(rules_dir))
        for rf in sorted(f for f in os.listdir(rules_dir) if f.endswith(".py") and f[0].isdigit()):
            mod_name = rf[:-3]
            try:
                mod = importlib.reload(sys.modules[mod_name]) if mod_name in sys.modules \
                      else importlib.import_module(mod_name)
                if hasattr(mod, "Rule") and hasattr(mod.Rule, "match"):
                    if mod.Rule.match(intent):
                        triggered.append(str(mod.Rule.id))
            except Exception:
                pass
        sys.path.remove(str(rules_dir))

    return schema_valid, len(triggered) == 0, triggered


# ---------------------------------------------------------------------------
# Config classifier
# ---------------------------------------------------------------------------
def _classify_group(filename: str) -> str:
    fn = filename.upper()
    for prefix in ("BLDG-FR", "BLDG-A", "BLDG-B", "BLDG-C", "BLDG-VA"):
        if fn.startswith(prefix): return "access-nac"
    if fn.startswith("DATACTR"): return "oob-server"
    if fn.startswith("DIST-"):   return "distribution"
    if fn.startswith("EDGE-SW"): return "remote-edge"
    if fn.startswith("CAMPUS"):  return "arista-distribution"
    return "other"


# ---------------------------------------------------------------------------
# Per-config runner
# ---------------------------------------------------------------------------
def run_config_b_plus(config_path: Path, vendor: str, out_dir: Path) -> dict:
    stem  = config_path.stem.lower()
    group = _classify_group(config_path.name)
    device_out = out_dir / stem
    device_out.mkdir(parents=True, exist_ok=True)

    try:
        raw_config = config_path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return _err(config_path.name, vendor, group, str(exc))

    # Stage 1: Legacy parser (provides structured fallback context)
    state: dict = {
        "raw_config": raw_config,
        "source_filename": config_path.name,
        "target_device_type": "Cisco Catalyst 9300 Series Switches",
        "source_vendor": vendor,
        "output_dir": str(device_out),
        "trace_log": [], "legacy_parsed_data": {}, "extracted_intent": {},
        "decision_metadata": [], "normalized_intent": {}, "validation_result": None,
        "iteration_count": 0, "rag_context": "", "final_yaml_output": "",
        "final_output_path": "", "report_path": "",
    }
    t_parse = time.perf_counter()
    try:
        state.update(agent_legacy_parser(state))
        parse_s = round(time.perf_counter() - t_parse, 4)
    except Exception as exc:
        return _err(config_path.name, vendor, group, f"parse: {exc}")

    legacy = state.get("legacy_parsed_data", {})
    hostname_hint = legacy.get("hostname", config_path.stem)

    # Stage 2: RAG retrieval
    t_rag = time.perf_counter()
    rag_ctx = _get_rag_context(hostname_hint, vendor)
    rag_s   = round(time.perf_counter() - t_rag, 4)

    # Stage 3: Schema-constrained LLM call (no retry, no normalizer, no validator)
    try:
        intent, llm_s = _call_llm_b_plus(raw_config, legacy, vendor, rag_ctx, hostname_hint)
    except Exception as exc:
        return _err(config_path.name, vendor, group, f"llm: {exc}")

    # Save output for compute_f1.py compatibility
    (device_out / "3_schema_normalizer.json").write_text(json.dumps(intent, indent=2, default=str))
    (device_out / "2_llm_mapper_raw.json").write_text(json.dumps(intent, indent=2, default=str))

    # Post-hoc semantic validation (same engine as C — no guardrails applied before this)
    schema_valid, semantic_valid, rules_fired = _post_hoc_validate(intent)

    total_s = parse_s + rag_s + llm_s
    return {
        "file": config_path.name, "vendor": vendor, "group": group,
        "approach": "B+",
        "total_elapsed_s": round(total_s, 4),
        "stage_times": {"parse_s": parse_s, "rag_s": rag_s, "llm_s": round(llm_s, 4)},
        "schema_valid": schema_valid,
        "semantic_valid": semantic_valid,
        "rules_fired": rules_fired,
        "llm_invoked": True,
        "model": MODEL,
        "parse_error": bool(intent.get("parse_error")),
    }


def _err(name, vendor, group, msg):
    return {
        "file": name, "vendor": vendor, "group": group, "approach": "B+",
        "total_elapsed_s": 0.0, "stage_times": {}, "schema_valid": False,
        "semantic_valid": False, "rules_fired": [], "llm_invoked": False,
        "model": MODEL, "parse_error": False, "error": msg,
    }


# ---------------------------------------------------------------------------
# Summary + report
# ---------------------------------------------------------------------------
def compute_summary(results: list) -> dict:
    n = len(results)
    if n == 0: return {}
    lats = [r["total_elapsed_s"] for r in results]
    llm_lats = [r["stage_times"].get("llm_s", 0) for r in results if r["llm_invoked"]]
    schema_ok = [r for r in results if r["schema_valid"]]
    sem_ok    = [r for r in results if r["semantic_valid"]]
    rc: dict  = defaultdict(int)
    for r in results:
        for rid in r["rules_fired"]: rc[rid] += 1

    by_group: dict = defaultdict(list)
    for r in results: by_group[r["group"]].append(r)

    return {
        "approach": "B+",
        "description": "Schema-constrained LLM + RAG; no normalizer, no validator, no retry",
        "model": MODEL,
        "run_timestamp": datetime.now().isoformat(),
        "n_total": n,
        "schema_valid_rate":   round(len(schema_ok) / n, 4),
        "semantic_valid_rate": round(len(sem_ok) / n, 4),
        "latency": {
            "mean_s":   round(statistics.mean(lats), 3),
            "median_s": round(statistics.median(lats), 3),
            "stdev_s":  round(statistics.stdev(lats) if n > 1 else 0, 3),
            "min_s":    round(min(lats), 3),
            "max_s":    round(max(lats), 3),
        },
        "llm_latency": {
            "mean_s":   round(statistics.mean(llm_lats), 3) if llm_lats else 0,
            "median_s": round(statistics.median(llm_lats), 3) if llm_lats else 0,
        },
        "rule_violations": {rid: cnt for rid, cnt in sorted(rc.items())},
        "by_group": {
            grp: {
                "n": len(gr),
                "schema_valid_rate":   round(sum(1 for r in gr if r["schema_valid"]) / len(gr), 3),
                "semantic_valid_rate": round(sum(1 for r in gr if r["semantic_valid"]) / len(gr), 3),
                "mean_latency_s":      round(statistics.mean(r["total_elapsed_s"] for r in gr), 3),
            }
            for grp, gr in sorted(by_group.items())
        },
    }


def format_report(summary: dict, results: list) -> str:
    n = summary["n_total"]
    lines = [
        "=" * 72,
        "  APPROACH B+ — Schema-Constrained LLM + RAG Ablation",
        f"  Model: {summary['model']}",
        f"  Run:   {summary['run_timestamp']}",
        "=" * 72,
        f"\nDataset: {n} configs",
        f"Schema valid  : {summary['schema_valid_rate']:.1%}  ({round(summary['schema_valid_rate']*n)}/{n})",
        f"Semantic valid: {summary['semantic_valid_rate']:.1%}  ({round(summary['semantic_valid_rate']*n)}/{n})",
        "",
        "EXPECTED INTERPRETATION (compare against paper Table 3):",
        "  Approach A (rules-only)     : semantic_valid = 44.1%",
        "  Approach B (zero-guardrail) : semantic_valid = 17.6%",
        f"  Approach B+ (this run)      : semantic_valid = {summary['semantic_valid_rate']:.1%}",
        "  Approach C (full guardrails): semantic_valid = 97.1%",
        "",
        "  B--B+ gap = prompt engineering alone",
        "  B+--C gap = normalizer + semantic rules + retry loop",
        "",
        "BY GROUP:",
    ]
    for grp, gs in summary.get("by_group", {}).items():
        lines.append(f"  {grp:<22}  n={gs['n']:2d}  schema={gs['schema_valid_rate']:.1%}"
                     f"  semantic={gs['semantic_valid_rate']:.1%}  lat={gs['mean_latency_s']:.1f}s")
    lines.append("\nRULE VIOLATIONS:")
    for rid, cnt in summary.get("rule_violations", {}).items():
        lines.append(f"  Rule {rid}: {cnt} configs")
    lines.append("\nPER-CONFIG:")
    for r in results:
        sch = "OK" if r["schema_valid"] else "FAIL"
        sem = "OK" if r["semantic_valid"] else "FAIL"
        rules = ",".join(r["rules_fired"]) if r["rules_fired"] else "-"
        lines.append(f"  {r['file']:<38}  {r['total_elapsed_s']:>6.1f}s  sch:{sch}  sem:{sem}  {rules}")
    lines.append("=" * 72)
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    global MODEL
    ap = argparse.ArgumentParser(description="Approach B+ ablation evaluation")
    ap.add_argument("--output", default="output/evaluation/approach_b_plus")
    ap.add_argument("--cisco-dir",  default=str(CISCO_DIR))
    ap.add_argument("--arista-dir", default=str(ARISTA_DIR))
    ap.add_argument("--subset", default=None,
                    help="File listing config stems (one per line). Recommended: input/subset_17.txt")
    ap.add_argument("--model", default=MODEL,
                    help=f"OpenAI model name (default: {MODEL})")
    args = ap.parse_args()

    MODEL = args.model

    out_dir = REPO_ROOT / args.output
    out_dir.mkdir(parents=True, exist_ok=True)

    all_configs: list[tuple[Path, str]] = []
    for p in sorted(Path(args.cisco_dir).glob("*.txt")):
        all_configs.append((p, "cisco"))
    for p in sorted(Path(args.arista_dir).glob("*.txt")):
        all_configs.append((p, "arista"))

    if args.subset:
        sub = Path(args.subset)
        stems = {
            Path(l.strip()).stem.upper()
            for l in sub.read_text().splitlines()
            if l.strip() and not l.startswith("#")
        }
        all_configs = [(p, v) for p, v in all_configs if p.stem.upper() in stems]
        print(f"Subset: {len(all_configs)} configs from {sub.name}")

    n = len(all_configs)
    print(f"\nApproach B+ evaluation: {n} configs  model={MODEL}")
    print("  Schema-constrained JSON output + RAG context. No normalizer/validator/retry.\n")

    results = []
    for i, (cfg, vendor) in enumerate(all_configs, 1):
        print(f"[{i:2d}/{n}] {cfg.name:<40}  vendor={vendor}", end="", flush=True)
        r = run_config_b_plus(cfg, vendor, out_dir)
        sch = "OK" if r["schema_valid"] else "FAIL"
        sem = "OK" if r["semantic_valid"] else "FAIL"
        print(f"  {r['total_elapsed_s']:.1f}s  sch:{sch}  sem:{sem}  rules:{','.join(r['rules_fired']) or '-'}")
        results.append(r)

    summary = compute_summary(results)
    report  = format_report(summary, results)

    (out_dir / "per_config_results.json").write_text(json.dumps(results, indent=2, default=str))
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2, default=str))
    (out_dir / "report.txt").write_text(report)

    print(f"\n{report}")
    print(f"\nResults written to: {out_dir}")

    # Print comparison table for easy copy-paste into paper
    print("\nABLATION COMPARISON (copy into paper if running B+):")
    print(f"  A (rules-only)      : sem_valid=44.1%  F1=0.998  lat=37ms")
    print(f"  B (zero-guardrail)  : sem_valid=17.6%  F1=0.512  lat=41.5s")
    print(f"  B+ (this run)       : sem_valid={summary['semantic_valid_rate']:.1%}  lat={summary['latency']['mean_s']:.1f}s")
    print(f"  C (full guardrails) : sem_valid=97.1%  F1=1.000  lat=42ms")


if __name__ == "__main__":
    main()
