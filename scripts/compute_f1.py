#!/usr/bin/env python3
"""
Field-level F1 evaluation script.

Computes precision, recall, and macro-averaged F1 by comparing ground-truth
normalized intent YAML files against system outputs from any approach.

The unit of comparison is a (field-path, normalized-value) pair, where:
  - field-path is a dot-separated path to a scalar leaf, e.g.
      hostname
      vlans[0].vlan_id
      snmp_config.communities[0].acl
  - normalized-value is the string representation of the leaf value after
    applying the normalization rules from docs/labeling_protocol.md

Metrics:
  - Precision: |predicted ∩ ground_truth| / |predicted|
  - Recall   : |predicted ∩ ground_truth| / |ground_truth|
  - F1       : harmonic mean of precision and recall
  - Object completeness: fraction of ground-truth top-level template sections
    that are non-empty in the prediction

Results are reported per-config, per-group, and overall (macro-averaged).

Usage:
    python3 scripts/compute_f1.py \\
        --ground-truth ground_truth/ \\
        --predictions  output/evaluation/approach_c/ \\
        --subset       input/subset_17.txt \\
        --output       output/evaluation/field_accuracy_c.json

    The --predictions directory is expected to contain per-config YAML files
    named <STEM>.yaml (case-insensitive stem match), OR subdirectories
    named <stem>/ each containing a <STEM>.yaml file (matching the Approach C
    output layout under output/).

    The --ground-truth directory is expected to contain files named
    <stem>.yaml (lowercase hyphenated stem).
"""

import argparse
import json
import os
import sys
from pathlib import Path
from collections import defaultdict
from datetime import datetime
import yaml


# ---------------------------------------------------------------------------
# Field-path enumeration
# ---------------------------------------------------------------------------

def _enumerate_pairs(obj, prefix: str = "") -> list[tuple[str, str]]:
    """
    Recursively walk a parsed YAML object and return all (path, value) pairs
    where value is a non-null, non-empty scalar.

    Lists are indexed by position: vlans[0], vlans[1], ...
    Dict keys with None / "" / [] / {} values are skipped.
    """
    pairs: list[tuple[str, str]] = []

    if isinstance(obj, dict):
        for key, val in obj.items():
            child_prefix = f"{prefix}.{key}" if prefix else key
            pairs.extend(_enumerate_pairs(val, child_prefix))

    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            child_prefix = f"{prefix}[{i}]"
            pairs.extend(_enumerate_pairs(item, child_prefix))

    else:
        # Scalar leaf
        if obj is None:
            return []
        val_str = str(obj).strip()
        if val_str == "" or val_str == "[]" or val_str == "{}":
            return []
        pairs.append((prefix, val_str))

    return pairs


# ---------------------------------------------------------------------------
# Prediction lookup
# ---------------------------------------------------------------------------

def _find_prediction_yaml(predictions_dir: Path, stem: str) -> Path | None:
    """
    Locate the prediction YAML for a config stem.
    Searches:
      1. <predictions_dir>/<stem>.yaml  (flat layout)
      2. <predictions_dir>/<stem-lower>/<stem-upper>.yaml (Approach C layout)
      3. <predictions_dir>/<stem-lower>/5_generator.yaml  (stage output)
    """
    # Normalize: predictions may use lowercase stems as dir names
    lower_stem = stem.lower()
    upper_stem = stem.upper()

    candidates = [
        predictions_dir / f"{stem}.yaml",
        predictions_dir / f"{lower_stem}.yaml",
        predictions_dir / f"{upper_stem}.yaml",
        predictions_dir / lower_stem / f"{upper_stem}.yaml",
        predictions_dir / lower_stem / f"{stem}.yaml",
        predictions_dir / lower_stem / "5_generator.yaml",
    ]
    for c in candidates:
        if c.exists():
            return c
    return None


def _find_prediction_normalizer_json(predictions_dir: Path, stem: str) -> Path | None:
    """
    Locate the normalized intent JSON (3_schema_normalizer.json) produced by
    Approach C or A, which carries the full structured intent before template
    rendering. Used as the prediction source when the YAML template output is
    not easily enumerable back to field paths.
    """
    lower_stem = stem.lower()
    candidates = [
        predictions_dir / lower_stem / "3_schema_normalizer.json",
    ]
    for c in candidates:
        if c.exists():
            return c
    return None


# ---------------------------------------------------------------------------
# Per-config F1
# ---------------------------------------------------------------------------

def _compute_config_f1(
    gt_path: Path,
    pred_yaml_path: Path | None,
    pred_norm_path: Path | None,
) -> dict:
    """
    Compute F1 for one config. Prefers the normalizer JSON (structured intent)
    over the rendered YAML (template format) because template variables are
    pipe-encoded and harder to enumerate faithfully. Falls back to rendered
    YAML if the normalizer JSON is absent.
    """
    # Load ground truth
    try:
        gt_obj = yaml.safe_load(gt_path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {"error": f"Cannot load ground truth: {exc}", "f1": None,
                "precision": None, "recall": None, "object_completeness": None}

    if not isinstance(gt_obj, dict):
        return {"error": "Ground truth is not a YAML mapping", "f1": None,
                "precision": None, "recall": None, "object_completeness": None}

    gt_pairs = set(_enumerate_pairs(gt_obj))
    if not gt_pairs:
        return {"error": "Ground truth has no enumerable pairs", "f1": None,
                "precision": None, "recall": None, "object_completeness": None}

    # Load prediction — prefer normalizer JSON
    pred_obj = None
    pred_source = None

    if pred_norm_path and pred_norm_path.exists():
        try:
            pred_obj = json.loads(pred_norm_path.read_text(encoding="utf-8"))
            pred_source = str(pred_norm_path)
        except Exception:
            pred_obj = None

    if pred_obj is None and pred_yaml_path and pred_yaml_path.exists():
        try:
            pred_obj = yaml.safe_load(pred_yaml_path.read_text(encoding="utf-8"))
            pred_source = str(pred_yaml_path)
        except Exception:
            pred_obj = None

    if pred_obj is None:
        return {"error": "Prediction file not found or unreadable", "f1": 0.0,
                "precision": 0.0, "recall": 0.0, "object_completeness": 0.0,
                "gt_pairs": len(gt_pairs), "pred_pairs": 0, "tp": 0}

    pred_pairs = set(_enumerate_pairs(pred_obj))

    tp = gt_pairs & pred_pairs
    precision = len(tp) / len(pred_pairs) if pred_pairs else 0.0
    recall = len(tp) / len(gt_pairs) if gt_pairs else 0.0
    f1 = (2 * precision * recall / (precision + recall)
          if (precision + recall) > 0 else 0.0)

    # Object completeness: fraction of top-level non-empty GT sections present
    # and non-empty in prediction
    gt_top_keys = {k for k, v in gt_obj.items()
                   if v is not None and v != [] and v != {}}
    pred_top_keys = {k for k, v in (pred_obj if isinstance(pred_obj, dict) else {}).items()
                     if v is not None and v != [] and v != {}}
    obj_completeness = (
        len(gt_top_keys & pred_top_keys) / len(gt_top_keys)
        if gt_top_keys else 1.0
    )

    return {
        "f1": round(f1, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "object_completeness": round(obj_completeness, 4),
        "gt_pairs": len(gt_pairs),
        "pred_pairs": len(pred_pairs),
        "tp": len(tp),
        "pred_source": pred_source,
    }


# ---------------------------------------------------------------------------
# Group label (mirrors batch_eval.py)
# ---------------------------------------------------------------------------

def _classify_group(filename: str) -> str:
    fn = filename.upper()
    if fn.startswith("BLDG-"):
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
# Main
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(
        description="Compute field-level F1 between ground truth and system predictions"
    )
    ap.add_argument("--ground-truth", required=True,
                    help="Directory containing ground_truth/<stem>.yaml files")
    ap.add_argument("--predictions", required=True,
                    help="Directory containing prediction YAML or per-config subdirs")
    ap.add_argument("--subset", default=None,
                    help="Path to subset manifest (e.g. input/subset_17.txt). "
                         "If omitted, evaluates all configs in --ground-truth.")
    ap.add_argument("--output", required=True,
                    help="Path to write field_accuracy_<approach>.json output")
    args = ap.parse_args()

    gt_dir = Path(args.ground_truth)
    pred_dir = Path(args.predictions)
    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    # Build list of stems to evaluate
    if args.subset:
        subset_path = Path(args.subset)
        if not subset_path.exists():
            print(f"ERROR: subset file not found: {subset_path}", file=sys.stderr)
            sys.exit(1)
        stems = []
        for line in subset_path.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # Strip .txt extension
            stem = line
            if stem.endswith(".txt"):
                stem = stem[:-4]
            stems.append(stem)
    else:
        # All .yaml files in ground-truth dir
        stems = [p.stem for p in sorted(gt_dir.glob("*.yaml"))]

    if not stems:
        print("ERROR: No configs to evaluate.", file=sys.stderr)
        sys.exit(1)

    print(f"Evaluating {len(stems)} configs")
    print(f"  Ground truth : {gt_dir}")
    print(f"  Predictions  : {pred_dir}")
    print()

    per_config: list[dict] = []
    missing_gt: list[str] = []

    for stem in stems:
        lower_stem = stem.lower()
        gt_path = gt_dir / f"{lower_stem}.yaml"
        if not gt_path.exists():
            # Also try uppercase
            gt_path_upper = gt_dir / f"{stem.upper()}.yaml"
            if gt_path_upper.exists():
                gt_path = gt_path_upper
            else:
                missing_gt.append(stem)
                print(f"  MISSING GT  : {stem}")
                per_config.append({
                    "stem": stem,
                    "group": _classify_group(stem),
                    "error": "ground_truth_file_missing",
                    "f1": None, "precision": None, "recall": None,
                    "object_completeness": None,
                })
                continue

        pred_yaml = _find_prediction_yaml(pred_dir, stem)
        pred_norm = _find_prediction_normalizer_json(pred_dir, stem)

        result = _compute_config_f1(gt_path, pred_yaml, pred_norm)
        result["stem"] = stem
        result["group"] = _classify_group(stem)
        per_config.append(result)

        f1_str = f"{result['f1']:.4f}" if result.get("f1") is not None else "N/A"
        oc_str = f"oc={result['object_completeness']:.3f}" if result.get("object_completeness") is not None else ""
        err_str = f"  ERROR: {result.get('error', '')}" if result.get("error") else ""
        print(f"  {stem:<40}  F1={f1_str}  {oc_str}{err_str}")

    # Aggregate per group
    groups: dict[str, list] = defaultdict(list)
    for r in per_config:
        if r.get("f1") is not None:
            groups[r["group"]].append(r)

    group_stats: dict[str, dict] = {}
    for grp, items in sorted(groups.items()):
        f1s = [r["f1"] for r in items]
        ocs = [r["object_completeness"] for r in items if r.get("object_completeness") is not None]
        precs = [r["precision"] for r in items if r.get("precision") is not None]
        recs = [r["recall"] for r in items if r.get("recall") is not None]
        group_stats[grp] = {
            "n": len(items),
            "macro_f1": round(sum(f1s) / len(f1s), 4) if f1s else None,
            "macro_precision": round(sum(precs) / len(precs), 4) if precs else None,
            "macro_recall": round(sum(recs) / len(recs), 4) if recs else None,
            "mean_object_completeness": round(sum(ocs) / len(ocs), 4) if ocs else None,
        }

    # Overall (macro-averaged across all configs with valid F1)
    all_f1s = [r["f1"] for r in per_config if r.get("f1") is not None]
    all_ocs = [r["object_completeness"] for r in per_config if r.get("object_completeness") is not None]
    all_precs = [r["precision"] for r in per_config if r.get("precision") is not None]
    all_recs = [r["recall"] for r in per_config if r.get("recall") is not None]

    overall = {
        "n_evaluated": len(all_f1s),
        "n_missing_gt": len(missing_gt),
        "macro_f1": round(sum(all_f1s) / len(all_f1s), 4) if all_f1s else None,
        "macro_precision": round(sum(all_precs) / len(all_precs), 4) if all_precs else None,
        "macro_recall": round(sum(all_recs) / len(all_recs), 4) if all_recs else None,
        "mean_object_completeness": round(sum(all_ocs) / len(all_ocs), 4) if all_ocs else None,
    }

    output = {
        "run_timestamp": datetime.now().isoformat(),
        "ground_truth_dir": str(gt_dir),
        "predictions_dir": str(pred_dir),
        "subset": args.subset,
        "overall": overall,
        "by_group": group_stats,
        "per_config": per_config,
        "missing_ground_truth": missing_gt,
    }

    out_path.write_text(json.dumps(output, indent=2, default=str))

    # Print summary
    print(f"\n{'=' * 60}")
    print("FIELD-LEVEL ACCURACY SUMMARY")
    print(f"  Configs evaluated : {overall['n_evaluated']}")
    print(f"  Missing GT        : {overall['n_missing_gt']}")
    if overall["macro_f1"] is not None:
        print(f"  Overall macro-F1  : {overall['macro_f1']:.4f}")
        print(f"  Overall precision : {overall['macro_precision']:.4f}")
        print(f"  Overall recall    : {overall['macro_recall']:.4f}")
        print(f"  Object completeness: {overall['mean_object_completeness']:.4f}")
    else:
        print("  Overall macro-F1  : N/A (no ground-truth files available)")
    print(f"\nPER GROUP:")
    for grp, gs in group_stats.items():
        f1_str = f"{gs['macro_f1']:.4f}" if gs["macro_f1"] is not None else "N/A"
        oc_str = f"oc={gs['mean_object_completeness']:.3f}" if gs["mean_object_completeness"] is not None else ""
        print(f"  {grp:<22}  n={gs['n']:2d}  F1={f1_str}  {oc_str}")
    print(f"\nResults written to: {out_path}")
    print("=" * 60)


if __name__ == "__main__":
    main()
