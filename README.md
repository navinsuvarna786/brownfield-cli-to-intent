# From Brownfield CLI to Intent Models: A Guardrailed Agentic Translation Workflow

Reproduction package for the IEEE LCN 2026 paper of the same title. This repository
contains the translation pipeline, vendor parsers, semantic rule engine, evaluation
harness, sanitized datasets, and ground-truth intent objects used to produce the
reported results.

## Repository Layout

```
schema.yaml                 # Target controller YAML intent schema
templates/                  # Jinja2 output templates (one per template category)
templates-legacy/           # Superseded templates (retained for reference)

scripts/ai_modernization/   # Translation pipeline (LangGraph state machine)
  main.py                   # Entry point: CLI, SSH, batch modes
  agents.py                 # LangGraph pipeline nodes
  models.py                 # Pydantic state models (AgentState)
  connector.py              # SSH device connector
  rag_setup.py              # ChromaDB index builder
  3850_parser.py            # Cisco IOS-XE deterministic parser
  arista_parser.py          # Arista EOS deterministic parser

scripts/                    # Evaluation harness
  batch_eval.py             # Approach C (hybrid pipeline)
  batch_eval_approach_a.py  # Approach A (rules-only)
  batch_eval_approach_b.py  # Approach B (zero-guardrail LLM)
  batch_eval_approach_b_plus.py  # Approach B+ (schema-constrained LLM)
  batch_eval_nxos_fallback.py    # NX-OS LLM-fallback evaluation
  batch_eval_stress_test.py      # Fallback/recovery stress test
  compute_f1.py             # Field-level precision/recall/F1
  blind_annotation_kappa.py # Inter-annotator agreement (Cohen's kappa)
  generate_gt.py, generate_100_configs.py  # Dataset construction
  sanitize_and_expand.py    # Corpus sanitization

validation/rules/           # 22 semantic guardrail rules (loaded at runtime)

input/sanitized/            # Sanitized evaluation corpus
  cisco/  arista/  nxos/    # 97 campus configs + 15 NX-OS fallback configs
input/stress_test/          # 5 synthetic fallback/recovery configs
input/subset_*.txt          # Evaluation split definitions
ground_truth/               # Curated ground-truth intent objects
output/                     # Pipeline outputs and evaluation results

paper/                      # LaTeX source (main.tex, references.bib, IEEEtran.cls)
```

## Setup

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # add OPENAI_API_KEY for the LLM fallback / Approach B/B+ paths
```

The deterministic Cisco IOS-XE and Arista EOS paths require no API key or network
access. An OpenAI key is only needed for the LLM fallback path and the LLM baselines.

## Running the Pipeline

```bash
# Translate a single configuration
python scripts/ai_modernization/main.py --config input/sanitized/cisco/BLDG-A-FLOOR1-SW01.txt --output-dir output/

# Reproduce the evaluation approaches
python scripts/batch_eval.py                  # Approach C (hybrid)
python scripts/batch_eval_approach_a.py       # Approach A (rules-only)
python scripts/compute_f1.py                  # Field-level F1 vs. ground truth
```

## Data

All configurations are sanitized: hostnames, IP addresses, and credentials are
replaced with RFC 5737 addresses and generic placeholders. See the paper's
Evaluation Corpus section for inclusion/exclusion criteria and corpus composition.

## Building the Paper

```bash
cd paper && pdflatex main.tex && bibtex main && pdflatex main.tex && pdflatex main.tex
```
