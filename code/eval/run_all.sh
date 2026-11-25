#!/usr/bin/env bash
# Run every evaluation variant sequentially (one model on the GPU at a time) and build the results table.
# Tuned models use the short prompt and the decision bias calibrated on validation (eval/calibrate.py).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; cd "$ROOT"
RUN="${1:-v2}"; PY=.venv/bin/python
BIAS=$($PY -c "import json;print(json.load(open('results/calibration-$RUN.json'))['logit_bias_on_empty_token'])")
for q in Q4_K_M Q8_0 F16; do
  $PY eval/harness.py --name "tuned-$RUN-$q" --gguf "models/gguf/tuned-$RUN-$q.gguf" --prompt short --empty-bias "$BIAS" | tail -1
done
[ -f results/runs/base-f16-fewshot/metrics.json ] || $PY eval/harness.py --name base-f16-fewshot --gguf models/gguf/base-F16.gguf --few-shot 2 | tail -1
[ -f results/runs/base-q4-zeroshot/metrics.json ] || $PY eval/harness.py --name base-q4-zeroshot --gguf models/gguf/base-Q4_K_M.gguf | tail -1
$PY eval/report_results.py > /dev/null
echo "results written to results/results.md"
