#!/usr/bin/env bash
# Train the LoRA adapter with MLX-LM, fuse it into the base and export GGUF (F16, Q8_0, Q4_K_M).
# Usage: train/train_mlx.sh [run_name] [config]   (v2+: decision-weighted loss via train/train_weighted.py)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; cd "$ROOT"
RUN="${1:-v2}"
CONFIG="${2:-train/lora_config_$RUN.yaml}"
[ -f "$CONFIG" ] || CONFIG=train/lora_config.yaml
PY=.venv/bin/python
mkdir -p experiments models/adapters models/fused
GIT=$(git rev-parse --short HEAD 2>/dev/null || echo none)
DATA_SHA=$(shasum -a 256 data/processed/train.jsonl | cut -c1-16)
START=$(date +%s)
if [ "$RUN" = "v1" ]; then TRAINER=(-m mlx_lm lora); else TRAINER=(train/train_weighted.py); fi
$PY "${TRAINER[@]}" -c "$CONFIG" --adapter-path "models/adapters/$RUN" 2>&1 | tee "experiments/train-$RUN.log"
TRAIN_S=$(( $(date +%s) - START ))
$PY -m mlx_lm fuse --model models/base/Qwen2.5-Coder-1.5B-Instruct --adapter-path "models/adapters/$RUN" \
    --save-path "models/fused/$RUN" --dequantize 2>&1 | tail -3
# LoRA does not change the tokenizer. mlx-lm (transformers 5) writes tokenizer_config.json in a format the
# pinned llama.cpp converter (transformers 4.57.6) cannot read, so restore the base model's original files.
for f in tokenizer.json tokenizer_config.json vocab.json merges.txt; do
  cp "models/base/Qwen2.5-Coder-1.5B-Instruct/$f" "models/fused/$RUN/$f"
done
rm -f "models/fused/$RUN/chat_template.jinja"
train/export_gguf.sh "models/fused/$RUN" "models/gguf/tuned-$RUN" | tee "experiments/export-$RUN.log"
$PY - <<PY
import json, platform, subprocess, re
log = open("experiments/train-$RUN.log").read()
clean = re.sub(r"\x1b\[[0-9;]*m", "", log.replace("\r", "\n"))
vals = re.findall(r"val ([0-9.]+)", clean)
trains = re.findall(r"^\s+\d+\s+([0-9.]+) ", clean, re.M)
peak = re.findall(r"[Pp]eak mem\w*\s+([0-9.]+)", clean)
rec = {"run": "$RUN", "git": "$GIT", "train_sha256_16": "$DATA_SHA", "train_seconds": $TRAIN_S,
       "config": open("$CONFIG").read(), "first_token_weight": "${FIRST_TOKEN_WEIGHT:-10}", "first_tokens": "${FIRST_TOKENS:-1}", "val_losses": vals, "last_train_loss": trains[-1:] ,
       "peak_mem_gb": max(map(float, peak)) if peak else None,
       "machine": platform.platform(), "mlx_lm": subprocess.run(["$PY", "-c", "import mlx_lm;print(mlx_lm.__version__)"], capture_output=True, text=True).stdout.strip()}
json.dump(rec, open("experiments/train-$RUN.json", "w"), indent=2)
print(json.dumps({k: v for k, v in rec.items() if k != "config"}, indent=2))
PY
