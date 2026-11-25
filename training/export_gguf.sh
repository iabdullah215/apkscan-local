#!/usr/bin/env bash
# Convert a Hugging Face model directory to GGUF F16, then quantize to Q8_0 and Q4_K_M.
# Usage: train/export_gguf.sh <hf_model_dir> <out_prefix>
# Uses llama.cpp b10210 (same commit as the Homebrew llama-server used for inference).
set -euo pipefail
SRC="$1"; OUT="$2"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LC="$ROOT/tools/llama.cpp"
VENV="$LC/.venv"
if [ ! -x "$VENV/bin/python" ]; then
  uv venv -q -p 3.12 "$VENV"
  # Same pins as llama.cpp requirements-convert_hf_to_gguf.txt; on macOS the PyPI torch wheel is the CPU build.
  uv pip install -q -p "$VENV/bin/python" "torch==2.11.0" "numpy~=1.26.4" "sentencepiece>=0.1.98,<0.3.0" \
    "transformers==4.57.6" "protobuf>=4.21.0,<5.0.0" -e "$LC/gguf-py"
fi
mkdir -p "$(dirname "$OUT")"
"$VENV/bin/python" "$LC/convert_hf_to_gguf.py" "$SRC" --outtype f16 --outfile "$OUT-F16.gguf"
llama-quantize "$OUT-F16.gguf" "$OUT-Q8_0.gguf" Q8_0
llama-quantize "$OUT-F16.gguf" "$OUT-Q4_K_M.gguf" Q4_K_M
ls -la "$OUT"-*.gguf
shasum -a 256 "$OUT"-*.gguf
