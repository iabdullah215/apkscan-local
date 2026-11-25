#!/usr/bin/env bash
# Demo: scan a held-out APK fully offline with the quantized fine-tuned verifier.
# For the video: turn Wi-Fi off first, then run this script.
#   demo/demo.sh [app.apk]
#   MODE=finder MODEL=models/gguf/tuned-v2-Q8_0.gguf demo/demo.sh   (older finder mode, for comparison)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; cd "$ROOT"
APK="${1:-data/raw/apks/ovaa-1.0.0-debug.apk}"
MODE="${MODE:-verify}"
if [ "$MODE" = "verify" ]; then DEFAULT_MODEL=models/gguf/tuned-verifier-v1-Q8_0.gguf; else DEFAULT_MODEL=models/gguf/tuned-v2-Q8_0.gguf; fi
MODEL="${MODEL:-$DEFAULT_MODEL}"
echo "== network check (expect no route when offline)"; (curl -s -m 3 https://huggingface.co >/dev/null && echo "online") || echo "offline"
echo "== mode: $MODE, model: $MODEL ($(du -h "$MODEL" | cut -f1))"
/usr/bin/time -l .venv/bin/apkscan-local scan "$APK" --mode "$MODE" --model "$MODEL" --md demo/sample_report.md --out demo/sample_report.json 2> >(tee demo/last_run_stderr.txt >&2)
echo "== report: demo/sample_report.md"
head -40 demo/sample_report.md
