#!/usr/bin/env bash
# Narrated demo for the hackathon video: base Qwen vs fine-tuned Qwen on the same held-out APK.
# Everything is typed out on screen so viewers can follow. Turn Wi-Fi off first.
#
#   demo/video_demo.sh                      # normal speed, for recording
#   FAST=1 demo/video_demo.sh               # no typing effect or pauses (rehearsal / testing)
#   TYPE_DELAY=0.04 PAUSE=3 demo/video_demo.sh   # slower typing, longer pauses
#
# Outputs go to demo/video_run/ (demo/sample_report.* is not touched).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; cd "$ROOT"

APK="${APK:-data/raw/apks/ovaa-1.0.0-debug.apk}"
BASE_MODEL="${BASE_MODEL:-models/gguf/base-Q8_0.gguf}"
TUNED_MODEL="${TUNED_MODEL:-models/gguf/tuned-verifier-v1-Q8_0.gguf}"
OUT=demo/video_run
PY=.venv/bin/python
CLI=.venv/bin/apkscan-local

TYPE_DELAY="${TYPE_DELAY:-0.02}"
PAUSE="${PAUSE:-2}"
if [ "${FAST:-0}" = "1" ]; then TYPE_DELAY=0; PAUSE=0; fi

Y=$'\033[1;33m'; G=$'\033[1;32m'; R=$'\033[1;31m'; C=$'\033[1;36m'; B=$'\033[1m'; D=$'\033[2m'; N=$'\033[0m'

# ---------- narration helpers ----------
type_out() {  # type_out "text" [color]: typewriter effect, then newline
  local s="$1" color="${2:-}" i
  printf '%s' "$color"
  if [ "$TYPE_DELAY" = "0" ]; then printf '%s' "$s"
  else for ((i = 0; i < ${#s}; i++)); do printf '%s' "${s:i:1}"; sleep "$TYPE_DELAY"; done; fi
  printf '%s\n' "$N"
}
pause() { [ "$PAUSE" = "0" ] || sleep "${1:-$PAUSE}"; }
STEP_NO=0
step() { STEP_NO=$((STEP_NO + 1)); echo; type_out "[STEP $STEP_NO] $1" "$Y"; pause 1; }
say() { type_out "  $1"; }
run() {  # show the command being typed, then run it
  printf '%s$ %s' "$G" "$N"; type_out "$1" "$B"; pause 1; eval "$1"
}
slow() {  # print piped output line by line
  local line
  while IFS= read -r line; do printf '%s\n' "$line"; [ "$TYPE_DELAY" = "0" ] || sleep 0.05; done
}
count() { "$PY" demo/video_helpers.py count "$1"; }

for f in "$APK" "$BASE_MODEL" "$TUNED_MODEL" "$CLI"; do
  [ -e "$f" ] || { echo "${R}missing: $f${N}"; exit 1; }
done
mkdir -p "$OUT"
clear 2>/dev/null || true

# ---------- intro ----------
type_out "==================================================================" "$C"
type_out "  apkscan-local: offline Android vulnerability triage" "$C"
type_out "  with a small fine-tuned Qwen model (Qwen2.5-Coder-1.5B + LoRA)" "$C"
type_out "==================================================================" "$C"
pause

# ---------- step 1 ----------
step "Checking the machine and confirming we are offline"
say "Chip   : $(sysctl -n machdep.cpu.brand_string 2>/dev/null || uname -m)"
say "Memory : $(( $(sysctl -n hw.memsize 2>/dev/null || echo 0) / 1073741824 )) GB unified memory"
say "OS     : macOS $(sw_vers -productVersion 2>/dev/null || uname -r)"
say "Network check (trying to reach huggingface.co for 3 seconds) ..."
if curl -s -m 3 https://huggingface.co >/dev/null 2>&1; then
  type_out "  -> ONLINE. (For the recording, turn Wi-Fi off: the scan never uses the network.)" "$R"
else
  type_out "  -> OFFLINE. Everything below runs on this laptop only." "$G"
fi
pause

# ---------- step 2 ----------
step "The test app and the two models"
say "Target: OVAA, a deliberately vulnerable Android app."
say "It was held out completely: the model never saw it during training."
run "ls -lh $APK"
say "Two models, same size, same quantization (Q8_0). Only the training differs:"
run "ls -lh $BASE_MODEL $TUNED_MODEL"
say "How a scan works:"
say "  1. jadx decompiles the APK back to Java code and the manifest"
say "  2. a loose pattern scanner marks every suspicious line (most are false alarms)"
say "  3. the Qwen model reads each candidate and decides: real vulnerability or not"
pause

# ---------- step 3 ----------
step "Running the normal (untuned) Qwen model to find vulnerabilities in the mobile app"
say "This is the original Qwen2.5-Coder-1.5B-Instruct, no fine-tuning."
T0=$SECONDS
run "$CLI scan $APK --model $BASE_MODEL --out $OUT/base_report.json --md $OUT/base_report.md"
BASE_N=$(count "$OUT/base_report.json"); BASE_S=$((SECONDS - T0))
echo
type_out "  Result: the untuned model confirmed $BASE_N vulnerabilities (in ${BASE_S}s)." "$R"
"$PY" demo/video_helpers.py table "$OUT/base_report.json" | slow
pause

# ---------- step 4 ----------
step "Running the FINE-TUNED Qwen model on the same app"
say "Same pipeline, same candidates, same quantization. Only the LoRA fine-tune is new."
T0=$SECONDS
run "$CLI scan $APK --model $TUNED_MODEL --out $OUT/tuned_report.json --md $OUT/tuned_report.md"
TUNED_N=$(count "$OUT/tuned_report.json"); TUNED_S=$((SECONDS - T0))
echo
type_out "  Result: the fine-tuned model confirmed $TUNED_N vulnerabilities (in ${TUNED_S}s)." "$G"
"$PY" demo/video_helpers.py table "$OUT/tuned_report.json" | slow
pause

# ---------- step 5 ----------
step "Before vs after, on the same app"
type_out "  Base Qwen        : $BASE_N findings" "$R"
type_out "  Fine-tuned Qwen  : $TUNED_N findings" "$G"
say "Every finding comes with evidence, a CWE, a severity and a fix. No exploit code, by design."
pause

# ---------- step 6 ----------
step "Looking at two findings in detail"
say "1) A WebView that runs JavaScript and loads any URL, including local files:"
"$PY" demo/video_helpers.py detail "$OUT/tuned_report.json" WebViewActivity.java 24 | slow
pause 1
say "2) An encryption key hardcoded in the app:"
"$PY" demo/video_helpers.py detail "$OUT/tuned_report.json" WeakCrypto.java 9 | slow
say "Full report: $OUT/tuned_report.md"
pause

# ---------- step 7 ----------
step "Measured results on two held-out apps (OVAA + InsecureBankv2, 36 labelled issues)"
say "Read from results/runs/*/metrics.json, measured on this laptop with llama.cpp:"
echo
"$PY" demo/video_helpers.py results | slow
echo
say "Fine-tuning: F1 0.00 -> 0.71 at F16, and 0.10 -> 0.71 at Q4_K_M."
say "Q4_K_M keeps the same accuracy at 1.0 GB, a third of the F16 size."
say "Honest note: strict grep rules still score F1 0.78 vs our 0.72. The model finds"
say "more real issues than grep but raises more false alarms."
pause

# ---------- step 8 ----------
step "What still fails"
say "The main weakness: harmless constants flagged as secrets. Example from this run:"
"$PY" demo/video_helpers.py fails "$OUT/tuned_report.json" | slow
say "PASSWORD_KEY = \"password\" is a preference name, not a secret. That is the next fix."
pause

echo
type_out "==================================================================" "$C"
type_out "  Done. No network used: everything ran on this 16 GB laptop with a 1.6 GB model." "$C"
type_out "  Reports: $OUT/base_report.md and $OUT/tuned_report.md" "$C"
type_out "==================================================================" "$C"
