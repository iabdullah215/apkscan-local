# Results

Held-out test apps: OVAA 1.0.0 and InsecureBankv2 (whole apps never seen in training), 48 chunks, 36 labelled findings. Hardware: Apple M4 (10 cores), 16 GB unified memory, macOS 27.2.1, llama.cpp b10210 (Metal). Decoding: temperature 0, seed 0, no grammar constraint.

## Overall

| Variant | Precision | Recall | F1 | Macro F1 | TP / FP / FN | Strict JSON | Gen tok/s | Prompt tok/s | s/chunk | Peak RSS MB | GGUF MB |
|---|---:|---:|---:|---:|---|---:|---:|---:|---:|---:|---:|
| grep baseline | 0.82 | 0.75 | **0.78** | 0.67 | 27 / 6 / 9 | 100% | - | - | - | - | - |
| Base Qwen2.5-Coder-1.5B, zero-shot (F16) | 0.27 | 0.19 | **0.23** | 0.21 | 7 / 19 / 29 | 0% | 31.7 | 2017.5 | 5.59 | 4029 | 3094 |
| Base, few-shot k=2 (F16) | 0.27 | 0.22 | **0.24** | 0.23 | 8 / 22 / 28 | 92% | 31.0 | 1747.9 | 6.21 | 3403 | 3094 |
| Base, zero-shot (Q4_K_M) | 0.31 | 0.25 | **0.28** | 0.25 | 9 / 20 / 27 | 0% | 62.4 | 935.8 | 4.48 | 2558 | 986 |
| Fine-tuned v1 (Q4_K_M, greedy) | 0.00 | 0.00 | **0.00** | 0.00 | 0 / 0 / 36 | 100% | 113.9 | 1368.0 | 0.91 | 2202 | 986 |
| Fine-tuned v2 (Q4_K_M, greedy) | 1.00 | 0.06 | **0.10** | 0.17 | 2 / 0 / 34 | 100% | 86.8 | 892.4 | 0.87 | 2224 | 986 |
| Fine-tuned v2 (F16, calibrated) | 0.39 | 0.28 | **0.32** | 0.29 | 10 / 16 / 26 | 96% | 32.2 | 675.8 | 4.47 | 4465 | 3094 |
| Fine-tuned v2 (Q8_0, calibrated) | 0.39 | 0.28 | **0.32** | 0.29 | 10 / 16 / 26 | 96% | 52.1 | 628.6 | 3.14 | 3035 | 1647 |
| Fine-tuned v2 (Q4_K_M, calibrated) | 0.28 | 0.22 | **0.25** | 0.26 | 8 / 21 / 28 | 85% | 67.2 | 711.3 | 3.15 | 2441 | 986 |

Peak RSS is the llama-server process and includes memory-mapped weights.

## F1 per class

| Class | gold | grep baseline | Base Qwen2.5-Coder-1.5B, zero-shot (F16) | Base, few-shot k=2 (F16) | Base, zero-shot (Q4_K_M) | Fine-tuned v1 (Q4_K_M, greedy) | Fine-tuned v2 (Q4_K_M, greedy) | Fine-tuned v2 (F16, calibrated) | Fine-tuned v2 (Q8_0, calibrated) | Fine-tuned v2 (Q4_K_M, calibrated) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| exported_component | 10 | 1.00 (10/0/0) | 0.27 (2/3/8) | 0.29 (2/2/8) | 0.29 (2/2/8) | 0.00 (0/0/10) | 0.00 (0/0/10) | 0.31 (2/1/8) | 0.31 (2/1/8) | 0.00 (0/3/10) |
| insecure_webview | 4 | 0.67 (2/0/2) | 0.36 (2/5/2) | 0.26 (3/16/1) | 0.35 (3/10/1) | 0.00 (0/0/4) | 0.00 (0/0/4) | 0.57 (2/1/2) | 0.57 (2/1/2) | 0.57 (2/1/2) |
| hardcoded_secret | 2 | 0.50 (2/4/0) | 0.00 (0/2/2) | 0.00 (0/2/2) | 0.00 (0/1/2) | 0.00 (0/0/2) | 0.67 (1/0/1) | 0.33 (1/3/1) | 0.33 (1/3/1) | 0.40 (1/2/1) |
| weak_crypto | 2 | 1.00 (2/0/0) | 0.67 (1/0/1) | 1.00 (2/0/0) | 0.67 (1/0/1) | 0.00 (0/0/2) | 0.67 (1/0/1) | 0.40 (1/2/1) | 0.40 (1/2/1) | 0.50 (1/1/1) |
| insecure_network | 5 | 1.00 (5/0/0) | 0.18 (1/5/4) | 0.25 (1/2/4) | 0.17 (1/6/4) | 0.00 (0/0/5) | 0.00 (0/0/5) | 0.00 (0/0/5) | 0.00 (0/0/5) | 0.00 (0/0/5) |
| insecure_storage | 5 | 0.60 (3/2/2) | 0.20 (1/4/4) | 0.00 (0/0/5) | 0.50 (2/1/3) | 0.00 (0/0/5) | 0.00 (0/0/5) | 0.22 (1/3/4) | 0.22 (1/3/4) | 0.25 (1/2/4) |
| provider_sqli | 1 | 0.00 (0/0/1) | 0.00 (0/0/1) | 0.00 (0/0/1) | 0.00 (0/0/1) | 0.00 (0/0/1) | 0.00 (0/0/1) | 0.00 (0/3/1) | 0.00 (0/3/1) | 0.00 (0/3/1) |
| intent_redirection | 7 | 0.60 (3/0/4) | 0.00 (0/0/7) | 0.00 (0/0/7) | 0.00 (0/0/7) | 0.00 (0/0/7) | 0.00 (0/0/7) | 0.46 (3/3/4) | 0.46 (3/3/4) | 0.32 (3/9/4) |

Cells: F1 (TP/FP/FN). With small per-class counts, read the raw counts, not only F1.

## Same apps from source code instead of the APK

Same two apps and the same 36 findings, labelled at source line numbers (GitHub source of OVAA and InsecureBankv2). Same models, prompts and calibration.

| Variant | F1 on APK (jadx) | F1 on source | Precision (src) | Recall (src) | TP / FP / FN (src) | Strict JSON (src) | s/chunk (src) |
|---|---:|---:|---:|---:|---|---:|---:|
| grep baseline | 0.78 | **0.79** | 0.80 | 0.78 | 28 / 7 / 8 | 100% | - |
| Base Qwen2.5-Coder-1.5B, zero-shot (F16) | 0.23 | **0.22** | 0.25 | 0.19 | 7 / 21 / 29 | 0% | 7.61 |
| Base, zero-shot (Q4_K_M) | 0.28 | **0.21** | 0.29 | 0.17 | 6 / 15 / 30 | 0% | 3.8 |
| Fine-tuned v2 (Q8_0, calibrated) | 0.32 | **0.29** | 0.36 | 0.25 | 9 / 16 / 27 | 96% | 3.03 |
| Fine-tuned v2 (Q4_K_M, calibrated) | 0.25 | **0.27** | 0.28 | 0.25 | 9 / 23 / 27 | 100% | 3.02 |

## Verifier pipeline (loose pattern scan, then a model confirms each candidate)

Same held-out apps and labels. The loose scanner raises 129 candidates and covers 100% of the labelled findings; the verifier decides which are real.

| Variant | F1 | Precision | Recall | TP / FP / FN | Verdict accuracy | Strict JSON | s/candidate |
|---|---:|---:|---:|---|---:|---:|---:|
| strict grep baseline (for reference) | 0.78 | 0.82 | 0.75 | 27 / 6 / 9 | - | - | - |
| loose scanner alone (every candidate reported) | **0.53** | 0.36 | 1.00 | 36 / 65 / 0 | 0.39 | 100% | - |
| base model as verifier (F16) | **0.00** | 0.00 | 0.00 | 0 / 1 / 36 | 0.61 | 2% | 1.12 |
| base model as verifier (Q4_K_M) | **0.10** | 0.67 | 0.06 | 2 / 1 / 34 | 0.62 | 2% | 0.92 |
| fine-tuned verifier v1 (Q8_0, greedy) | **0.72** | 0.64 | 0.81 | 29 / 16 / 7 | 0.75 | 97% | 1.71 |
| fine-tuned verifier v1 (F16, calibrated) | **0.71** | 0.57 | 0.94 | 34 / 26 / 2 | 0.72 | 96% | 2.42 |
| fine-tuned verifier v1 (Q8_0, calibrated) | **0.70** | 0.56 | 0.94 | 34 / 27 / 2 | 0.72 | 97% | 2.01 |
| fine-tuned verifier v1 (Q4_K_M, calibrated) | **0.71** | 0.57 | 0.94 | 34 / 26 / 2 | 0.72 | 99% | 1.95 |

