# apkscan-local

**Offline Android vulnerability triage with a small fine-tuned Qwen model.**

Give it an APK. It decompiles the app with jadx, finds candidate issues in the app's own code, manifest and network config, and a LoRA-tuned Qwen2.5-Coder-1.5B decides which candidates are real and explains each one with evidence, a CWE, a severity and a fix. Everything runs on a laptop through llama.cpp; nothing leaves the machine. It explains issues; it never writes exploits.

```bash
apkscan-local scan app.apk --md report.md                # verifier mode (default), about 2 min per app on an M4
apkscan-local scan --src path/to/android/project         # scan source code instead of an APK
apkscan-local scan app.apk --mode finder                 # older mode: the model reads whole code chunks
```

Built during the Qwen Local Hackathon 2026 (Qwen Pakistan, build week 23 to 28 Nov 2026). Every number below is a real measurement on apps the model never saw in training, including the parts that still fail.

| | |
|---|---|
| Base model | [Qwen/Qwen2.5-Coder-1.5B-Instruct](https://huggingface.co/Qwen/Qwen2.5-Coder-1.5B-Instruct) (Apache-2.0, revision 2e1fd397) |
| Method | LoRA (rank 16) with MLX-LM, decision-weighted loss, threshold calibrated on validation only |
| Quantization | GGUF F16, Q8_0, Q4_K_M (llama.cpp b10210) |
| Hardware (training and every number here) | Apple M4 (4P+6E cores), 16 GB unified memory, macOS 27.2.1, llama.cpp Metal |
| Model download | TODO: Hugging Face / ModelScope link |
| Demo video | TODO: link |

## Results at a glance

Test set: two whole apps held out from training, **OVAA 1.0.0** and **InsecureBankv2**, decompiled from their APKs: 36 hand-labelled findings across 8 vulnerability classes. Temperature 0, no grammar constraint.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="results/charts/01-base-vs-tuned-dark.png">
  <img alt="F1, base vs fine-tuned at the same precision. Verifier mode Q4_K_M: 0.10 to 0.71. Verifier mode F16: 0.00 to 0.71. Finder mode F16: 0.23 to 0.32. Finder mode Q4_K_M: 0.28 to 0.25. grep baseline 0.78." src="results/charts/01-base-vs-tuned-light.png">
</picture>

| Variant (held-out apps) | Precision | Recall | F1 | TP / FP / FN | Strict JSON | GGUF |
|---|---:|---:|---:|---|---:|---:|
| grep baseline, strict rules | 0.82 | 0.75 | **0.78** | 27 / 6 / 9 | n/a | n/a |
| Base Qwen2.5-Coder-1.5B as verifier, F16 | 0.00 | 0.00 | **0.00** | 0 / 1 / 36 | 2% | 3.1 GB |
| Base as verifier, Q4_K_M | 0.67 | 0.06 | **0.10** | 2 / 1 / 34 | 2% | 1.0 GB |
| **Fine-tuned verifier v1, Q8_0** (CLI default) | 0.64 | 0.81 | **0.72** | 29 / 16 / 7 | 97% | 1.6 GB |
| Fine-tuned verifier v1, Q4_K_M, calibrated | 0.57 | 0.94 | **0.71** | 34 / 26 / 2 | 99% | 1.0 GB |

What this shows:

- **The fine-tune is what makes the pipeline work.** The same base model, given the same candidates and prompt, answers "not real" to almost everything (F1 0.00 at F16, 0.10 at Q4_K_M) and rarely returns plain JSON. After LoRA it confirms 29 of 36 real issues at Q8_0 and returns strict JSON 97% of the time.
- **Quantization costs nothing here.** Q4_K_M scores the same F1 as F16 (0.71) at a third of the file size.
- **grep is still ahead on F1** (0.78 vs 0.72). The verifier finds more real issues (recall 0.81 vs 0.75, or 0.94 calibrated) but raises more false alarms. The grep rules and the labels were written by the same person, which favours grep. The model also adds what grep cannot: a per-finding explanation, severity and fix.
- The test set is small (36 findings). Differences of a few points are within noise; read the raw TP / FP / FN counts.

## How it works

```
app.apk -> jadx -> app files only (library packages skipped) -> files with original line numbers
        -> loose pattern scanner (high recall, mostly false alarms)        -> candidates
        -> llama-server on 127.0.0.1 + fine-tuned verifier GGUF            -> {"real": true/false, ...} per candidate
        -> confirmed findings -> dedupe -> JSON + Markdown report
```

1. **Loose scanner** (`src/apkscan/candidates.py`): broad per-class regexes over Java/Kotlin, `AndroidManifest.xml` and `network_security_config.xml`. On the held-out apps it raises 129 candidates and covers **all 36** labelled findings, but 65 of them are false. Its patterns were written against the training apps only.
2. **Verifier** (fine-tuned Qwen): sees a small window (about 10 lines either side) around each candidate and answers with strict JSON:

```json
{"real": true, "severity": "high", "cwe": "CWE-89",
 "evidence": "caller projection, selection and sortOrder passed to SQLiteQueryBuilder.query without setStrict or a projection map",
 "why_exploitable": "A calling app controls part of the SQL, so it can read rows or tables beyond user data ...",
 "fix": "Use parameterized selections with selectionArgs, a fixed projection map, qb.setStrict(true) and setStrictColumns, and require a permission on the provider."}
```

The 8 classes, with CWE and MASVS v2 mappings, are in [configs/classes.yaml](configs/classes.yaml):

| Class | What it covers | CWE | MASVS v2 |
|---|---|---|---|
| exported_component | Exported activity, service, receiver or provider without a permission | CWE-926 | MASVS-PLATFORM-1 |
| insecure_webview | JavaScript interface, file access, unvalidated URL loading | CWE-749 | MASVS-PLATFORM-2 |
| hardcoded_secret | API keys, passwords, crypto keys in code | CWE-798 | MASVS-CRYPTO-2 |
| weak_crypto | ECB, static IV, MD5/SHA1 for security, hardcoded keys | CWE-327 | MASVS-CRYPTO-1 |
| insecure_network | Cleartext traffic, trust-all TrustManager or HostnameVerifier | CWE-319 / CWE-295 | MASVS-NETWORK-1 |
| insecure_storage | World-readable files, secrets in SharedPreferences or external storage | CWE-922 / CWE-312 | MASVS-STORAGE-1 |
| provider_sqli | SQL injection through ContentProvider selection or projection | CWE-89 | MASVS-CODE-4 |
| intent_redirection | Untrusted intent extras launched or forwarded, implicit broadcasts with data | CWE-940 | MASVS-PLATFORM-1 |

There is also a **finder mode** (`--mode finder`), the first design: the model reads each whole code chunk and lists findings itself. It is kept for comparison; it scores much lower (F1 0.32, see below).

## Before and after, on a held-out candidate

InsecureBankv2 `TrackUserContentProvider.java`, line 78: the provider passes the caller's projection, selection and sort order straight into `SQLiteQueryBuilder.query`. Labelled as a real `provider_sqli` issue. grep misses it.

**Base Qwen2.5-Coder-1.5B-Instruct (F16)**, same prompt, wrapped in a code fence:

````
```json
{
  "real": false
}
```
````

**Fine-tuned verifier v1 (Q8_0)**, strict JSON:

```json
{"real": true, "severity": "high", "cwe": "CWE-89",
 "evidence": "caller projection, selection and sortOrder passed to SQLiteQueryBuilder.query without setStrict or a projection map",
 "why_exploitable": "A calling app controls part of the SQL, so it can read rows or tables beyond user data (for example with UNION SELECT or a subquery in the selection).",
 "fix": "Use parameterized selections with selectionArgs, a fixed projection map, qb.setStrict(true) and setStrictColumns, and require a permission on the provider."}
```

The same pattern repeats across the test set: the base model rejected every one of the 36 real candidates at F16; the tuned model confirmed 29. Every raw answer is in `results/runs/*/predictions.jsonl`.

## Sample report

[demo/sample_report.md](demo/sample_report.md) (JSON: [demo/sample_report.json](demo/sample_report.json)) is a full, unedited `demo/demo.sh` run on the held-out OVAA APK with the default verifier (Q8_0): 22 app files, 43 candidates, 19 confirmed findings (10 high, 9 medium). The model took 54.6 s and the whole run, jadx included, took 61 s on the M4.

It shows the strengths and the known errors side by side:

- Correct (matches the labels): four exported components without permissions (LoginActivity, MainActivity, InsecureLoggerService, TheftOverwriteProvider), the cleartext `BASE_URL`, the JavaScript WebView that loads the `url` extra and `file://` URLs, the hardcoded AES key, `Cipher.getInstance("AES")`, and picked content copied to external cache.
- False alarms: `EntranceActivity` is flagged as exported, but it is the launcher activity and must be exported. `PASSWORD_KEY = "password"` is a preference key, not a secret; this is the `hardcoded_secret` weakness described below.
- Wrong label: an exported `InsecureLoggerService` that dumps logs for any sender is confirmed as `hardcoded_secret`. The scanner assigned the class and the model accepted it.
- Duplicate: `WebViewActivity.java` line 18 is reported as both `insecure_webview` and `intent_redirection`.

The earlier finder-mode report (24 Nov, `tuned-v2-Q8_0`) is kept in [demo/finder-v2-2026-11-24/](demo/finder-v2-2026-11-24/) for comparison.

## Detailed results

### Precision and recall

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="results/charts/02-precision-recall-dark.png">
  <img alt="Precision against recall for every variant. grep: precision 0.82, recall 0.75. Fine-tuned verifier greedy: 0.64, 0.81. Fine-tuned verifier calibrated: 0.57, 0.94. Loose scan alone: 0.36, 1.00. Every base model variant finds at most 0.25 of the issues." src="results/charts/02-precision-recall-light.png">
</picture>

### Verifier pipeline, every variant

| Variant | F1 | Precision | Recall | TP / FP / FN | Verdict accuracy | Strict JSON | s / candidate | Peak RSS | Gen tok/s |
|---|---:|---:|---:|---|---:|---:|---:|---:|---:|
| strict grep baseline (reference) | 0.78 | 0.82 | 0.75 | 27 / 6 / 9 | - | - | - | - | - |
| loose scanner alone (every candidate reported) | 0.53 | 0.36 | 1.00 | 36 / 65 / 0 | 0.39 | 100% | - | - | - |
| base model as verifier, F16 | 0.00 | 0.00 | 0.00 | 0 / 1 / 36 | 0.61 | 2% | 1.12 | 4.7 GB | 27.5 |
| base model as verifier, Q4_K_M | 0.10 | 0.67 | 0.06 | 2 / 1 / 34 | 0.62 | 2% | 0.92 | 2.7 GB | 60.7 |
| **fine-tuned verifier v1, Q8_0, greedy** | **0.72** | 0.64 | 0.81 | 29 / 16 / 7 | 0.75 | 97% | 1.71 | 3.5 GB | 48.9 |
| fine-tuned verifier v1, F16, calibrated | 0.71 | 0.57 | 0.94 | 34 / 26 / 2 | 0.72 | 96% | 2.42 | 3.9 GB | 32.5 |
| fine-tuned verifier v1, Q8_0, calibrated | 0.70 | 0.56 | 0.94 | 34 / 27 / 2 | 0.72 | 97% | 2.01 | 3.7 GB | 52.0 |
| fine-tuned verifier v1, Q4_K_M, calibrated | 0.71 | 0.57 | 0.94 | 34 / 26 / 2 | 0.72 | 99% | 1.95 | 3.0 GB | 58.9 |

"Calibrated" means a logit bias of +0.62 on the ` true` token, chosen on the validation set only ([eval/calibrate_verifier.py](eval/calibrate_verifier.py), [results/calibration-verifier-v1.json](results/calibration-verifier-v1.json)). It trades precision for recall. The CLI default is greedy Q8_0 (no bias); pass `--true-bias 0.62` for the high-recall setting. Peak RSS is the llama-server process including memory-mapped weights.

### Per class

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="results/charts/03-per-class-dark.png">
  <img alt="Per class, fine-tuned verifier vs grep. Found: equal on exported components, hardcoded secrets, weak crypto, cleartext TLS, storage and intent redirection; the verifier finds one more WebView issue and the one ContentProvider SQLi grep misses. False alarms: verifier 10 on hardcoded secrets (grep 4), 3 on storage (grep 2), 3 on intent redirection (grep 0)." src="results/charts/03-per-class-light.png">
</picture>

The verifier matches grep on six classes, finds one more WebView issue and the ContentProvider SQL injection that grep misses. Its weakness is false alarms on `hardcoded_secret` (10 vs 4).

### Quantization

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="results/charts/04-quantization-dark.png">
  <img alt="Fine-tuned verifier by quantization. F1: F16 0.71, Q8_0 0.70, Q4_K_M 0.71. File size: 3.1, 1.6, 1.0 GB. Peak memory: 3.9, 3.7, 3.0 GB. Generation: 32, 52, 59 tokens per second." src="results/charts/04-quantization-light.png">
</picture>

| Fine-tuned verifier v1, calibrated | F1 | GGUF size | Peak RSS | Generation tok/s | Prompt tok/s | Scan time per test app |
|---|---:|---:|---:|---:|---:|---:|
| F16 | 0.71 | 3.1 GB | 3.9 GB | 32.5 | 1324 | 156 s |
| Q8_0 | 0.70 | 1.6 GB | 3.7 GB | 52.0 | 657 | 129 s |
| Q4_K_M | 0.71 | 1.0 GB | 3.0 GB | 58.9 | 558 | 126 s |

Any of the three fits comfortably on a 16 GB laptop alongside jadx. Q4_K_M is the best choice on smaller machines.

### Finder mode (the first design)

The model reads each whole chunk (48 chunks in the test apps) and lists findings itself.

| Variant | Precision | Recall | F1 | TP / FP / FN | Strict JSON | s / chunk | GGUF |
|---|---:|---:|---:|---|---:|---:|---:|
| Base, zero-shot, F16 | 0.27 | 0.19 | 0.23 | 7 / 19 / 29 | 0% | 5.6 | 3.1 GB |
| Base, few-shot (k=2), F16 | 0.27 | 0.22 | 0.24 | 8 / 22 / 28 | 92% | 6.2 | 3.1 GB |
| Base, zero-shot, Q4_K_M | 0.31 | 0.25 | 0.28 | 9 / 20 / 27 | 0% | 4.5 | 1.0 GB |
| Fine-tuned v1 (plain LoRA, collapsed) | 0.00 | 0.00 | 0.00 | 0 / 0 / 36 | 100% | 0.9 | 1.0 GB |
| Fine-tuned v2, Q4_K_M, greedy | 1.00 | 0.06 | 0.10 | 2 / 0 / 34 | 100% | 0.9 | 1.0 GB |
| Fine-tuned v2, F16, calibrated | 0.39 | 0.28 | 0.32 | 10 / 16 / 26 | 96% | 4.5 | 3.1 GB |
| Fine-tuned v2, Q8_0, calibrated | 0.39 | 0.28 | 0.32 | 10 / 16 / 26 | 96% | 3.1 | 1.6 GB |
| Fine-tuned v2, Q4_K_M, calibrated | 0.28 | 0.22 | 0.25 | 8 / 21 / 28 | 85% | 3.2 | 1.0 GB |

Fine-tuning helped at F16 (0.23 to 0.32, strict JSON 0% to 96%) but not at Q4_K_M (0.28 to 0.25). Asking a 1.5B model to both find and classify everything in a 100-line chunk was too hard; splitting the job into "pattern proposes, model decides" is what moved F1 from 0.32 to 0.72.

### APK versus source input

Does jadx decompilation noise hurt? The same two apps were labelled again from their GitHub source (same 36 findings, source line numbers) and the finder models rerun:

| Variant | F1 on APK (jadx) | F1 on source |
|---|---:|---:|
| grep baseline | 0.78 | 0.79 |
| Base, zero-shot, F16 | 0.23 | 0.22 |
| Base, zero-shot, Q4_K_M | 0.28 | 0.21 |
| Fine-tuned v2, Q8_0 | 0.32 | 0.29 |
| Fine-tuned v2, Q4_K_M | 0.25 | 0.27 |

Source input does not help, so decompilation is not the bottleneck. APK input stays the default because auditing apps without source is where the tool is most useful; `--src` is supported.

Full tables, including per-class F1 for every variant: [results/results.md](results/results.md).

## What still fails

Real outputs from the held-out run (fine-tuned verifier v1, Q8_0):

- **False alarms on harmless constants.** 10 of the 16 false positives are `hardcoded_secret` on strings that are not secrets: `MYPREFS2 = "mySharedPreferences"`, a password-policy regex `PASSWORD_PATTERN = "((?=.*\d)..."`, and twice on `Cipher.getInstance("AES/CBC/PKCS5Padding")`.
- **Missed intent redirection in OVAA.** 4 of the 7 misses are OVAA `intent_redirection` (deep link handling in `DeeplinkActivity`, the login-data broadcast in `MainActivity`). Those need data-flow reasoning across more than a 20-line window.
- **Right verdict, wrong explanation.** Sometimes the verdict is correct but the text belongs to another class: for the cleartext `BASE_URL = "http://..."` in OVAA the model says real (correct, `insecure_network`) but explains it as a hardcoded secret that "cannot be rotated".
- **Small test set.** Two apps, 36 findings. Per-class counts are 1 to 10.
- **Test set now used for diagnosis.** The verifier v1 numbers above are its first and only evaluation. The error analysis in this section looked at the test predictions, so any future version tuned on these errors needs a separate dev app to stay honest.

Treat output as triage leads for a human reviewer, not verdicts.

## Training journey

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="results/charts/05-journey-dark.png">
  <img alt="F1 per training step: v1 plain LoRA 0.00, v2 weighted loss 0.10, v2 with calibration 0.32, verifier v1 0.72. Best base model 0.28, grep baseline 0.78." src="results/charts/05-journey-light.png">
</picture>

1. **v1, plain LoRA (finder): F1 0.00.** Training loss went down, then the model answered `[]` ("clean") for every input, including its own training examples. The first answer token (`[]` versus `[`) is the whole "is there a vulnerability here" decision, but it is 1 of about 140 answer tokens, so the model learned the JSON format without learning when to use it. [eval/decision_probe.py](eval/decision_probe.py) showed P(`[]`) of about 0.83 for every input.
2. **v2, decision-weighted loss: F1 0.10.** [train/train_weighted.py](train/train_weighted.py) gives the first answer token 10x weight, plus a shorter system prompt and a constant learning rate. The model learned the direction of the decision but stayed biased to `[]`: precise (2 of 2 correct) but found almost nothing.
3. **v2 + calibration: F1 0.32.** A logit bias of -1.69 on the `[]` token, chosen on the validation set only ([eval/calibrate.py](eval/calibrate.py)), applied through llama-server `logit_bias`.
4. **Verifier v1: F1 0.72.** New task split: the loose scanner proposes, the model decides. Training data built automatically by running the scanner over the labelled training apps and marking each candidate real or false ([data/build_verifier.py](data/build_verifier.py)). Same weighted loss over the first 5 answer tokens.

| Training run | Data | Iterations | Batch | LR | Time on M4 | Final val loss |
|---|---|---:|---:|---|---:|---:|
| finder v2 | 780 records (282 clean) | 600 | 2 | 1.5e-4 constant | 59 min | 0.101 |
| verifier v1 | 1444 candidates (685 real, 759 false) | 720 (about 1 epoch) | 2 | 1.5e-4 constant, 30 warmup | 46 min | 0.033 |

Both: LoRA rank 16, scale 2.0, dropout 0.05, last 16 of 28 transformer blocks, all attention and MLP projections, loss on the answer only, seed 0, MLX-LM 0.32.2. Batch 4 stalled in swap on 16 GB, so batch 2. Configs: [train/lora_config_v2.yaml](train/lora_config_v2.yaml), [train/lora_config_verifier-v1.yaml](train/lora_config_verifier-v1.yaml). Logs: [experiments/](experiments/).

## Data

All sources, licences and pinned revisions: [DATA_SOURCES.md](DATA_SOURCES.md).

| Source | Licence | Use |
|---|---|---|
| OVAA 1.0.0, InsecureBankv2 (APKs) | BSD-2-Clause, MIT | **test only**, every file labelled by hand |
| DIVA, allsafe, InjuredAndroid (source) | GPL-3.0, Apache-2.0, Apache-2.0 | training, reviewed files only |
| OWASP MASTG demos (24, jadx-reversed) | CC-BY-SA-4.0 | training |
| Synthetic generator ([data/synth/generator.py](data/synth/generator.py)) | MIT (this repo) | training (seed 1234), validation (seed 1235); rule-checked labels, safe look-alikes as hard negatives |
| AndroGoat | no licence in repo | excluded |

- **Split by app, never by snippet.** A unit test checks that no test-app text appears in any training file.
- Real-app records are repeated 2x in the finder training file so the synthetic data does not drown them.
- No personal data: the "credentials" in these apps are fake demo values shipped by their authors.
- Labels were made with AI assistance by reading every file in full; `python data/check_labels.py` prints them for human spot checks. Real issues outside the 8 classes are marked `ignore` (neither TP nor FP).

## Reproduce

Requirements: macOS on Apple Silicon (training uses MLX), Python 3.12, [uv](https://docs.astral.sh/uv/), `brew install jadx llama.cpp`. The base model download is about 3.1 GB.

```bash
make setup                                   # uv env from uv.lock
make data                                    # clone/decompile sources at pinned commits, build JSONL
make test                                    # unit tests + train/test leakage check
make baseline eval-base                      # grep baseline, base model zero/few-shot (finder)

# verifier (the default pipeline)
.venv/bin/python data/build_verifier.py      # data/processed_verifier/{train,valid}.jsonl
FIRST_TOKENS=5 train/train_mlx.sh verifier-v1   # MLX LoRA -> fuse -> GGUF F16/Q8_0/Q4_K_M (~50 min)
.venv/bin/python eval/calibrate_verifier.py models/adapters/verifier-v1 results/calibration-verifier-v1.json
.venv/bin/python eval/verify_harness.py --name verifier-v1-Q8_0-greedy --gguf models/gguf/tuned-verifier-v1-Q8_0.gguf
.venv/bin/python eval/verify_harness.py --name verifier-v1-Q4_K_M --gguf models/gguf/tuned-verifier-v1-Q4_K_M.gguf --true-bias 0.62

# finder (comparison)
make train RUN=v2                            # ~65 min
.venv/bin/python eval/calibrate.py models/adapters/v2 results/calibration-v2.json
eval/run_all.sh v2

make results                                 # results/results.md and the charts in results/charts/
demo/demo.sh                                 # offline verify-mode scan of the OVAA APK -> demo/sample_report.md
demo/video_demo.sh                           # narrated base-vs-fine-tuned demo (FAST=1 to skip the typing effect)
```

Inference only (any machine with llama.cpp, no training stack needed): download a verifier GGUF, then

```bash
apkscan-local scan app.apk --model tuned-verifier-v1-Q4_K_M.gguf --md report.md --out report.json
```

`llama-server` binds 127.0.0.1 only and the CLI makes no network calls. jadx itself can use several GB of memory on large apps.

## Limits

- 8 classes only. Real issues outside them (deserialization, path traversal, logging of secrets) are not reported.
- Training and test apps are deliberately vulnerable demo apps. Obfuscated release builds of real apps have not been tested.
- The verifier only sees what the loose scanner flags. On the test apps that was 100% of labelled issues, but a new pattern the scanner does not know will be missed.
- Class, line range and file come from the scanner; the model only decides real or not and writes the explanation.

## Next

1. Verifier v2: hard negatives for `hardcoded_secret` (preference names, intent action strings, extra keys, column names) and more `intent_redirection` examples, evaluated against a separate, licence-checked dev app so the test set stays clean.
2. More real training code for `insecure_storage` and `intent_redirection`.
3. Hybrid report: strict grep hits plus verifier-confirmed candidates, clearly labelled.

## Licence

Code: [MIT](LICENSE). The base model is Apache-2.0. Training data keeps its original licences (see [DATA_SOURCES.md](DATA_SOURCES.md)).
