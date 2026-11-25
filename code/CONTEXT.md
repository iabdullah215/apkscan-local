# CONTEXT

Single source of truth for what this project is, why it is built this way, and where it stands. Read this first in every new session. Update the Status log at the end of each work block.

## 1. What we are building

**apkscan-local**: a small Qwen model, fine-tuned with LoRA and quantized to GGUF, that runs fully offline on a laptop and triages security vulnerabilities in decompiled Android apps.

```
app.apk -> jadx decompile -> chunk (manifest, network config, one chunk per class/method window)
        -> local Qwen GGUF via llama.cpp -> JSON findings per chunk -> merged report
```

- It **finds and explains** issues. It does **not** generate working exploits.
- Input: jadx-decompiled Java (or Kotlin source), `AndroidManifest.xml`, `network_security_config.xml`.
- Output: strict JSON array, one object per finding, or `[]` when the chunk is clean:

```json
[{"vuln_class": "insecure_webview", "cwe": "CWE-749", "masvs": "MASVS-PLATFORM-2",
  "severity": "high", "file": "com/example/WebActivity.java", "line_range": [42, 47],
  "evidence": "webView.addJavascriptInterface(new Bridge(), \"Android\")",
  "why_exploitable": "Any page loaded in this WebView can call Bridge methods ...",
  "fix": "Remove the interface or only load trusted, allowlisted origins ..."}]
```

### Vulnerability classes (v1, fixed list)

| id | class | primary CWE | MASVS v2 |
|---|---|---|---|
| exported_component | Exported component without permission protection | CWE-926 | MASVS-PLATFORM-1 |
| insecure_webview | WebView JS interface, file access, unvalidated URL loading | CWE-749 | MASVS-PLATFORM-2 |
| hardcoded_secret | Hardcoded secrets, API keys, passwords, keys | CWE-798 | MASVS-CRYPTO-2 |
| weak_crypto | ECB, static IV, MD5/SHA1 for security, hardcoded crypto keys | CWE-327 | MASVS-CRYPTO-1 |
| insecure_network | Cleartext traffic, trust-all TrustManager/HostnameVerifier | CWE-319 / CWE-295 | MASVS-NETWORK-1 |
| insecure_storage | World-readable files, secrets in SharedPreferences/external storage | CWE-922 / CWE-312 | MASVS-STORAGE-1 |
| provider_sqli | SQL injection in ContentProvider query/selection | CWE-89 | MASVS-CODE-4 |
| intent_redirection | Untrusted Intent extras launched/forwarded, unsafe intent handling | CWE-940 | MASVS-PLATFORM-1 |

Source of truth: `configs/classes.yaml`. CWE/MASVS mappings for intent_redirection and hardcoded_secret should be reviewed by a human before submission (see Open questions).

## 2. Hackathon (Qwen Local Hackathon 2026, Qwen Pakistan)

- Event page: https://luma.com/zymwkh7c . Host: Junaid Shaukat. Starter repo: `../finetune-anywhere` (github.com/junaiddshaukat/finetune-anywhere).
- Build week 23 to 28 Nov 2026. **Submissions close Sat 28 Nov 2026, 23:59 PKT (18:59 UTC).** Results Sun 29 Nov 20:00 PKT.
- Rules: solo or team up to 3; any small open-weight Qwen model, follow its licence; build during the hackathon week only (older projects do not qualify); only datasets we are allowed to use, no private or personal data; not trained from scratch.
- Judging (kickoff slides 23 Nov, authoritative): four criteria, 25% each. Usefulness (solves a real problem for someone); Proof it helped (clear before/after on examples the model never saw); Runs locally (quantized, normal laptop, hardware stated); Demo and write-up (clear video, steps someone else can follow). The Luma page also names "technical work" without weights.
- Slide rules: use a Qwen model and respect its licence; data must be our own, open licensed, or **carefully reviewed** synthetic; **real outputs only, including what still fails**; winners need ModelScope.
- Slide advice: do not leave training for Saturday; Colab GPUs are not guaranteed (we train locally on MLX, so this risk is removed).
- Kickoff slides PDF: `../Qwen Local Hackathon 2026 Kickoff.pdf`.
- Submit: (1) adapter/weights plus quantized GGUF on Hugging Face or ModelScope, (2) public GitHub repo with README (base model, data, method, hardware, before/after results), (3) 2 to 3 minute demo video running locally, (4) PR to the starter repo: fork finetune-anywhere, copy `showcase/_template/` to `showcase/qwen-local-hackathon-2026/<slug>/`, fill `model.yaml` and `README.md`, open PR titled `Showcase: <Project Name>` with the showcase template; an automated check reports what to fix. Slug: lowercase, digits, hyphens, must match `model.yaml`; `event` must equal the parent folder name. No weights, no files over 5 MB. Winners need a ModelScope account.
- `model.yaml` fields: project_name, slug, event, members[name, github], one_liner, base_model, training_tool, training_platform, method, dataset{description, size, link}, model_link, quantization, runtime, hardware_tested, demo_video, repo_link, before_after{prompt, base_output, finetuned_output} (actual outputs from the same held-out prompt).

## 3. Strategy

**Day 1 (Tue 24 Nov): complete the whole pipeline end to end once** (data, base eval, training, GGUF export, quantized eval, CLI, results table). Every later day improves one measured number.

## 4. Key decisions

| Decision | Choice | Why |
|---|---|---|
| Base model | `Qwen/Qwen2.5-Coder-1.5B-Instruct` (Apache-2.0, verified on HF API 24 Nov) | Code-specialized, small, permissive licence |
| Training | LoRA with MLX-LM on the local Apple M4 (16 GB), decision-weighted loss (`train/train_weighted.py`, first answer token x10), short system prompt, batch 2 (batch 4 stalls in swap) | Whole loop on one machine. v1 with plain loss collapsed to `[]` everywhere |
| Decision calibration | logit bias on the `[]` token (id 1294) chosen on the validation set only (`eval/calibrate.py`), v2: -1.69 | v2 learned the direction of the clean/finding decision but stays biased to `[]` |
| Default model | tuned-v2-Q8_0 (1.6 GB) | Same scores as F16; Q4_K_M loses quality |
| Runtime | llama.cpp (`llama-server`, Homebrew build 10210) | Offline, same runtime for every variant so speed and RAM are comparable |
| Quantizations | GGUF F16, Q8_0, Q4_K_M | Size/quality trade-off table |
| Env | Python 3.12 via uv, lockfile committed | Deterministic |
| JSON validity | Headline number measured **without** grammar constraints | Measures what the model learned; CLI may add a grammar later as a separate row |
| Matching | TP if `vuln_class` equal, same file, line ranges overlap (with small tolerance). A finding on a clean chunk is an FP | Simple, explainable |
| Split | **By app**, never by snippet. Synthetic samples split by generator template | No leakage |
| Line numbers | Code is shown to the model with line-number prefixes | Lets the model output `line_range` reliably |

## 5. Data

Details and licences: `DATA_SOURCES.md`. Summary:

| Source | Licence | Split |
|---|---|---|
| OVAA (oversecured/ovaa) | BSD-2-Clause | test |
| InsecureBankv2 (dineshshetty/Android-InsecureBankv2) | MIT | test |
| DIVA (payatu/diva-android) | GPL-3.0 | train |
| allsafe (t0thkr1s/allsafe-android) | Apache-2.0 | train |
| InjuredAndroid (B3nac/InjuredAndroid) | Apache-2.0 | train |
| OWASP MASTG demos (OWASP/mastg `demos/`), 24 demos | CC-BY-SA-4.0 | train |
| Synthetic, `data/synth/generator.py` | MIT (ours) | train (seed 1234) / valid (seed 1235, loss monitoring only) |
| AndroGoat | no licence on repo | **excluded** |

Labels: every test-app file was read in full and labelled by hand (Claude-assisted, needs human spot check: `python data/check_labels.py`). Out-of-scope real issues are `ignore` regions (neither TP nor FP). Training apps allsafe/InjuredAndroid use only fully reviewed files. Real training records are repeated 2x (REAL_REPEAT) so they are not drowned by synthetic data. Test set: 48 chunks, 36 findings.

## 6. Evaluation protocol

Variants, all on the held-out test apps:
1. grep baseline (`eval/baselines/grep_baseline.py`)
2. base Qwen zero-shot (F16 GGUF)
3. base Qwen few-shot (F16 GGUF)
4. fine-tuned F16, Q8_0, Q4_K_M

Metrics: precision, recall, F1 per class and overall (with raw TP/FP/FN counts), JSON validity rate, tokens/sec (prompt and generation), peak RSS of llama-server, GGUF file size. Output: `results/results.md`, `results/chart.png`, raw per-sample predictions in `results/runs/`.

Hardware for all numbers: Apple M4 (4P+6E), 16 GB unified memory, macOS 27.2.1.

## 7. Working rules

- No em-dashes in any doc, README or text in this repo.
- Ask before installing anything large or downloading anything over 500 MB.
- CLI is fully offline: no network calls at inference.
- Deterministic: fixed seeds, pinned versions, every experiment logged to `experiments/`.
- Small verifiable steps; run tests after each step.
- Defensive tool: explanations and fixes only, no exploit generation.

## 8. Repo layout

```
apkscan-local/
  CONTEXT.md README.md DATA_SOURCES.md LICENSE Makefile pyproject.toml
  configs/        classes.yaml, train.yaml
  src/apkscan/    schema.py decompile.py chunking.py prompts.py infer.py cli.py report.py
  data/           raw/ (gitignored clones), labels/ (per-app ground truth), synth/, builder.py, processed/
  train/          train_mlx.sh, export_gguf.sh, colab notebook (secondary)
  eval/           harness.py metrics.py perf.py plot.py baselines/grep_baseline.py
  models/         (gitignored) base, adapters, fused, gguf
  results/        results.md chart.png runs/
  experiments/    one JSON per run
  tests/
```

## 9. Open questions

- Confirm CWE/MASVS mapping for intent_redirection (CWE-940 chosen) and hardcoded_secret (MASVS-CRYPTO-2 chosen).
- Hugging Face account/org name for upload.
- Demo video recording (user).

## 9b. Pipeline commands

```
make data        # data/materialize.py (jadx scan trees) + data/builder.py (JSONL)
make test        # pytest (includes a train/test leakage check)
make baseline    # grep baseline
make eval-base   # base F16 zero-shot and few-shot
make train       # train/train_mlx.sh: MLX LoRA -> fuse -> GGUF F16/Q8_0/Q4_K_M
make eval-tuned  # tuned variants
make results     # results/results.md + chart.png
apkscan-local scan app.apk --model models/gguf/tuned-v1-Q4_K_M.gguf --md report.md
```

GGUF conversion uses llama.cpp b10210 (`tools/llama.cpp`, same commit as Homebrew llama-server), converter venv `tools/llama.cpp/.venv`.

## 10. Status log

- 2026-11-16: brief written, machine inventoried, plan proposed (prior session).
- 2026-11-24: plan approved with change: finish everything end to end today, iterate after. CONTEXT.md created. Licences verified via GitHub/HF APIs. Kickoff slides read and folded in.
- 2026-11-24 (day 1 build): repo scaffolded; data cloned (pinned commits); test apps OVAA/InsecureBankv2 decompiled with jadx and labelled (36 findings); training labels for DIVA, allsafe, InjuredAndroid, 24 MASTG demos; synthetic generator with rule checks; dataset 1010 train / 83 valid records. Base model downloaded (rev 2e1fd397) and exported to GGUF. grep baseline F1 0.78 (strong bar; rules written by the labeller, so it is if anything favoured). Base zero-shot eval run; LoRA v1 training started (MLX, 450 iters, rank 16, 16 layers).
- 2026-11-24 (end of day 1): FULL PIPELINE DONE END TO END. v1 LoRA (plain loss) collapsed: answers `[]` for every input (diagnosed with eval/decision_probe.py: P('[]') ~0.83 regardless of input). v2 = decision-weighted loss + short prompt + constant LR (600 iters, batch 2, 60 min) + validation-calibrated logit bias -1.69. A batch-4 attempt stalled in swap for ~1h (lost time).
- Results on held-out test (48 chunks, 36 findings): grep 0.78 F1; base F16 zero-shot 0.25, few-shot 0.24, base Q4 0.31; v1 0.00; v2 greedy 0.10 (P=1.0); v2 calibrated F16 0.35, Q8_0 0.35, Q4_K_M 0.28. Strict JSON base 0% vs tuned 96%. Fine-tuning gain is modest and within noise vs base Q4; grep is far ahead. Weak: insecure_network 0/5, provider_sqli FPs, wrong-class findings, one backwards fix text.
- CLI `apkscan-local scan` works offline (OVAA: 23 chunks in 57 s, demo/sample_report.md). README, DATA_SOURCES, results/results.md and chart written. Nothing committed to git yet; nothing uploaded.

- 2026-11-24 evening: source-vs-APK experiment. Labelled OVAA and InsecureBankv2 again from GitHub source (labels/ovaa-src.yaml, insecurebankv2-src.yaml, split test_src, same 36 findings). F1 APK -> source: grep 0.78->0.79, base F16 0.25->0.22, base Q4 0.31->0.24, tuned Q8 0.35->0.29, tuned Q4 0.28->0.27. Decision: decompilation is NOT the bottleneck; keep APK as default, added `scan --src`. Harness: `--split test_src`.

- 2026-11-24 night: VERIFIER PIPELINE built (src/apkscan/candidates.py loose scanner, data/build_verifier.py auto-labelled data 1444 train records, train/lora_config_verifier-v1.yaml, FIRST_TOKENS=5 weighted loss, 720 iters 47 min, eval/verify_harness.py, eval/calibrate_verifier.py, CLI `--mode verify` default). Metrics fix: XML lines matched with 0 tolerance (eval/rescore.py rescored old runs: tuned v2 Q8 0.32, base F16 0.23, base Q4 0.28). Loose scanner: 100% recall on train and test, 129 test candidates (65 false). Results: base as verifier F1 0.00 (F16) / 0.10 (Q4) (answers false to everything); tuned verifier v1 Q8 greedy 0.72 (P .64 R .81), calibrated 0.70, Q4 calibrated 0.71; strict grep 0.78. Union grep+verifier 0.71. Errors: 10 of 16 FPs are hardcoded_secret on harmless constants (MYPREFS = "mySharedPreferences", EMAIL_KEY = "email"); FNs mostly OVAA intent_redirection. NOTE: test set has now been used to diagnose verifier v1; further fixes are test-informed unless a separate dev app is added.

- 2026-11-25: verifier v1 F16 evaluated (calibrated, bias 0.62): F1 0.71, P .57 R .94, same as Q8/Q4. README charts added: eval/make_charts.py -> results/charts/*-{light,dark}.png (base vs tuned, precision/recall map, per class, quantization, training journey), wired into `make results`. README results tables still show pre-rescore finder numbers (0.35) and no verifier rows: refresh pending.
- 2026-11-25: README.md rewritten around the verifier pipeline (all 5 charts, verifier/finder/quantization/source tables from results.md, base-vs-tuned example TrackUserContentProvider provider_sqli, honest failure list). Model link and demo video are TODO placeholders. demo/demo.sh still passes the finder model (tuned-v2-Q8_0) while the CLI default mode is verify, and demo/sample_report.md is a finder-mode report: fix before recording the video.
- 2026-11-25: FIXED. demo/demo.sh now runs verify mode with tuned-verifier-v1-Q8_0 by default (MODE=finder for the old mode). Regenerated demo/sample_report.{md,json} on OVAA: 43 candidates, 19 findings, 54.6 s model time, 61 s total. Old finder report kept in demo/finder-v2-2026-11-24/. README has a Sample report section listing its correct findings and its errors (EntranceActivity launcher FP, PASSWORD_KEY FP, InsecureLoggerService labelled hardcoded_secret, WebViewActivity:18 duplicated across two classes).

## 11. Next steps (day 2+, priority order)

1. Verifier v2: hard negatives for hardcoded_secret (non-secret constants: pref names, action strings, extra keys, tags, column names) and more intent_redirection positives/negatives; add a licence-checked DEV app for iteration so the test set stays clean; target > grep 0.78.
1b. (Finder mode, lower priority) per-class output target (`TARGET_STYLE = "byclass"`).
2. Data for weak classes: insecure_network (code-level http:// URLs, trust-all in real code), provider_sqli negatives; consider more real apps (licence-checked).
3. Hybrid mode (grep candidates + model confirm/explain) as a separate, clearly labelled variant.
4. Upload adapter + GGUFs to Hugging Face/ModelScope (ask user for account), git init commit + public GitHub repo, demo video (user), showcase PR (model.yaml) before Sat 28 Nov 18:59 UTC.

