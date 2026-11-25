PY := .venv/bin/python
RUN ?= v1

.PHONY: setup data test baseline eval-base train eval-tuned results demo all

setup:            ## create the Python env (uv) from the lockfile
	uv sync --all-extras

data:             ## decompile/collect apps and build train/valid JSONL
	$(PY) data/materialize.py
	$(PY) data/builder.py

test:
	$(PY) -m pytest -q

baseline:
	$(PY) eval/harness.py --name grep --grep

eval-base:        ## base model, zero-shot and few-shot (F16)
	$(PY) eval/harness.py --name base-f16-zeroshot --gguf models/gguf/base-F16.gguf
	$(PY) eval/harness.py --name base-f16-fewshot --gguf models/gguf/base-F16.gguf --few-shot 2

train:            ## LoRA with MLX-LM, fuse, export GGUF F16/Q8_0/Q4_K_M
	train/train_mlx.sh $(RUN)

eval-tuned:
	for q in F16 Q8_0 Q4_K_M; do $(PY) eval/harness.py --name tuned-$(RUN)-$$q --gguf models/gguf/tuned-$(RUN)-$$q.gguf; done

results:          ## results/results.md, chart.png and README charts (results/charts/)
	$(PY) eval/report_results.py
	$(PY) eval/make_charts.py

demo:
	demo/demo.sh

all: data test baseline eval-base train eval-tuned results
