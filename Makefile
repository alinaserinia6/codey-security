PYTHON ?= python3

.PHONY: help install test doctor phase1 phase2 phase3 bench taint-bench \
        python-bench manifest-sard manifest-devign manifest-bigvul aggregate \
        presentation clean

help:
	@echo 'Targets:'
	@echo '  test         run the test suite'
	@echo '  doctor       check the toolchain and the environment'
	@echo '  phase1       static + structural report for FILE= (default examples/cpp/vulnerable.cpp)'
	@echo '  phase2       Scanner -> Verifier report for REPORT= (default results/phase1_report.json)'
	@echo '  phase3       evaluate MANIFEST= through the pipeline'
	@echo '  bench        full benchmark ladder, selectable with ARGS='
	@echo '               (make bench ARGS="--list" to see every choice)'
	@echo '  taint-bench  source-to-sink evidence vs Flawfinder on VulnLLM-R C'
	@echo '  python-bench source-to-sink evidence vs Bandit on the Python benchmark'
	@echo '  manifest-*   build a Phase 3 manifest from SARD / Devign / Big-Vul'
	@echo '  aggregate    merge the experiment JSON files into a comparison CSV'
	@echo '  presentation rebuild the defence deck'

install:
	$(PYTHON) -m pip install -r requirements.txt

test:
	$(PYTHON) -m pytest -q

doctor:
	$(PYTHON) scripts/doctor.py

phase1:
	$(PYTHON) -m analyzers.phase1_pipeline \
		$(or $(FILE),examples/cpp/vulnerable.cpp) \
		--out $(or $(OUT),results/phase1_report.json)

# The Scanner/Verifier architecture is the default; pass ARCH=single_agent to
# run the original one-agent-per-group path for the comparison.
phase2:
	$(PYTHON) scripts/run_phase2.py \
		$(or $(REPORT),results/phase1_report.json) \
		--architecture $(or $(ARCH),multi_agent) \
		--out $(or $(OUT),results/phase2_report.json)

phase3:
	$(PYTHON) -m codey_security phase3

# The one command for the full ladder. Everything is chosen on the command
# line: which suites (static/taint/llm), which legs (A/B/C/D/E), which
# datasets, which manifest the LLM subset is cut from, model, tag.
#   make bench ARGS="--list"
#   make bench ARGS="--suite static,taint --datasets all"
#   make bench ARGS="--suite llm --llm-source vulnllm_r_python --llm-limit 30 --tag py30"
bench:
	$(PYTHON) scripts/run_benchmarks.py $(ARGS)

taint-bench:
	$(PYTHON) scripts/eval_taint_evidence.py \
		--dataset $(or $(DATASET),datasets/vulnllm_r_c.json) \
		--baseline flawfinder \
		--out $(or $(OUT),results/exp_E_taint_evidence.json)

python-bench:
	$(PYTHON) scripts/make_python_bench.py
	$(PYTHON) scripts/eval_taint_evidence.py \
		--dataset datasets/python_bench/python_bench.json \
		--baseline bandit \
		--out results/exp_F_python_bench.json

aggregate:
	$(PYTHON) scripts/aggregate_phase3.py \
		--csv $(or $(OUT),results/comparison.csv) \
		$(or $(RESULTS),results/exp_vulnllm_r_c_static.json \
			results/exp_vulnllm_r_python_static.json \
			results/exp_vulnllm_r_c_dataflow_static.json)

# Convert a public corpus into the same manifest format the other benchmarks
# use, so one evaluation harness measures all of them. CORPUS points at a
# downloaded release; see the README for where each comes from.
manifest-sard:
	@test -n "$(CORPUS)" || (echo 'Usage: make manifest-sard CORPUS=/path/to/sard OUT=datasets/sard.json'; exit 1)
	$(PYTHON) scripts/make_manifest.py sard --root $(CORPUS) \
		$(if $(ASSUME_VULNERABLE),--assume-vulnerable,) \
		--out $(or $(OUT),datasets/sard.json)

manifest-devign:
	@test -n "$(CORPUS)" || (echo 'Usage: make manifest-devign CORPUS=datasets/devign.json'; exit 1)
	$(PYTHON) scripts/make_manifest.py devign --input $(CORPUS) \
		--out $(or $(OUT),datasets/devign_manifest.json)

manifest-bigvul:
	@test -n "$(CORPUS)" || (echo 'Usage: make manifest-bigvul CORPUS=datasets/big-vul.json'; exit 1)
	$(PYTHON) scripts/make_manifest.py big-vul --input $(CORPUS) \
		--out $(or $(OUT),datasets/big_vul_manifest.json)

presentation:
	$(PYTHON) scripts/make_presentation.py

# Results are the record of what was measured, so they are not removed here.
clean:
	rm -rf .pytest_cache __pycache__ */__pycache__ .pytest_cache
