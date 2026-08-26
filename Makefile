PYTHON ?= python3

.PHONY: install test doctor phase1 phase2 phase3 clean

install:
	$(PYTHON) -m pip install -r requirements.txt
	$(PYTHON) -m pip install -r requirements-dev.txt

test:
	pytest -q

doctor:
	$(PYTHON) scripts/doctor.py

phase1:
	@test -n "$(FILE)" || (echo 'Usage: make phase1 FILE=examples/cpp/vulnerable.cpp'; exit 1)
	$(PYTHON) run_pipeline.py phase1 $(FILE) --out results/phase1.json

phase2:
	@test -n "$(REPORT)" || (echo 'Usage: make phase2 REPORT=results/phase1.json'; exit 1)
	$(PYTHON) run_phase2.py $(REPORT) --out results/phase2.json

phase3:
	@test -n "$(MANIFEST)" || (echo 'Usage: make phase3 MANIFEST=datasets/manifest.json'; exit 1)
	$(PYTHON) run_phase3.py $(MANIFEST) --mode phase1 --out results/evaluation.json

clean:
	rm -rf .pytest_cache __pycache__ */__pycache__ results/*.json results/*.csv
