PYTHON ?= python3

.PHONY: help install lint validate test test-samples convert coverage ci clean

help:  ## Show targets
	@grep -E '^[a-z-]+:.*##' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-14s %s\n", $$1, $$2}'

install:  ## Install dependencies
	$(PYTHON) -m pip install -r requirements.txt

lint:  ## Lint Python code with ruff
	$(PYTHON) -m ruff check dac tests

validate:  ## Schema + semantic validation of all rules
	$(PYTHON) -m dac validate

test:  ## Run the pytest suite
	$(PYTHON) -m pytest -v

test-samples:  ## Print per-rule results against sample logs
	$(PYTHON) -m dac test

convert:  ## Convert rules to KQL and SPL under build/
	$(PYTHON) -m dac convert --target all --out build

sentinel:  ## Export Sentinel analytics rules as an ARM template
	$(PYTHON) -m dac sentinel --out build/sentinel/analytics-rules.json

migrate:  ## Example legacy SIEM -> Sentinel migration plan
	$(PYTHON) -m dac migrate --legacy examples/legacy_splunk_searches.csv

coverage:  ## Regenerate docs/COVERAGE.md
	$(PYTHON) -m dac coverage --out docs/COVERAGE.md

ci: lint validate test convert sentinel coverage  ## Everything CI runs

clean:  ## Remove generated files
	rm -rf build .pytest_cache .ruff_cache
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
