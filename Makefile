PYTHON ?= python3

.PHONY: deps lint lintfix test

deps:
	$(PYTHON) -m pip install -r requirements-dev.txt

lint:
	$(PYTHON) -m ruff check src/ scripts/ tests/
	$(PYTHON) -m ruff format --check src/ scripts/ tests/
	$(PYTHON) -m mypy src/tempesttrace/ scripts/

lintfix:
	$(PYTHON) -m ruff check --fix src/ scripts/ tests/
	$(PYTHON) -m ruff format src/ scripts/ tests/

test:
	$(PYTHON) -m pytest tests/
