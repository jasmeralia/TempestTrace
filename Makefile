PYTHON ?= python3

.PHONY: deps lint lintfix test screenshots

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
	$(PYTHON) -m pytest tests/ --cov=src/tempesttrace --cov=scripts --cov-report=term-missing --cov-report=xml:coverage.xml --junitxml=junit.xml

screenshots: deps
	QT_QPA_PLATFORM=offscreen $(PYTHON) tools/screenshots/generate_readme_screenshots.py
