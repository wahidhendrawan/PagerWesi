.PHONY: test lint security

test:
	python -m pytest --cov=cloud --cov-report=term-missing

lint:
	python -m ruff check .
	python -m compileall -q cloud tests
	shellcheck linux/harden.sh macos/harden.sh

security:
	python -m pip_audit -r requirements.lock
