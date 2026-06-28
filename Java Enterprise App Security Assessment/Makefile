.PHONY: test coverage format lint scan

test:
	pytest tests/

coverage:
	pytest tests/ --cov=java_security_assessment --cov-report=html

format:
	black java_security_assessment/ tests/

lint:
	flake8 java_security_assessment/ tests/
	mypy java_security_assessment/

scan:
	python -m java_security_assessment.cli --config config/config.yaml
