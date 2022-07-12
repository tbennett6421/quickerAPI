# The following recipes are not based on files
.PHONY: all build clean tests

# make all
all: env resources

# create venv
env:
	@echo "[*] Creating venv..."
	python3 -m venv env
	env/bin/pip install --upgrade pip
	env/bin/pip install -r requirements.txt

resources: generate

resources/top-1m-alexa.csv: generate

# requirements:
# 	poetry export -f requirements.txt -o requirements.txt
# 	poetry export --dev -f requirements.txt -o requirements-dev.txt

generate:
	@echo "[*] fetching resources..."
	chmod +x generate_resources_and_cache.sh
	$(shell ./generate_resources_and_cache.sh)

clean:
	@echo "[*] Cleaning up..."
	rm -f -r build/
	rm -f -r bin/
	rm -f -r dist/
	rm -f -r env/
	rm -f -r *.egg-info
	find . -name '*.pyc' -exec rm -f {} +
	find . -name '*.pyo' -exec rm -f {} +
	find . -name '__pycache__' -exec rm -rf {} +
	find . -name '.pytest_cache' -exec rm -rf {} +

#flake8 . --count --select=E9,F63,F7,F82 --show-source --statistics
tests:
	@echo "[*] Running tests..."
	env/bin/python -m pytest
