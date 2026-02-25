.PHONY: setup_venv generate_datasets sast_analyze test_framework run_metrics dashboard run_stats
setup_venv:
	python3 -m venv .venv && \
	source .venv/bin/activate && \
	pip install --upgrade pip && \
	pip install -r requirements.txt

generate_datasets:
	source .venv/bin/activate && python generate_datasets.py

sast_analyze:
	$(MAKE) -C baselines/sast analyze-datasets

test_framework:
	cd testing-framework && npm run test

run_metrics:
	source .venv/bin/activate && python metrics/dynamic_metrics_runner.py

dashboard:
	@echo "Starting evaluation dashboard..."
	@echo "Dashboard will be available at: http://localhost:8000"
	@python3 -m http.server 8000

