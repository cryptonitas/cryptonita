.PHONY: all test dist upload clean deps clean_test

all:
	@echo "Usage: make deps[-dev]"
	@echo " - deps: install the dependencies for cryptonita"
	@echo " - deps-dev: install the dependencies for run and build cryptonita"
	@echo
	@echo "Usage: make [lib|docs]-test"
	@echo "Run a suite of tests."
	@echo " - lib-test: run the tests in the lib (unit test)."
	@echo " - docs-test: run the tests in the docs."
	@echo
	@echo "Usage: make format[-test]"
	@echo "Format the source code following the PEP 8 style."
	@echo "Use format-test to verify the complaince without touching"
	@echo "the code"
	@echo
	@echo "Usage: make test|dist|upload|clean|deps"
	@echo " - test: run the all the tests"
	@echo " - dist: make a source and a binary distribution (package)"
	@echo " - upload: upload the source and the binary distribution to pypi"
	@echo " - clean: restore the environment"
	@echo " - deps: install the dependencies"
	@exit 1

deps:
	pip install -e .

deps-dev: deps
	pip install -r requirements-dev.txt

lib-test: clean_test
	@byexample @test/minimum.env -- cryptonita/*.py cryptonita/**/*.py
	@make -s clean_test

docs-test: clean_test
	@byexample @test/minimum.env -- README.md docs/*.md docs/**/*.md
	@make -s clean_test

format:
	yapf -vv -i --style=.style.yapf --recursive cryptonita/

format-test:
	yapf -vv --style=.style.yapf --diff --recursive cryptonita/

test: lib-test docs-test

dist:
	rm -Rf dist/ build/ *.egg-info
	python setup.py sdist bdist_wheel
	rm -Rf build/ *.egg-info

upload: dist
	twine upload dist/*.tar.gz dist/*.whl

clean_test:
	@echo


clean: clean_test
	rm -Rf dist/ build/ *.egg-info
	rm -Rf build/ *.egg-info
	find . -name "*.pyc" -delete
	find . -type d -name "__pycache__" -delete
