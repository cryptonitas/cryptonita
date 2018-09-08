.PHONY: all test dist upload clean deps clean_test

all:
	@echo "Usage: make test|dist|upload|clean|deps"
	@echo " - test: run the all the tests"
	@echo " - dist: make a source and a binary distribution (package)"
	@echo " - upload: upload the source and the binary distribution to pypi"
	@echo " - clean: restore the environment"
	@echo " - deps: install the dependencies"
	@exit 1

deps:
	pip install -e .
	pip install byexample
	pip install wheel

test: clean_test
	@byexample -l python cryptonita/*.py
	@make -s clean_test

dist:
	rm -Rf dist/ build/ *.egg-info
	python setup.py sdist bdist_wheel --universal
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
