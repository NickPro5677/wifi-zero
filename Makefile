.PHONY: run test lint check stop backup report

run:
	bash start_all.sh

test:
	python3 -m unittest discover -s tests -v

lint:
	@python3 -c "import ast,glob,sys; \
	bad=[]; \
	[bad.append(f) for f in glob.glob('**/*.py', recursive=True) \
		if (lambda p:(open(p).read(), ast.parse(open(p).read()))[0] or True)(f) is None]"
	@echo "lint: (syntax check) OK"

check:
	bash checks.sh

stop:
	bash stop_all.sh

backup:
	bash scripts/backup.sh

report:
	python3 -m core.report
