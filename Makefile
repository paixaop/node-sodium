
MOCHA_OPTS= --check-leaks
REPORTER = tap

test: test-unit

test-unit:
	@NODE_ENV=test ./node_modules/.bin/mocha \
		--reporter $(REPORTER) \
		--globals setImmediate,clearImmediate \

.PHONY: test test-unit
