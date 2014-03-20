MOCHA_OPTS= --check-leaks
REPORTER = tap
BINDIR = ./node_modules/.bin

sodium:
	$(BINDIR)/node-gyp rebuild
	
test: test-unit

test-unit:
	@NODE_ENV=test $(BINDIR)/mocha \
		--reporter $(REPORTER) \
		--globals setImmediate,clearImmediate

instrument: clean
	$(BINDIR)/istanbul instrument --output lib-cov --no-compact --variable global.__coverage__ lib


test-cov: clean instrument
	@echo Run make test for simple tests with no coverage reports
	@COVERAGE=1 NODE_ENV=test $(BINDIR)/mocha \
		-R mocha-istanbul \
		--globals setImmediate,clearImmediate
	@$(BINDIR)/istanbul report
	@rm -rf lib-cov
	@echo
	@echo Open html-report/index.html file in your browser

git-pull:
	git pull
	git submodule init
	git submodule update
	git submodule status

clean:
	-rm -fr lib-cov
	-rm -fr covershot
	-rm -fr html-report
	-rm -fr coverage
	-rm -fr coverage.html

.PHONY: test-cov site docs test docclean
