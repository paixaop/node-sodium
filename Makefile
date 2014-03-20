
MOCHA_OPTS= --check-leaks
REPORTER = tap

test: test-unit

test-unit:
	@NODE_ENV=test ./node_modules/.bin/mocha \
		--reporter $(REPORTER) \
		--globals setImmediate,clearImmediate \

instrument: clean
	istanbul instrument --output lib-cov --no-compact --variable global.__coverage__ lib


test-cov: clean instrument
	@echo Run make test for simple tests with no coverage reports
	@echo Mocha and Istanbul Node.js must be installed globally
	@COVERAGE=1 NODE_ENV=test mocha \
		-R mocha-istanbul \
		$(TESTS)
	@istanbul report
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

sodium:
	# libsodium is now compiled through node-gyp
	#cd libsodium; \
	#./autogen.sh; \
	#./configure;  \
	#make	
	node-gyp rebuild

.PHONY: test-cov site docs test docclean
