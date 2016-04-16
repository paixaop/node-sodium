MOCHA_OPTS= --check-leaks
REPORTER = tap
BINDIR = ./node_modules/.bin

LIBSODIUM_DIR = ./deps/libsodium
INSTALL_DIR = $(CURDIR)/deps/build
STATIC_LIB = ${INSTALL_DIR}/lib/libsodium

PLATFORM = ''
THIS_OS = ''

ifeq ($(OS),Windows_NT)
    CCFLAGS += -D WIN32
	THIS_OS = Windows
    ifeq ($(PROCESSOR_ARCHITECTURE),AMD64)
        CCFLAGS += -D AMD64
		PLATFORM = x86_64
    endif
    ifeq ($(PROCESSOR_ARCHITECTURE),x86)
        CCFLAGS += -D IA32
		PLATFORM = i386
    endif
else
    UNAME_S := $(shell uname -s)
    ifeq ($(UNAME_S),Linux)
		THIS_OS = Linux
        CCFLAGS += -D LINUX
		CCFLAGS += -fPIC
		
    endif
    ifeq ($(UNAME_S),Darwin)
		THIS_OS = OSX
		OSX_VERSION_MIN = $(shell sw_vers -productVersion ) | awk -F '.' '{print $$1 "." $$2}'
        CFLAGS="-arch x86_64 -mmacosx-version-min=${OSX_VERSION_MIN} -O2 -g -flto"
		LDFLAGS="-arch x86_64 -mmacosx-version-min=${OSX_VERSION_MIN} -flto"
    endif
    UNAME_P := $(shell uname -p)
    ifeq ($(UNAME_P),x86_64)
		PLATFORM = x86_64
        CCFLAGS += -D AMD64
    endif
    ifneq ($(filter %86,$(UNAME_P)),)
        CCFLAGS += -D IA32
		PLATFORM = i386
    endif
    ifneq ($(filter arm%,$(UNAME_P)),)
		PLATFORM = ARM
        CCFLAGS += -D ARM
    endif
endif

ec:
	@echo ${OSX_VERSION_MIN}
	
# If a static libsodium is found then compile against it
# instead of trying to compile from source
libsodium:
ifeq (,$(wildcard ${STATIC_LIB}.*))
	@echo Static libsodium was not found at ${STATIC_LIB} so compiling libsodium from source.
	@cd $(LIBSODIUM_DIR)/ && ./configure  \
		--enable-static --enable-shared --with-pic --prefix="$(INSTALL_DIR)"
	@cd $(LIBSODIUM_DIR)/ && make clean > /dev/null
	@cd $(LIBSODIUM_DIR)/ && make -j3 check
	@cd $(LIBSODIUM_DIR)/ && make -j3 install
else
	@echo Found a compiled lib in ${INSTALL_DIR}. Make sure this library that was compiled for this platform.
	@echo Use make clean to remove the static lib and force recompilation
	@echo Operating System: ${OS} THIS_OS = ${THIS_OS}, Platform = ${PLATFORM}
endif

sodium: libsodium
	$(BINDIR)/node-gyp rebuild

test: test-unit

test-unit:
	@NODE_ENV=test $(BINDIR)/mocha \
		--reporter $(REPORTER) \
		--globals setImmediate,clearImmediate

instrument: clean
	$(BINDIR)/istanbul instrument --output lib-cov --no-compact \
		--variable global.__coverage__ lib


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
	-rm -fr *.o
	-rm -fr ${INSTALL_DIR}

all:
	sodium

.PHONY: test-cov site docs test docclean
