# catl — Xahau catalogue toolkit
#   make            build ./catl (TLS auto-detected: needs OpenSSL headers)
#   make TLS=0      build without OpenSSL (ws:// and http:// still work)
#   make test       build and run the test suite
#   make install    install to $(PREFIX)/bin
CXX      ?= g++
CXXFLAGS ?= -O2 -g
PREFIX   ?= /usr/local
override CXXFLAGS += -std=c++20 -Wall -Wextra -pthread

TLS ?= auto
ifeq ($(TLS),auto)
  TLS := $(shell echo 'int main(){return 0;}' | $(CXX) -x c++ -include openssl/ssl.h - -lssl -lcrypto -o /dev/null >/dev/null 2>&1 && echo 1 || echo 0)
endif
ifeq ($(TLS),1)
  override CXXFLAGS += -DCATL_WITH_OPENSSL
  LIBS += -lssl -lcrypto
endif

CORE := sha zlib catl index shamap protocol net ops fetch tui
OBJS := $(CORE:%=build/%.o)
HDRS := $(wildcard src/*.hpp) src/protocol_defs.inc

all: catl

catl: $(OBJS) build/main.o
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LIBS)

catl_tests: $(OBJS) build/test_main.o
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LIBS)

build/%.o: src/%.cpp $(HDRS) | build
	$(CXX) $(CXXFLAGS) -c $< -o $@

build/test_main.o: tests/test_main.cpp tests/vectors.inc $(HDRS) | build
	$(CXX) $(CXXFLAGS) -c $< -o $@

build:
	mkdir -p build

test: catl_tests
	./catl_tests

install: catl
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 755 catl $(DESTDIR)$(PREFIX)/bin/catl

clean:
	rm -rf build catl catl_tests

.PHONY: all test install clean
