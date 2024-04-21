# SPDX-License-Identifier: Apache-2.0

RELEASE ?= 0
srcdir = .
abs_srcdir = $(shell realpath $(srcdir))

ifeq ($(RELEASE),1)
        PROFILE ?= release
        CARGO_ARGS = --release
else
        PROFILE ?= debug
        CARGO_ARGS =
endif

all:: sequoia.so

libsequoia_a = capi/target/${PROFILE}/libsequoia.a
$(libsequoia_a):
	cd capi && cargo build ${CARGO_ARGS}

export CGO_LDFLAGS = -L$(abs_srcdir)/capi/target/${PROFILE} -lsequoia $(shell pkg-config --libs openssl) $(shell pkg-config --libs sqlite3) $(shell pkg-config --libs bzip2) -lm
export CGO_CFLAGS = -I$(abs_srcdir)/capi/include $(shell pkg-config --cflags openssl) $(shell pkg-config --cflags sqlite3) $(shell pkg-config --cflags bzip2)

sequoia.so: sequoia.go GNUmakefile $(libsequoia_a)
	@echo "CGO_LDFLAGS: $$CGO_LDFLAGS"
	@echo "CGO_CFLAGS: $$CGO_CFLAGS"
	go build --buildmode=plugin sequoia.go

clean::
	cd capi && cargo clean
	rm -f sequoia.so
