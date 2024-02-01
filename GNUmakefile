# SPDX-License-Identifier: LGPL-2.0-or-later

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

.PHONY: all
all: sequoia.so

libsequoia_a = capi/target/${PROFILE}/libsequoia.a
$(libsequoia_a):
	cd capi && cargo build ${CARGO_ARGS}

export CGO_LDFLAGS = -L$(abs_srcdir)/capi/target/${PROFILE} -lsequoia $(shell pkg-config --libs openssl) -lm
export CGO_CFLAGS = -I$(abs_srcdir)/capi/include $(shell pkg-config --cflags openssl)

sequoia.so: sequoia.go GNUmakefile $(libsequoia_a)
	@echo "CGO_LDFLAGS: $$CGO_LDFLAGS"
	@echo "CGO_CFLAGS: $$CGO_CFLAGS"
	go build --buildmode=plugin sequoia.go

.PHONY: all
clean:
	cd capi && cargo clean
	rm -f sequoia.so
