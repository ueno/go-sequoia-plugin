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

PKGS := openssl sqlite3 bzip2
LIBS := $(foreach pkg,$(PKGS),$(shell pkg-config --libs $(pkg)))
CFLAGS := $(foreach pkg,$(PKGS),$(shell pkg-config --cflags $(pkg)))

export CGO_LDFLAGS = -L$(abs_srcdir)/capi/target/${PROFILE} -lsequoia $(LIBS) -lm
export CGO_CFLAGS = -I$(abs_srcdir)/capi/include $(CFLAGS)

sequoia.so: sequoia.go GNUmakefile $(libsequoia_a)
	@echo "CGO_LDFLAGS: $$CGO_LDFLAGS"
	@echo "CGO_CFLAGS: $$CGO_CFLAGS"
	go build --buildmode=plugin sequoia.go

clean::
	cd capi && cargo clean
	rm -f sequoia.so
