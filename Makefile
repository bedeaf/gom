CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra -Werror -D_FORTIFY_SOURCE=3 -fstack-protector-strong -fPIE
LDFLAGS ?= -pie -Wl,-z,relro,-z,now

all: build/gom-lock build/attack

build/syscalls.h: src/denied-syscalls.txt src/gen-syscalls.sh | build
	bash src/gen-syscalls.sh src/denied-syscalls.txt > $@.tmp && mv $@.tmp $@

build/gom-lock: src/lock.c build/syscalls.h | build
	$(CC) $(CFLAGS) -Ibuild -o $@ src/lock.c $(LDFLAGS)

# Attack simulation: only ever run inside the sandbox (gom --selftest).
build/attack: tests/attack.c | build
	$(CC) -O1 -Wall -Wextra -o $@ tests/attack.c

build:
	mkdir -p build

check: all
	shellcheck bin/gom src/gen-syscalls.sh
	python3 tests/shelf_test.py
	bin/gom --selftest

clean:
	rm -rf build

.PHONY: all check clean
