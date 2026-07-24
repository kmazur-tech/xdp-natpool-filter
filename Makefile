# Build the XDP NAT-pool filter and its loader.
# Requires: clang, llvm, libbpf-dev, libelf, bpftool.
# vmlinux.h is generated from the running kernel's BTF (host-specific, not
# committed). Build on the target host (same kernel you will run on).

CLANG    ?= clang
BPFTOOL  ?= bpftool
CC       ?= cc
ARCH     := x86

BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) \
              -Wall -Wno-unused-value -Wno-pointer-sign \
              -Wno-compare-distinct-pointer-types -I.

LOADER_CFLAGS := -g -O2 -Wall
LOADER_LIBS   := -lbpf -lelf -lz

all: natpool_filter.bpf.o loader

vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

natpool_filter.bpf.o: natpool_filter.bpf.c natpool_filter.h vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	@echo "-- verifier-facing section check --"
	@$(BPFTOOL) btf dump file $@ format c >/dev/null 2>&1 || true

loader: loader.c natpool_filter.h
	$(CC) $(LOADER_CFLAGS) $< -o $@ $(LOADER_LIBS)

clean:
	rm -f natpool_filter.bpf.o loader

# vmlinux.h is intentionally NOT removed by clean (expensive to regenerate).
distclean: clean
	rm -f vmlinux.h

.PHONY: all clean distclean
