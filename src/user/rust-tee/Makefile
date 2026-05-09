# rust-tee — twenty-ninth user-space Rust program for Futura.

PLATFORM ?= x86_64

ROOT := ../../..
BUILD_ROOT := $(ROOT)/build
OBJ_DIR := $(BUILD_ROOT)/obj/$(PLATFORM)/user/rust-tee
BIN_DIR := $(BUILD_ROOT)/bin/$(PLATFORM)/user

ifeq ($(PLATFORM),arm64)
    ifeq ($(shell uname -s),Darwin)
        CROSS_COMPILE ?= /opt/homebrew/bin/aarch64-elf-
    else
        CROSS_COMPILE ?= aarch64-linux-gnu-
    endif
    CC := $(CROSS_COMPILE)gcc
    AR := $(CROSS_COMPILE)ar
    OBJCOPY := $(CROSS_COMPILE)objcopy
    ARCH_CFLAGS := -march=armv8-a -mtune=cortex-a53 -mno-outline-atomics
    RUST_TARGET := aarch64-unknown-linux-gnu
else
    CC := gcc
    AR := ar
    OBJCOPY := objcopy
    ARCH_CFLAGS := -m64
    RUST_TARGET := x86_64-unknown-linux-gnu
endif

CARGO ?= cargo
RUSTC ?= rustc

LDSCRIPT  := ../libfutura/userland_$(PLATFORM).ld
CRT0      := $(BUILD_ROOT)/lib/$(PLATFORM)/crt0.o
LIBFUTURA := $(BUILD_ROOT)/lib/$(PLATFORM)/libfutura.a

ifeq ($(PLATFORM),arm64)
LIBGCC := $(shell $(CC) -print-libgcc-file-name)
else
LIBGCC :=
endif

RUST_BUILD_DIR := target/$(RUST_TARGET)/release
RUST_LIB       := $(RUST_BUILD_DIR)/librust_tee.a

TARGET := $(BIN_DIR)/rust-tee

LDFLAGS := -nostdlib -static -T $(LDSCRIPT)
LDLIBS  := $(RUST_LIB) $(LIBFUTURA) $(LIBGCC)

.PHONY: all clean cargo-build

all: $(TARGET)

cargo-build:
	@echo "CARGO rust-tee ($(RUST_TARGET))"
	@RUSTFLAGS="-C panic=abort -C force-unwind-tables=no" \
		$(CARGO) build --release --target $(RUST_TARGET)
	@tmpdir=$$(mktemp -d); cd $$tmpdir && \
		$(AR) x $(abspath $(RUST_LIB)) && \
		for o in *.o; do \
			$(OBJCOPY) --remove-section='.gcc_except_table*' --remove-section='.eh_frame*' --remove-section='.data.DW.ref.*' $$o >/dev/null 2>&1 || true; \
		done && \
		$(AR) rcs $(abspath $(RUST_LIB)) *.o; \
		rm -rf $$tmpdir

$(RUST_LIB): cargo-build

$(TARGET): $(RUST_LIB) | $(BIN_DIR) $(CRT0) $(LIBFUTURA)
	@echo "LD $@"
	@$(CC) $(LDFLAGS) $(CRT0) $(LDLIBS) -o $@

$(BIN_DIR):
	@mkdir -p $@

$(LIBFUTURA):
	@$(MAKE) -C ../libfutura PLATFORM=$(PLATFORM) all

clean:
	@rm -rf $(OBJ_DIR) $(TARGET) target
