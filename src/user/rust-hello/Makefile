# rust-hello — first user-space Rust program for Futura.
#
# cargo build produces librust_hello.a; we then link it with the
# C crt0 + libfutura.a using the same linker script the C apps use.
# This proves the user-space Rust toolchain is wired up before any
# follow-up Rust apps (file picker, settings panel, …) are added.

PLATFORM ?= x86_64

ROOT := ../../..
BUILD_ROOT := $(ROOT)/build
OBJ_DIR := $(BUILD_ROOT)/obj/$(PLATFORM)/user/rust-hello
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

# Cargo writes the staticlib into target/<triple>/release/.
RUST_BUILD_DIR := target/$(RUST_TARGET)/release
RUST_LIB       := $(RUST_BUILD_DIR)/librust_hello.a

TARGET := $(BIN_DIR)/rust-hello

LDFLAGS := -nostdlib -static -T $(LDSCRIPT)
LDLIBS  := $(RUST_LIB) $(LIBFUTURA) $(LIBGCC)

.PHONY: all clean cargo-build

all: $(TARGET)

# cargo build is .PHONY; let cargo handle its own incremental tracking.
cargo-build:
	@echo "CARGO rust-hello ($(RUST_TARGET))"
	@RUSTFLAGS="-C panic=abort -C force-unwind-tables=no" \
		$(CARGO) build --release --target $(RUST_TARGET)
	@# Strip exception/unwind sections that creep in via libcore so the
	@# linker doesn't pull GNU EH machinery into the freestanding binary.
	@tmpdir=$$(mktemp -d); cd $$tmpdir && \
		$(AR) x $(abspath $(RUST_LIB)) && \
		for o in *.o; do \
			$(OBJCOPY) --remove-section='.gcc_except_table*' --remove-section='.eh_frame*' $$o >/dev/null 2>&1 || true; \
		done && \
		$(AR) rcs $(abspath $(RUST_LIB)) *.o; \
		rm -rf $$tmpdir

$(RUST_LIB): cargo-build

$(TARGET): $(RUST_LIB) | $(BIN_DIR) $(CRT0) $(LIBFUTURA)
	@echo "LD $@"
	@$(CC) $(LDFLAGS) $(CRT0) $(LDLIBS) -o $@

$(BIN_DIR):
	@mkdir -p $@

$(CRT0):
	@$(MAKE) -C ../libfutura PLATFORM=$(PLATFORM) all

$(LIBFUTURA):
	@$(MAKE) -C ../libfutura PLATFORM=$(PLATFORM) all

clean:
	@rm -rf $(OBJ_DIR) $(TARGET) target
