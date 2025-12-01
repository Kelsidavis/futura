# Makefile for Futura OS Userland
# Copyright (c) 2025 Kelsi Davis
# Licensed under MPL v2.0

# Platform selection (inherited from parent Makefile)
PLATFORM ?= x86_64
export PLATFORM

# Subdirectories - conditionally exclude Wayland programs on macOS
ifeq ($(shell uname -s),Darwin)
# On macOS, only build non-Wayland programs (init requires no Wayland deps)
USERLAND_DIRS := libfutura init stubs
else
# On Linux, build everything
USERLAND_DIRS := libfutura init shell cat echo wc fsd posixd futurawayd fbtest stubs services/winsrv apps/winstub clients/wl-simple clients/wl-colorwheel clients/wl-term
endif

# Build targets
.PHONY: all clean $(USERLAND_DIRS)

# Build libfutura first, then services
all: libfutura $(USERLAND_DIRS)

# Ensure services depend on libfutura
ifeq ($(shell uname -s),Darwin)
init stubs: libfutura
else
init shell cat echo wc fsd posixd futurawayd fbtest services/winsrv apps/winstub clients/wl-simple clients/wl-colorwheel clients/wl-term: libfutura
endif

$(USERLAND_DIRS):
	@echo "Building $@ for $(PLATFORM)..."
	@$(MAKE) -C $@ all PLATFORM=$(PLATFORM)

clean:
	@for dir in $(USERLAND_DIRS); do \
		echo "Cleaning $$dir..."; \
		$(MAKE) -C $$dir clean; \
	done

# Help
help:
	@echo "Futura OS Userland Build System"
	@echo ""
	@echo "Targets:"
	@echo "  all           - Build all userland services"
	@echo "  init          - Build init system"
	@echo "  fsd           - Build filesystem daemon"
	@echo "  posixd        - Build POSIX daemon"
	@echo "  futurawayd    - Build FuturaWay compositor"
	@echo "  services/winsrv - Build window server"
	@echo "  apps/winstub  - Build window protocol stub client"
	@echo "  clean         - Clean all build artifacts"
	@echo "  help          - Show this help message"
