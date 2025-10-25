# Makefile for Futura OS Userland
# Copyright (c) 2025 Kelsi Davis
# Licensed under MPL v2.0

# Subdirectories
USERLAND_DIRS := libfutura init shell cat echo wc fsd posixd futurawayd fbtest stubs services/winsrv apps/winstub

# Build targets
.PHONY: all clean $(USERLAND_DIRS)

# Build libfutura first, then services
all: libfutura $(USERLAND_DIRS)

# Ensure services depend on libfutura
init shell cat echo wc fsd posixd futurawayd fbtest services/winsrv apps/winstub: libfutura

$(USERLAND_DIRS):
	@echo "Building $@..."
	@$(MAKE) -C $@ all

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
