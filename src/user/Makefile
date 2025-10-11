# Makefile for Futura OS Userland
# Copyright (c) 2025 Kelsi Davis
# Licensed under MPL v2.0

# Subdirectories
USERLAND_DIRS := init fsd posixd futurawayd

# Build targets
.PHONY: all clean $(USERLAND_DIRS)

all: $(USERLAND_DIRS)

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
	@echo "  clean         - Clean all build artifacts"
	@echo "  help          - Show this help message"
