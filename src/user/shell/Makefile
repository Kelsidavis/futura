# SPDX-License-Identifier: MPL-2.0

PLATFORM ?= x86_64

SUBDIRS := futura-shell

.PHONY: all clean

all:
	@for dir in $(SUBDIRS); do $(MAKE) -C $$dir PLATFORM=$(PLATFORM) all || exit 1; done

clean:
	@for dir in $(SUBDIRS); do $(MAKE) -C $$dir clean || exit 1; done
