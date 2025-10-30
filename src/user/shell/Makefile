# SPDX-License-Identifier: MPL-2.0

SUBDIRS := futura-shell

.PHONY: all clean

all:
	@for dir in $(SUBDIRS); do $(MAKE) -C $$dir all || exit 1; done

clean:
	@for dir in $(SUBDIRS); do $(MAKE) -C $$dir clean || exit 1; done
