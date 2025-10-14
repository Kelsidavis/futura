# Wayland protocol generation helpers
# SPDX-License-Identifier: MPL-2.0
#
# Usage:
#   include $(ROOT)/mk/wayland.mk
#   $(call wayland_proto, path/to/protocol.xml, $(BUILD_DIR)/proto, protocol_name)
#
# The helper creates targets for:
#   - client header:  $(outdir)/$(basename)-client-protocol.h
#   - server header:  $(outdir)/$(basename)-server-protocol.h
#   - shared C stub:  $(outdir)/$(basename)-protocol.c
#
# The macro requires WAYLAND_SCANNER to be set, which happens automatically
# once `make third_party-wayland` has produced build/third_party/wayland/paths.mk.

ifndef WAYLAND_SCANNER
$(warning WAYLAND_SCANNER is not set; run `make third_party-wayland` to build it)
WAYLAND_SCANNER := wayland-scanner
endif

# $(call wayland_proto,<xml>,<outdir>,<basename>)
define wayland_proto
$(eval $(call __wayland_proto,$(1),$(2),$(3)))
endef

define __wayland_proto
$(2):
	@mkdir -p $$@

$(2)/$(3)-client-protocol.h: $(1) | $(2)
	$$(WAYLAND_SCANNER) client-header $$(abspath $(1)) $$@

$(2)/$(3)-server-protocol.h: $(1) | $(2)
	$$(WAYLAND_SCANNER) server-header $$(abspath $(1)) $$@

$(2)/$(3)-protocol.c: $(1) | $(2)
	$$(WAYLAND_SCANNER) public-code $$(abspath $(1)) $$@
endef
