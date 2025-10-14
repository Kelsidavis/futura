/* ipc_ids.h - Reserved FIPC channel identifiers
 *
 * SPDX-License-Identifier: MPL-2.0
 *
 * Shared enumeration of user-visible channel IDs. Keep this list compact
 * and synchronized between kernel and userland to avoid hard-coded magic
 * numbers scattered across services.
 */

#pragma once

#include <stdint.h>

/* System metrics live on ID 1; admin control on ID 2 (see fut_fipc_sys.h). */

enum fut_ipc_reserved_id {
    FIPC_CHAN_WINSRV = 16u /* Window server control channel */
};

#define FIPC_CHAN_NAME_WINSRV "winsrv"

