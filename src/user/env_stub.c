/* env_stub.c - Minimal environment stub for standalone ARM64 testing
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 */

void __libc_init_environ(char **envp) {
    /* For now, just ignore the environment */
    (void)envp;
}
