#include <user/sys.h>

/* Weak fallback; abort.c provides the preferred version with diagnostics */
__attribute__((weak))
void __stack_chk_fail(void) {
    sys_exit(-1);
    for (;;) {
    }
}
