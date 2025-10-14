#include <user/sys.h>

void __stack_chk_fail(void) {
    sys_exit(-1);
    for (;;) {
    }
}
