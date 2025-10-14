#include <stdint.h>

#include <user/stdio.h>
#include <user/sys.h>

void __assert_fail(const char *expr, const char *file,
                   unsigned int line, const char *func) {
    printf("[ASSERT] %s:%u %s: %s\n",
           file ? file : "<unknown>",
           line,
           func ? func : "<func>",
           expr ? expr : "<expr>");
    sys_exit(-1);
    for (;;) {
        /* unreachable */
    }
}
