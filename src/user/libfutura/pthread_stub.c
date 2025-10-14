#include <stddef.h>

int pthread_once(void *once_control, void (*init_routine)(void)) {
    (void)once_control;
    if (init_routine) {
        init_routine();
    }
    return 0;
}
