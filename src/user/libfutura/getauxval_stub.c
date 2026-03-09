/* getauxval stub for freestanding ARM64 userspace.
 * libgcc's LSE atomics init calls __getauxval to detect hardware
 * atomic instructions. Return 0 to disable runtime detection.
 */

unsigned long __getauxval(unsigned long type) {
    (void)type;
    return 0;
}

unsigned long getauxval(unsigned long type) {
    (void)type;
    return 0;
}
