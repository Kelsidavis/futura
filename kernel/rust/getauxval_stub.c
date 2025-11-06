/* getauxval stub for Rust compiler-builtins */
unsigned long getauxval(unsigned long type) {
    (void)type;
    return 0;  /* Return 0 for all features (disable Rust runtime feature detection) */
}
