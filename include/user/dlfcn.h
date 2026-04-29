// SPDX-License-Identifier: MPL-2.0
//
// dlfcn.h surface — Futura statically links userland; libwayland calls
// dlsym() to load opt-in extensions but tolerates them being absent.
// Stubs return NULL so the optional path bypasses gracefully.

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#define RTLD_LAZY     0x00001
#define RTLD_NOW      0x00002
#define RTLD_GLOBAL   0x00100
#define RTLD_LOCAL    0x00000
#define RTLD_NODELETE 0x01000
#define RTLD_NOLOAD   0x00004
#define RTLD_DEFAULT  ((void *)0)
#define RTLD_NEXT     ((void *)-1)

void  *dlopen(const char *filename, int flag);
int    dlclose(void *handle);
void  *dlsym(void *handle, const char *symbol);
char  *dlerror(void);

#ifdef __cplusplus
}
#endif
