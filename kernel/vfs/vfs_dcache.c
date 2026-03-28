/* kernel/vfs/vfs_dcache.c - VFS dentry cache stub
 *
 * Provides no-op implementations for the dcache API. The full cache
 * implementation is deferred until vnode lifecycle refcounting is
 * robust enough to safely cache vnode pointers.
 */

#include <kernel/fut_vfs.h>
#include <stdint.h>
#include <stddef.h>

uint64_t vfs_dcache_nr_dentry = 0;
uint64_t vfs_dcache_nr_unused = 0;
uint64_t vfs_dcache_hits      = 0;
uint64_t vfs_dcache_misses    = 0;

void vfs_dcache_init(void) { }

struct fut_vnode *vfs_dcache_lookup(const char *path) {
    (void)path;
    vfs_dcache_misses++;
    return NULL;  /* Always miss — no caching */
}

void vfs_dcache_insert(const char *path, struct fut_vnode *vnode) {
    (void)path;
    (void)vnode;
}

void fut_dcache_invalidate_vnode(struct fut_vnode *vnode) {
    (void)vnode;
}

void vfs_dcache_invalidate_path(const char *path) {
    (void)path;
}
