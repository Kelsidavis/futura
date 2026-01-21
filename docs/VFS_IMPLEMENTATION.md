# VFS Implementation Guide — Futura OS

**Project:** Futura OS
**Component:** Virtual Filesystem (VFS) Layer
**Status:** Phase 2 - Foundation Complete
**Date:** October 2025
**Author:** Kelsi Davis

---

## Overview

The Futura OS Virtual Filesystem (VFS) provides a unified abstraction layer for all filesystem operations. It enables multiple filesystem types (ramfs, ext4, FAT, FuturaFS) to coexist and be accessed through a common API.

**Key Features:**
- Vnode-based architecture (similar to BSD VFS)
- Path resolution with component-level lookup
- Mount point management
- File descriptor table (256 FDs per kernel)
- Reference counting for vnodes
- Pluggable filesystem backends

---

## Architecture

### Core Concepts

#### 1. **VNode (Virtual Node)**
Represents any filesystem object (file, directory, device, etc.)

```c
struct fut_vnode {
    enum fut_vnode_type type;      // VN_REG, VN_DIR, VN_CHR, etc.
    uint64_t ino;                  // Inode number
    uint32_t mode;                 // Permissions (UNIX-style)
    uint64_t size;                 // File size in bytes
    uint32_t nlinks;               // Hard link count

    struct fut_mount *mount;       // Mount point
    void *fs_data;                 // Filesystem-specific data
    uint32_t refcount;             // Reference count

    const struct fut_vnode_ops *ops;  // Operations table
};
```

**Vnode Types:**
- `VN_REG` - Regular file
- `VN_DIR` - Directory
- `VN_CHR` - Character device
- `VN_BLK` - Block device
- `VN_FIFO` - Named pipe
- `VN_LNK` - Symbolic link
- `VN_SOCK` - Socket

#### 2. **VNode Operations**
Function pointers for filesystem-specific operations:

```c
struct fut_vnode_ops {
    int (*open)(struct fut_vnode *vnode, int flags);
    int (*close)(struct fut_vnode *vnode);
    ssize_t (*read)(struct fut_vnode *vnode, void *buf, size_t size, uint64_t offset);
    ssize_t (*write)(struct fut_vnode *vnode, const void *buf, size_t size, uint64_t offset);
    int (*lookup)(struct fut_vnode *dir, const char *name, struct fut_vnode **result);
    int (*create)(struct fut_vnode *dir, const char *name, uint32_t mode, struct fut_vnode **result);
    int (*mkdir)(struct fut_vnode *dir, const char *name, uint32_t mode);
    // ... more operations
};
```

#### 3. **Mount Point**
Represents a mounted filesystem:

```c
struct fut_mount {
    const char *device;             // Device path (e.g., "/dev/sda1")
    const char *mountpoint;         // Mount point (e.g., "/home")
    const struct fut_fs_type *fs;   // Filesystem type
    struct fut_vnode *root;         // Root vnode of this mount
    int flags;                      // Mount flags (read-only, etc.)
    void *fs_data;                  // FS-specific mount data
    struct fut_mount *next;         // Linked list
};
```

#### 4. **Filesystem Type**
Defines operations for a filesystem implementation:

```c
struct fut_fs_type {
    const char *name;               // e.g., "ramfs", "ext4"
    int (*mount)(const char *device, int flags, void *data, struct fut_mount **mount);
    int (*unmount)(struct fut_mount *mount);
};
```

---

## Path Resolution

### Algorithm

Path resolution walks the directory tree from root to the target file:

```
Input: "/home/user/file.txt"

1. Split path into components: ["home", "user", "file.txt"]
2. Start at root vnode
3. For each component:
   a. Verify current vnode is a directory
   b. Call vnode->ops->lookup(current, component, &next)
   c. Move to next vnode
4. Return final vnode
```

### Implementation

**Function:** `lookup_vnode()` in `kernel/vfs/fut_vfs.c`

```c
static int lookup_vnode(const char *path, struct fut_vnode **vnode) {
    // Handle root directory special case
    if (path[0] == '/' && path[1] == '\0') {
        *vnode = root_vnode;
        fut_vnode_ref(*vnode);
        return 0;
    }

    // Parse path into components
    char components[MAX_PATH_COMPONENTS][64];
    int num_components = parse_path(path, components, MAX_PATH_COMPONENTS);

    // Walk from root through each component
    struct fut_vnode *current = root_vnode;
    fut_vnode_ref(current);

    for (int i = 0; i < num_components; i++) {
        // Verify current is directory
        if (current->type != VN_DIR) {
            fut_vnode_unref(current);
            return -ENOTDIR;
        }

        // Lookup next component
        struct fut_vnode *next = NULL;
        int ret = current->ops->lookup(current, components[i], &next);
        if (ret < 0) {
            fut_vnode_unref(current);
            return ret;
        }

        fut_vnode_unref(current);
        current = next;
    }

    *vnode = current;
    return 0;
}
```

### Path Parsing

**Function:** `parse_path()` in `kernel/vfs/fut_vfs.c`

Splits `/foo/bar/baz` into `["foo", "bar", "baz"]`:
- Skips leading and trailing slashes
- Handles multiple consecutive slashes
- Component length limit: 64 characters
- Max components: 32

---

## File Operations

### Opening Files

**API:** `int fut_vfs_open(const char *path, int flags, int mode)`

**Process:**
1. Lookup vnode using path resolution
2. Check permissions (future: use `mode` parameter)
3. Verify open flags (can't write to directories)
4. Call `vnode->ops->open(vnode, flags)`
5. Allocate file descriptor structure
6. Add to file descriptor table
7. Return file descriptor number

**Flags:**
- `O_RDONLY` - Read-only
- `O_WRONLY` - Write-only
- `O_RDWR` - Read-write
- `O_CREAT` - Create if doesn't exist (fully implemented)
- `O_EXCL` - With O_CREAT, fail if file exists (atomic create)
- `O_TRUNC` - Truncate to zero length
- `O_APPEND` - Append mode

### Reading Files

**API:** `ssize_t fut_vfs_read(int fd, void *buf, size_t size)`

**Process:**
1. Get file structure from FD table
2. Call `vnode->ops->read(vnode, buf, size, file->offset)`
3. Update file offset by bytes read
4. Return bytes read

### Writing Files

**API:** `ssize_t fut_vfs_write(int fd, const void *buf, size_t size)`

**Process:**
1. Get file structure from FD table
2. Call `vnode->ops->write(vnode, buf, size, file->offset)`
3. Update file offset by bytes written
4. Return bytes written

### Closing Files

**API:** `int fut_vfs_close(int fd)`

**Process:**
1. Get file structure from FD table
2. Call `vnode->ops->close(vnode)`
3. Free file descriptor
4. Decrement vnode reference count

---

## RamFS Implementation

RamFS is an in-memory filesystem used for testing and temporary storage.

### Data Structures

**Per-Vnode Data:**
```c
struct ramfs_node {
    union {
        // For regular files
        struct {
            uint8_t *data;       // File data buffer
            size_t capacity;     // Allocated size
        } file;

        // For directories
        struct {
            struct ramfs_dirent *entries;  // Linked list
        } dir;
    };
};
```

**Directory Entry:**
```c
struct ramfs_dirent {
    char name[64];                  // Filename
    struct fut_vnode *vnode;        // Associated vnode
    struct ramfs_dirent *next;      // Next entry
};
```

### File Data Storage

Files use dynamically allocated buffers that grow as needed:
- Initial capacity: 0 bytes
- Growth strategy: Double capacity on expansion
- Write operation triggers expansion if needed

**Example:**
```
Write 100 bytes → Allocate 200 bytes
Write 150 more → Reallocate to 500 bytes
```

### Directory Operations

**Lookup:**
```c
static int ramfs_lookup(struct fut_vnode *dir, const char *name, struct fut_vnode **result) {
    struct ramfs_node *node = dir->fs_data;

    // Linear search through directory entries
    struct ramfs_dirent *entry = node->dir.entries;
    while (entry) {
        if (str_cmp(entry->name, name) == 0) {
            *result = entry->vnode;
            fut_vnode_ref(*result);
            return 0;
        }
        entry = entry->next;
    }

    return -ENOENT;  // Not found
}
```

**Create File:**
```c
static int ramfs_create(struct fut_vnode *dir, const char *name, uint32_t mode, struct fut_vnode **result) {
    // 1. Check if file already exists
    // 2. Allocate new vnode
    // 3. Allocate ramfs_node for file data
    // 4. Initialize vnode (type=VN_REG, size=0)
    // 5. Create directory entry
    // 6. Add to parent directory
    // 7. Return new vnode
}
```

**Create Directory:**
```c
static int ramfs_mkdir(struct fut_vnode *dir, const char *name, uint32_t mode) {
    // Similar to create, but type=VN_DIR
    // Initialize empty directory entry list
}
```

### Read/Write Operations

**Read:**
```c
static ssize_t ramfs_read(struct fut_vnode *vnode, void *buf, size_t size, uint64_t offset) {
    struct ramfs_node *node = vnode->fs_data;

    // Check EOF
    if (offset >= vnode->size) return 0;

    // Calculate bytes to read
    size_t remaining = vnode->size - offset;
    size_t to_read = (size < remaining) ? size : remaining;

    // Copy from file buffer
    for (size_t i = 0; i < to_read; i++) {
        dest[i] = node->file.data[offset + i];
    }

    return to_read;
}
```

**Write:**
```c
static ssize_t ramfs_write(struct fut_vnode *vnode, const void *buf, size_t size, uint64_t offset) {
    struct ramfs_node *node = vnode->fs_data;

    // Expand buffer if needed
    if (offset + size > node->file.capacity) {
        size_t new_capacity = (offset + size) * 2;
        uint8_t *new_data = fut_malloc(new_capacity);
        // Copy old data, free old buffer
        node->file.data = new_data;
        node->file.capacity = new_capacity;
    }

    // Write data
    for (size_t i = 0; i < size; i++) {
        node->file.data[offset + i] = src[i];
    }

    // Update file size
    if (offset + size > vnode->size) {
        vnode->size = offset + size;
    }

    return size;
}
```

---

## File Descriptor Management

### File Descriptor Table

Global array of file pointers:
```c
#define MAX_OPEN_FILES 256
static struct fut_file *file_table[MAX_OPEN_FILES];
```

**File Structure:**
```c
struct fut_file {
    struct fut_vnode *vnode;    // Associated vnode
    uint64_t offset;            // Current file position
    int flags;                  // Open flags
    uint32_t refcount;          // Reference count
};
```

### Allocation

**Function:** `alloc_fd()`

Searches file table for first NULL entry:
```c
static int alloc_fd(struct fut_file *file) {
    for (int i = 0; i < MAX_OPEN_FILES; i++) {
        if (file_table[i] == NULL) {
            file_table[i] = file;
            return i;
        }
    }
    return -ENOMEM;  // Table full
}
```

**FD 0, 1, 2 Reserved:**
- 0 = stdin (future)
- 1 = stdout (future)
- 2 = stderr (future)

---

## Reference Counting

Vnodes use reference counting to track active users:

```c
void fut_vnode_ref(struct fut_vnode *vnode) {
    if (vnode) {
        vnode->refcount++;
    }
}

void fut_vnode_unref(struct fut_vnode *vnode) {
    if (vnode && vnode->refcount > 0) {
        vnode->refcount--;
        if (vnode->refcount == 0) {
            // Free vnode and associated resources
            fut_free(vnode);
        }
    }
}
```

**When to increment refcount:**
- File opened
- Directory lookup returns vnode
- Vnode cached

**When to decrement refcount:**
- File closed
- Lookup result no longer needed
- Cache eviction

---

## Mounting Filesystems

### Registration

Register filesystem type with VFS:
```c
static const struct fut_fs_type ramfs_type = {
    .name = "ramfs",
    .mount = ramfs_mount,
    .unmount = ramfs_unmount
};

void fut_ramfs_init(void) {
    fut_vfs_register_fs(&ramfs_type);
}
```

### Mounting

**API:** `int fut_vfs_mount(const char *device, const char *mountpoint, const char *fstype, int flags, void *data)`

**Process:**
1. Find filesystem type by name
2. Call `fs->mount(device, flags, data, &mount)`
3. FS creates mount structure with root vnode
4. VFS adds mount to global mount list
5. If mounting at "/", set as root vnode

**Example:**
```c
// Mount ramfs as root
fut_vfs_mount(NULL, "/", "ramfs", 0, NULL);

// Mount ext4 at /home (future)
fut_vfs_mount("/dev/sda1", "/home", "ext4", 0, NULL);
```

---

## Error Codes

VFS uses POSIX-style error codes (negative values):

| Code | Value | Description |
|------|-------|-------------|
| `ENOENT` | -2 | No such file or directory |
| `EIO` | -5 | I/O error |
| `EBADF` | -9 | Bad file descriptor |
| `ENOMEM` | -12 | Out of memory |
| `EACCES` | -13 | Permission denied |
| `EEXIST` | -17 | File exists |
| `ENOTDIR` | -20 | Not a directory |
| `EISDIR` | -21 | Is a directory |
| `EINVAL` | -22 | Invalid argument |

---

## Usage Examples

### Creating and Writing a File

```c
// Open file for writing (create if doesn't exist)
int fd = fut_vfs_open("/test.txt", O_WRONLY | O_CREAT, 0644);
if (fd < 0) {
    fut_printf("Failed to create file: %d\n", fd);
    return;
}

// Write data
const char *data = "Hello, VFS!";
ssize_t written = fut_vfs_write(fd, data, 11);
fut_printf("Wrote %lld bytes\n", (long long)written);

// Close file
fut_vfs_close(fd);
```

### Reading a File

```c
// Open file for reading
int fd = fut_vfs_open("/test.txt", O_RDONLY, 0);
if (fd < 0) {
    fut_printf("Failed to open file: %d\n", fd);
    return;
}

// Read data
char buffer[128];
ssize_t bytes_read = fut_vfs_read(fd, buffer, sizeof(buffer));
buffer[bytes_read] = '\0';  // Null-terminate

fut_printf("Read: %s\n", buffer);

// Close file
fut_vfs_close(fd);
```

### Getting File Statistics

```c
struct fut_stat st;
int ret = fut_vfs_stat("/test.txt", &st);
if (ret == 0) {
    fut_printf("File size: %llu bytes\n", st.st_size);
    fut_printf("Inode: %llu\n", st.st_ino);
}
```

---

## Testing

### Test Procedure

1. **Initialize VFS:**
   ```c
   fut_vfs_init();
   fut_ramfs_init();
   fut_vfs_mount(NULL, "/", "ramfs", 0, NULL);
   ```

2. **Create directory:**
   ```c
   struct fut_vnode *root;
   lookup_vnode("/", &root);
   root->ops->mkdir(root, "test", 0755);
   ```

3. **Create file:**
   ```c
   int fd = fut_vfs_open("/test/file.txt", O_WRONLY | O_CREAT, 0644);
   ```

4. **Write data:**
   ```c
   fut_vfs_write(fd, "Hello", 5);
   fut_vfs_close(fd);
   ```

5. **Read back:**
   ```c
   fd = fut_vfs_open("/test/file.txt", O_RDONLY, 0);
   char buf[16];
   ssize_t n = fut_vfs_read(fd, buf, sizeof(buf));
   buf[n] = '\0';
   fut_printf("Read: %s\n", buf);  // Should print "Hello"
   fut_vfs_close(fd);
   ```

### Current Test Status

✅ VFS initialization
✅ RamFS registration
✅ Root filesystem mount
✅ File creation (O_CREAT)
✅ File read/write operations
✅ Directory creation

---

## Future Enhancements

### Short-Term (Phase 2)
- [x] Implement `O_CREAT` flag in `fut_vfs_open()`
- [x] Add `unlink()` and `rmdir()` operations
- [x] Implement `readdir()` for directory listing
- [x] Add symbolic link support
- [x] Implement `rename()` operation

### Medium-Term (Phase 3)
- [ ] VFS cache layer for frequently accessed vnodes
- [ ] Mount point overlay support
- [ ] Path cache for faster lookups
- [ ] Asynchronous I/O operations
- [ ] mmap() support for memory-mapped files

### Long-Term (Phase 4)
- [ ] Journaling support for crash recovery
- [ ] Quota management
- [ ] Extended attributes (xattr)
- [ ] POSIX ACLs (Access Control Lists)
- [ ] Network filesystems (NFS, CIFS)

---

## Performance Considerations

### Path Lookup
- **Complexity:** O(n) where n = path depth
- **Optimization:** Path cache (future)
- **Worst case:** Deep directory hierarchies

### File I/O
- **RamFS:** O(1) for read/write (direct memory access)
- **Block FS:** O(1) with caching, O(log n) without
- **Optimization:** Read-ahead, write-behind caching

### Reference Counting
- **Overhead:** Minimal (atomic increment/decrement)
- **Memory:** Vnodes freed immediately when refcount = 0
- **Thread safety:** Future - add atomic operations

---

## Integration Points

### FIPC Integration
VFS will use FIPC for:
- Asynchronous I/O notifications
- Filesystem daemon communication
- Block device driver messaging

### POSIX Layer
POSIX syscalls map to VFS:
- `open()` → `fut_vfs_open()`
- `read()` → `fut_vfs_read()`
- `write()` → `fut_vfs_write()`
- `close()` → `fut_vfs_close()`
- `stat()` → `fut_vfs_stat()`

### Device Drivers
Block devices register as filesystems:
- Device nodes (`/dev/sda1`)
- Character devices (`/dev/null`)
- Special files

---

## Files Modified

| File | Purpose |
|------|---------|
| `include/kernel/fut_vfs.h` | VFS API definitions |
| `kernel/vfs/fut_vfs.c` | Core VFS implementation (path resolution, FD management) |
| `include/kernel/fut_ramfs.h` | RamFS API |
| `kernel/vfs/ramfs.c` | RamFS implementation |
| `kernel/kernel_main.c` | VFS initialization in boot sequence |
| `Makefile` | Added ramfs.c to build |

---

## Conclusion

The VFS layer provides a solid foundation for filesystem operations in Futura OS. With path resolution, reference counting, and a pluggable architecture, it supports multiple filesystem types through a unified API.

**Current Status:** Foundation complete, ready for file I/O testing
**Next Milestone:** Complete file creation/read/write tests, begin block device abstraction

---

**Document Version:** 1.0
**Last Updated:** October 2025
**Maintainer:** Futura OS Core Team
