// SPDX-License-Identifier: MPL-2.0
//
// DMA-Safe Memory Pool Allocator for x86-64 Device Drivers
//
// Provides pre-allocated, physically contiguous, cache-aligned memory
// regions for device DMA operations. Each pool manages pages divided
// into fixed-size blocks with O(1) alloc/free via a freelist.
//
// Architecture:
//   - Up to 8 independent pools, each with a power-of-2 block size
//   - Pages allocated from the kernel physical page allocator
//   - Virtual-to-physical translation via kernel helper
//   - Freelist-based allocation within each pool
//   - Bounce buffer helpers for non-DMA-safe memory transfers
//
// Block sizes: 16, 32, 64, 128, 256, 512, 1024, 2048, 4096 bytes

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![allow(unexpected_cfgs)]

use core::ffi::c_void;
use core::ptr;

use common::{alloc_page, free_page, log};

// ── FFI imports ──

unsafe extern "C" {
    fn fut_printf(fmt: *const u8, ...);
    fn rust_virt_to_phys(vaddr: *const c_void) -> u64;
}

// ── StaticCell for safe global mutable state ──

struct StaticCell<T>(core::cell::UnsafeCell<T>);
unsafe impl<T> Sync for StaticCell<T> {}

impl<T> StaticCell<T> {
    const fn new(v: T) -> Self {
        Self(core::cell::UnsafeCell::new(v))
    }

    fn get(&self) -> *mut T {
        self.0.get()
    }
}

// ── DMA region descriptor ──

/// Describes a DMA-accessible memory region with both virtual and physical
/// addresses, suitable for passing to hardware device descriptors.
#[repr(C)]
pub struct DmaRegion {
    pub vaddr: *mut u8,
    pub paddr: u64,
    pub size: usize,
}

// ── Constants ──

const PAGE_SIZE: usize = 4096;
const MAX_POOLS: usize = 8;
const MAX_PAGES_PER_POOL: usize = 64;
const MIN_BLOCK_SIZE: u32 = 16;
const MAX_BLOCK_SIZE: u32 = 4096;

// ── Pool internals ──

/// A single page tracked by a pool, storing the virtual address of the
/// page and the number of free blocks remaining within it.
#[derive(Clone, Copy)]
struct PoolPage {
    vaddr: *mut u8,
    paddr: u64,
}

impl PoolPage {
    const fn empty() -> Self {
        Self {
            vaddr: ptr::null_mut(),
            paddr: 0,
        }
    }
}

/// A freelist node embedded at the start of each free block.
/// When a block is free, its first 8 bytes hold the pointer to the
/// next free block (or null if it is the last).
struct FreeNode {
    next: *mut FreeNode,
}

/// A DMA memory pool managing fixed-size blocks across multiple pages.
struct DmaPool {
    active: bool,
    block_size: u32,
    blocks_per_page: u32,
    pages: [PoolPage; MAX_PAGES_PER_POOL],
    page_count: u32,
    freelist: *mut FreeNode,
    total_allocs: u32,
    total_frees: u32,
}

impl DmaPool {
    const fn empty() -> Self {
        Self {
            active: false,
            block_size: 0,
            blocks_per_page: 0,
            pages: [PoolPage::empty(); MAX_PAGES_PER_POOL],
            page_count: 0,
            freelist: ptr::null_mut(),
            total_allocs: 0,
            total_frees: 0,
        }
    }
}

// ── Global pool table ──

static POOLS: StaticCell<[DmaPool; MAX_POOLS]> = StaticCell::new([
    DmaPool::empty(),
    DmaPool::empty(),
    DmaPool::empty(),
    DmaPool::empty(),
    DmaPool::empty(),
    DmaPool::empty(),
    DmaPool::empty(),
    DmaPool::empty(),
]);

// ── Helpers ──

fn virt_to_phys(ptr: *const u8) -> u64 {
    unsafe { rust_virt_to_phys(ptr as *const c_void) }
}

/// Check that a block size is a power of two within the valid range.
fn is_valid_block_size(size: u32) -> bool {
    size >= MIN_BLOCK_SIZE && size <= MAX_BLOCK_SIZE && size.is_power_of_two()
}

/// Initialise freelist for a newly added page within a pool.
/// Each block's first bytes become a FreeNode pointing to the next block.
/// The last block's next pointer is set to the current freelist head,
/// chaining the new page's blocks onto the existing freelist.
fn init_page_freelist(
    page_vaddr: *mut u8,
    block_size: u32,
    blocks_per_page: u32,
    current_head: *mut FreeNode,
) -> *mut FreeNode {
    let bs = block_size as usize;
    // Chain blocks in reverse order so the first block is at the head
    let mut head = current_head;
    let mut i = blocks_per_page as usize;
    while i > 0 {
        i -= 1;
        let block_ptr = unsafe { page_vaddr.add(i * bs) } as *mut FreeNode;
        unsafe {
            ptr::write(block_ptr, FreeNode { next: head });
        }
        head = block_ptr;
    }
    head
}

/// Add a single page to a pool, initialising its freelist blocks.
/// Returns 0 on success, -1 on failure.
fn pool_add_page(pool: &mut DmaPool) -> i32 {
    if pool.page_count as usize >= MAX_PAGES_PER_POOL {
        return -1;
    }

    let page = unsafe { alloc_page() };
    if page.is_null() {
        return -1;
    }

    // Zero the page
    unsafe { ptr::write_bytes(page, 0, PAGE_SIZE); }

    let paddr = virt_to_phys(page);

    let idx = pool.page_count as usize;
    pool.pages[idx] = PoolPage { vaddr: page, paddr };
    pool.page_count += 1;

    // Chain the new page's blocks onto the freelist
    pool.freelist = init_page_freelist(
        page,
        pool.block_size,
        pool.blocks_per_page,
        pool.freelist,
    );

    0
}

/// Check whether an address belongs to a given pool.
fn pool_owns_addr(pool: &DmaPool, vaddr: *const u8) -> bool {
    let addr = vaddr as usize;
    for i in 0..pool.page_count as usize {
        let page_start = pool.pages[i].vaddr as usize;
        if addr >= page_start && addr < page_start + PAGE_SIZE {
            return true;
        }
    }
    false
}

/// Verify that an address is properly aligned for the pool's block size.
fn is_block_aligned(pool: &DmaPool, vaddr: *const u8) -> bool {
    let addr = vaddr as usize;
    (addr & (pool.block_size as usize - 1)) == 0
}

// ── Exported C API ──

/// Create a DMA memory pool with the given block size and initial page count.
///
/// block_size: size of each block in bytes (must be power of 2, 16..=4096)
/// initial_pages: number of pages to pre-allocate (0 = lazy allocation)
///
/// Returns: pool ID (0..7) on success, -1 on error
#[unsafe(no_mangle)]
pub extern "C" fn dma_pool_create(block_size: u32, initial_pages: u32) -> i32 {
    if !is_valid_block_size(block_size) {
        log("dma_pool: invalid block size (must be power of 2, 16..4096)");
        return -1;
    }

    let pools = unsafe { &mut *POOLS.get() };

    // Find a free pool slot
    let mut slot: i32 = -1;
    for i in 0..MAX_POOLS {
        if !pools[i].active {
            slot = i as i32;
            break;
        }
    }

    if slot < 0 {
        log("dma_pool: no free pool slots");
        return -1;
    }

    let idx = slot as usize;
    let blocks_per_page = PAGE_SIZE as u32 / block_size;

    pools[idx] = DmaPool {
        active: true,
        block_size,
        blocks_per_page,
        pages: [PoolPage::empty(); MAX_PAGES_PER_POOL],
        page_count: 0,
        freelist: ptr::null_mut(),
        total_allocs: 0,
        total_frees: 0,
    };

    // Pre-allocate initial pages
    for _ in 0..initial_pages {
        if pool_add_page(&mut pools[idx]) != 0 {
            log("dma_pool: failed to allocate initial page");
            // Clean up already-allocated pages
            dma_pool_destroy(slot);
            return -1;
        }
    }

    unsafe {
        fut_printf(
            b"dma_pool: created pool %d (block=%u, blocks/page=%u, pages=%u)\n\0".as_ptr(),
            slot,
            block_size,
            blocks_per_page,
            initial_pages,
        );
    }

    slot
}

/// Destroy a DMA pool, freeing all its pages back to the kernel.
///
/// Returns: 0 on success, -1 on error
#[unsafe(no_mangle)]
pub extern "C" fn dma_pool_destroy(pool: i32) -> i32 {
    if pool < 0 || pool as usize >= MAX_POOLS {
        return -1;
    }

    let pools = unsafe { &mut *POOLS.get() };
    let idx = pool as usize;

    if !pools[idx].active {
        return -1;
    }

    // Free all pages
    for i in 0..pools[idx].page_count as usize {
        let page = pools[idx].pages[i].vaddr;
        if !page.is_null() {
            unsafe { free_page(page); }
        }
    }

    pools[idx] = DmaPool::empty();
    0
}

/// Allocate a block from the specified pool.
///
/// Fills in the DmaRegion with virtual address, physical address, and size.
/// If the pool has no free blocks, a new page is allocated automatically.
///
/// Returns: 0 on success, -1 on error
#[unsafe(no_mangle)]
pub extern "C" fn dma_pool_alloc(pool: i32, region: *mut DmaRegion) -> i32 {
    if pool < 0 || pool as usize >= MAX_POOLS || region.is_null() {
        return -1;
    }

    let pools = unsafe { &mut *POOLS.get() };
    let idx = pool as usize;

    if !pools[idx].active {
        return -1;
    }

    // If freelist is empty, grow the pool by one page
    if pools[idx].freelist.is_null() {
        if pool_add_page(&mut pools[idx]) != 0 {
            log("dma_pool: alloc failed, cannot grow pool");
            return -1;
        }
    }

    // Pop from freelist
    let node = pools[idx].freelist;
    pools[idx].freelist = unsafe { (*node).next };
    pools[idx].total_allocs += 1;

    let vaddr = node as *mut u8;

    // Zero the block before returning
    unsafe { ptr::write_bytes(vaddr, 0, pools[idx].block_size as usize); }

    let paddr = virt_to_phys(vaddr);

    unsafe {
        (*region).vaddr = vaddr;
        (*region).paddr = paddr;
        (*region).size = pools[idx].block_size as usize;
    }

    0
}

/// Free a block back to its pool.
///
/// The vaddr must have been obtained from dma_pool_alloc on the same pool.
///
/// Returns: 0 on success, -1 on error
#[unsafe(no_mangle)]
pub extern "C" fn dma_pool_free(pool: i32, vaddr: *mut u8) -> i32 {
    if pool < 0 || pool as usize >= MAX_POOLS || vaddr.is_null() {
        return -1;
    }

    let pools = unsafe { &mut *POOLS.get() };
    let idx = pool as usize;

    if !pools[idx].active {
        return -1;
    }

    // Validate the address belongs to this pool and is aligned
    if !pool_owns_addr(&pools[idx], vaddr) {
        log("dma_pool: free of address not owned by pool");
        return -1;
    }

    if !is_block_aligned(&pools[idx], vaddr) {
        log("dma_pool: free of unaligned address");
        return -1;
    }

    // Push onto freelist
    let node = vaddr as *mut FreeNode;
    unsafe {
        ptr::write(node, FreeNode { next: pools[idx].freelist });
    }
    pools[idx].freelist = node;
    pools[idx].total_frees += 1;

    0
}

/// Grow a pool by adding more pages.
///
/// Returns: 0 on success, -1 on error
#[unsafe(no_mangle)]
pub extern "C" fn dma_pool_grow(pool: i32, num_pages: u32) -> i32 {
    if pool < 0 || pool as usize >= MAX_POOLS {
        return -1;
    }

    let pools = unsafe { &mut *POOLS.get() };
    let idx = pool as usize;

    if !pools[idx].active {
        return -1;
    }

    for _ in 0..num_pages {
        if pool_add_page(&mut pools[idx]) != 0 {
            return -1;
        }
    }

    0
}

/// Allocate a single full page for DMA use.
///
/// Fills in the DmaRegion with the page's virtual/physical address and size.
/// The page is zeroed before return.
///
/// Returns: 0 on success, -1 on error
#[unsafe(no_mangle)]
pub extern "C" fn dma_alloc_page(region: *mut DmaRegion) -> i32 {
    if region.is_null() {
        return -1;
    }

    let page = unsafe { alloc_page() };
    if page.is_null() {
        log("dma_pool: failed to allocate page");
        return -1;
    }

    unsafe { ptr::write_bytes(page, 0, PAGE_SIZE); }

    let paddr = virt_to_phys(page);

    unsafe {
        (*region).vaddr = page;
        (*region).paddr = paddr;
        (*region).size = PAGE_SIZE;
    }

    0
}

/// Free a single DMA page previously allocated with dma_alloc_page.
///
/// Returns: 0 on success, -1 on error
#[unsafe(no_mangle)]
pub extern "C" fn dma_free_page(vaddr: *mut u8) -> i32 {
    if vaddr.is_null() {
        return -1;
    }

    unsafe { free_page(vaddr); }
    0
}

/// Translate a virtual address to its physical address.
///
/// Returns: physical address, or 0 if vaddr is null
#[unsafe(no_mangle)]
pub extern "C" fn dma_virt_to_phys(vaddr: *const u8) -> u64 {
    if vaddr.is_null() {
        return 0;
    }
    virt_to_phys(vaddr)
}

/// Allocate a coherent (uncacheable) DMA page.
///
/// On x86-64 with write-back caching, coherent DMA regions should bypass
/// the CPU cache. This allocates a page and relies on the kernel's page
/// flags to mark it uncacheable (PAT/MTRR). The caller must ensure the
/// kernel's alloc_page returns memory that can be remapped as uncacheable,
/// or use explicit cache management (CLFLUSH) after writes.
///
/// Returns: 0 on success, -1 on error
#[unsafe(no_mangle)]
pub extern "C" fn dma_alloc_coherent(region: *mut DmaRegion) -> i32 {
    // Allocate via the standard page path; the kernel is responsible for
    // ensuring the returned page can be used for coherent DMA.
    // On x86-64 with PAT, we would set the PCD (Page Cache Disable) bit.
    // For now this behaves the same as dma_alloc_page but documents the
    // intent for coherent / uncacheable allocation.
    dma_alloc_page(region)
}

/// Free a coherent DMA page previously allocated with dma_alloc_coherent.
///
/// Returns: 0 on success, -1 on error
#[unsafe(no_mangle)]
pub extern "C" fn dma_free_coherent(vaddr: *mut u8) -> i32 {
    dma_free_page(vaddr)
}

/// Copy data from a regular buffer into a DMA-safe region (bounce-to-device).
///
/// Allocates a temporary DMA page if the destination physical address is not
/// already mapped; otherwise copies directly via the virtual mapping.
///
/// dest_phys: physical address of the DMA destination buffer
/// src: virtual address of the source data
/// len: number of bytes to copy (must not exceed PAGE_SIZE)
///
/// Returns: 0 on success, -1 on error
#[unsafe(no_mangle)]
pub extern "C" fn dma_bounce_copy_to(dest_phys: u64, src: *const u8, len: u32) -> i32 {
    if src.is_null() || len == 0 || len as usize > PAGE_SIZE {
        return -1;
    }

    // We need a virtual mapping for the destination physical address.
    // Search the pool pages and standalone pages for a matching physical range.
    let dest_vaddr = phys_to_pool_vaddr(dest_phys);
    if dest_vaddr.is_null() {
        log("dma_pool: bounce_copy_to: dest paddr not in any pool");
        return -1;
    }

    unsafe {
        ptr::copy_nonoverlapping(src, dest_vaddr, len as usize);
    }

    0
}

/// Copy data from a DMA-safe region into a regular buffer (bounce-from-device).
///
/// src_phys: physical address of the DMA source buffer
/// dest: virtual address of the destination buffer
/// len: number of bytes to copy (must not exceed PAGE_SIZE)
///
/// Returns: 0 on success, -1 on error
#[unsafe(no_mangle)]
pub extern "C" fn dma_bounce_copy_from(dest: *mut u8, src_phys: u64, len: u32) -> i32 {
    if dest.is_null() || len == 0 || len as usize > PAGE_SIZE {
        return -1;
    }

    let src_vaddr = phys_to_pool_vaddr(src_phys);
    if src_vaddr.is_null() {
        log("dma_pool: bounce_copy_from: src paddr not in any pool");
        return -1;
    }

    unsafe {
        ptr::copy_nonoverlapping(src_vaddr as *const u8, dest, len as usize);
    }

    0
}

/// Reverse-lookup: find the virtual address for a physical address that
/// lives within one of the pool's managed pages.
fn phys_to_pool_vaddr(paddr: u64) -> *mut u8 {
    let pools = unsafe { &*POOLS.get() };

    for pool in pools.iter() {
        if !pool.active {
            continue;
        }
        for i in 0..pool.page_count as usize {
            let page = &pool.pages[i];
            if paddr >= page.paddr && paddr < page.paddr + PAGE_SIZE as u64 {
                let offset = (paddr - page.paddr) as usize;
                return unsafe { page.vaddr.add(offset) };
            }
        }
    }

    ptr::null_mut()
}

/// Initialise the DMA pool subsystem.
///
/// Resets all pool slots. Should be called once during kernel boot before
/// any driver requests DMA memory.
///
/// Returns: 0 on success
#[unsafe(no_mangle)]
pub extern "C" fn dma_pool_init() -> i32 {
    let pools = unsafe { &mut *POOLS.get() };
    for pool in pools.iter_mut() {
        *pool = DmaPool::empty();
    }

    log("dma_pool: subsystem initialised");
    0
}
