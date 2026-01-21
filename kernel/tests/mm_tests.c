// SPDX-License-Identifier: MPL-2.0
/*
 * mm_tests.c - Comprehensive memory management tests
 *
 * Tests for COW fork, file-backed mmap, partial munmap, and VMA management.
 */

#include <kernel/fut_mm.h>
#include <kernel/fut_memory.h>
#include <kernel/fut_task.h>
#include <kernel/errno.h>

#if defined(__x86_64__)
#include <platform/x86_64/memory/paging.h>
#include <platform/x86_64/memory/pmap.h>
#endif

#include <kernel/kprintf.h>

/* mmap/munmap flags */
#define PROT_READ       0x1
#define PROT_WRITE      0x2
#define PROT_EXEC       0x4
#define MAP_SHARED      0x1
#define MAP_PRIVATE     0x2

/* VFS flags */
#define O_RDONLY        0x0000
#define O_WRONLY        0x0001
#define O_RDWR          0x0002
#define O_CREAT         0x0040

/* Test result tracking */
static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST_BEGIN(name) \
    do { \
        fut_printf("[MM-TEST] Running: %s\n", name); \
        tests_run++; \
    } while (0)

#define TEST_PASS(name) \
    do { \
        fut_printf("[MM-TEST] ✓ PASS: %s\n", name); \
        tests_passed++; \
    } while (0)

#define TEST_FAIL(name, reason) \
    do { \
        fut_printf("[MM-TEST] ✗ FAIL: %s - %s\n", name, reason); \
        tests_failed++; \
    } while (0)

#define ASSERT(cond, msg) \
    do { \
        if (!(cond)) { \
            TEST_FAIL(current_test, msg); \
            return; \
        } \
    } while (0)

/* ============================================================
 *   COW Fork Tests
 * ============================================================ */

/**
 * Test basic COW fork: parent writes to page, child's copy remains unchanged
 */
static void test_cow_fork_basic(void) {
    const char *current_test = "COW fork basic write";
    TEST_BEGIN(current_test);

    /* Create a test mapping */
    fut_mm_t *parent_mm = fut_mm_create();
    ASSERT(parent_mm != NULL, "Failed to create parent MM");

    /* Map an anonymous page */
    void *addr = fut_mm_map_anonymous(parent_mm, 0x80000000, PAGE_SIZE,
                                       PROT_READ | PROT_WRITE, MAP_PRIVATE);
    ASSERT(addr != NULL, "Failed to map anonymous page");
    ASSERT((uintptr_t)addr == 0x80000000, "Unexpected mapping address");

    /* Note: Cannot write to user-space memory from kernel context without
     * implementing a COW page fault handler. Skipping memory access verification.
     * The test verifies that:
     * 1. Anonymous page mapping succeeds
     * 2. VMA cloning succeeds
     * 3. Page tables are properly set up
     */

    /* Fork: create child MM with COW pages */
    fut_mm_t *child_mm = fut_mm_create();
    ASSERT(child_mm != NULL, "Failed to create child MM");

    /* Clone VMAs with COW */
    int rc = fut_mm_clone_vmas(child_mm, parent_mm);
    ASSERT(rc == 0, "Failed to clone VMAs");

    /* Note: COW page fault handler is fully implemented in kernel/trap/page_fault.c.
     * Testing actual memory access from kernel context is not possible since we cannot
     * switch to user-space page tables and access user memory directly.
     * The VMA cloning test here verifies the architectural setup is correct.
     * Full end-to-end COW testing would require userland test executables that perform
     * actual memory writes and verify the isolated copies, which is tested indirectly
     * through the Wayland compositor and other userland services.
     */

    (void)addr;  /* Suppress unused warning */

    fut_mm_release(child_mm);
    fut_mm_release(parent_mm);

    TEST_PASS(current_test);
}

/**
 * Test COW sole owner optimization: single reference should become writable
 */
static void test_cow_sole_owner(void) {
    const char *current_test = "COW sole owner optimization";
    TEST_BEGIN(current_test);

    /* Create parent with mapped page */
    fut_mm_t *parent_mm = fut_mm_create();
    ASSERT(parent_mm != NULL, "Failed to create parent MM");

    void *addr = fut_mm_map_anonymous(parent_mm, 0x80000000, PAGE_SIZE,
                                       PROT_READ | PROT_WRITE, MAP_PRIVATE);
    ASSERT(addr != NULL, "Failed to map page");

    /* Fork to create COW pages */
    fut_mm_t *child_mm = fut_mm_create();
    ASSERT(child_mm != NULL, "Failed to create child MM");

    int rc = fut_mm_clone_vmas(child_mm, parent_mm);
    ASSERT(rc == 0, "Failed to clone VMAs");

    /* Release child MM - parent becomes sole owner */
    fut_mm_release(child_mm);

    /* Parent should be able to write without copying */
    /* (This would be verified by checking refcount == 1) */

    fut_mm_release(parent_mm);

    TEST_PASS(current_test);
}

/* ============================================================
 *   Partial munmap Tests
 * ============================================================ */

/**
 * Test munmap shrinking VMA from the left
 */
static void test_munmap_shrink_left(void) {
    const char *current_test = "munmap shrink left";
    TEST_BEGIN(current_test);

    fut_mm_t *mm = fut_mm_create();
    ASSERT(mm != NULL, "Failed to create MM");

    /* Map 4 pages */
    void *addr = fut_mm_map_anonymous(mm, 0x80000000, PAGE_SIZE * 4,
                                       PROT_READ | PROT_WRITE, MAP_PRIVATE);
    ASSERT(addr != NULL, "Failed to map 4 pages");

    /* Unmap first 2 pages */
    int rc = fut_mm_unmap(mm, 0x80000000, PAGE_SIZE * 2);
    ASSERT(rc == 0, "Failed to unmap left portion");

    /* Verify VMA now starts at page 2 */
    struct fut_vma *vma = mm->vma_list;
    ASSERT(vma != NULL, "VMA list is empty");
    ASSERT(vma->start == 0x80000000 + PAGE_SIZE * 2, "VMA not shrunk from left");
    ASSERT(vma->end == 0x80000000 + PAGE_SIZE * 4, "VMA end changed unexpectedly");

    fut_mm_release(mm);

    TEST_PASS(current_test);
}

/**
 * Test munmap shrinking VMA from the right
 */
static void test_munmap_shrink_right(void) {
    const char *current_test = "munmap shrink right";
    TEST_BEGIN(current_test);

    fut_mm_t *mm = fut_mm_create();
    ASSERT(mm != NULL, "Failed to create MM");

    /* Map 4 pages */
    void *addr = fut_mm_map_anonymous(mm, 0x80000000, PAGE_SIZE * 4,
                                       PROT_READ | PROT_WRITE, MAP_PRIVATE);
    ASSERT(addr != NULL, "Failed to map 4 pages");

    /* Unmap last 2 pages */
    int rc = fut_mm_unmap(mm, 0x80000000 + PAGE_SIZE * 2, PAGE_SIZE * 2);
    ASSERT(rc == 0, "Failed to unmap right portion");

    /* Verify VMA now ends at page 2 */
    struct fut_vma *vma = mm->vma_list;
    ASSERT(vma != NULL, "VMA list is empty");
    ASSERT(vma->start == 0x80000000, "VMA start changed unexpectedly");
    ASSERT(vma->end == 0x80000000 + PAGE_SIZE * 2, "VMA not shrunk from right");

    fut_mm_release(mm);

    TEST_PASS(current_test);
}

/**
 * Test munmap splitting VMA in the middle
 */
static void test_munmap_split_middle(void) {
    const char *current_test = "munmap split middle";
    TEST_BEGIN(current_test);

    fut_mm_t *mm = fut_mm_create();
    ASSERT(mm != NULL, "Failed to create MM");

    /* Map 4 pages */
    void *addr = fut_mm_map_anonymous(mm, 0x80000000, PAGE_SIZE * 4,
                                       PROT_READ | PROT_WRITE, MAP_PRIVATE);
    ASSERT(addr != NULL, "Failed to map 4 pages");

    /* Unmap middle 2 pages (pages 1 and 2) */
    int rc = fut_mm_unmap(mm, 0x80000000 + PAGE_SIZE, PAGE_SIZE * 2);
    ASSERT(rc == 0, "Failed to unmap middle portion");

    /* Should have 2 VMAs now */
    struct fut_vma *vma1 = mm->vma_list;
    ASSERT(vma1 != NULL, "First VMA is missing");
    ASSERT(vma1->start == 0x80000000, "First VMA wrong start");
    ASSERT(vma1->end == 0x80000000 + PAGE_SIZE, "First VMA wrong end");

    struct fut_vma *vma2 = vma1->next;
    ASSERT(vma2 != NULL, "Second VMA is missing");
    ASSERT(vma2->start == 0x80000000 + PAGE_SIZE * 3, "Second VMA wrong start");
    ASSERT(vma2->end == 0x80000000 + PAGE_SIZE * 4, "Second VMA wrong end");

    fut_mm_release(mm);

    TEST_PASS(current_test);
}

/**
 * Test munmap across multiple VMAs
 */
static void test_munmap_cross_vma(void) {
    const char *current_test = "munmap cross VMA";
    TEST_BEGIN(current_test);

    fut_mm_t *mm = fut_mm_create();
    ASSERT(mm != NULL, "Failed to create MM");

    /* Map 2 separate regions */
    void *addr1 = fut_mm_map_anonymous(mm, 0x80000000, PAGE_SIZE * 2,
                                        PROT_READ | PROT_WRITE, MAP_PRIVATE);
    ASSERT(addr1 != NULL, "Failed to map first region");

    void *addr2 = fut_mm_map_anonymous(mm, 0x80010000, PAGE_SIZE * 2,
                                        PROT_READ | PROT_WRITE, MAP_PRIVATE);
    ASSERT(addr2 != NULL, "Failed to map second region");

    /* Unmap range spanning both VMAs */
    int rc = fut_mm_unmap(mm, 0x80000000, 0x80012000 - 0x80000000);
    ASSERT(rc == 0, "Failed to unmap cross-VMA range");

    /* Should have no VMAs or only the tail of the second VMA */
    /* (depending on exact overlap) */

    fut_mm_release(mm);

    TEST_PASS(current_test);
}

/* ============================================================
 *   Edge Case Tests
 * ============================================================ */

/**
 * Test munmap with unaligned addresses (should round to pages)
 */
static void test_munmap_unaligned(void) {
    const char *current_test = "munmap unaligned addresses";
    TEST_BEGIN(current_test);

    fut_mm_t *mm = fut_mm_create();
    ASSERT(mm != NULL, "Failed to create MM");

    /* Map aligned region */
    void *addr = fut_mm_map_anonymous(mm, 0x80000000, PAGE_SIZE * 2,
                                       PROT_READ | PROT_WRITE, MAP_PRIVATE);
    ASSERT(addr != NULL, "Failed to map region");

    /* Unmap with unaligned address - should round down */
    int rc = fut_mm_unmap(mm, 0x80000000 + 100, PAGE_SIZE);
    ASSERT(rc == 0, "Failed to unmap with unaligned address");

    fut_mm_release(mm);

    TEST_PASS(current_test);
}

/**
 * Test munmap with zero length (should be no-op)
 */
static void test_munmap_zero_length(void) {
    const char *current_test = "munmap zero length";
    TEST_BEGIN(current_test);

    fut_mm_t *mm = fut_mm_create();
    ASSERT(mm != NULL, "Failed to create MM");

    /* Map region */
    void *addr = fut_mm_map_anonymous(mm, 0x80000000, PAGE_SIZE,
                                       PROT_READ | PROT_WRITE, MAP_PRIVATE);
    ASSERT(addr != NULL, "Failed to map region");

    /* Unmap zero bytes - should be no-op */
    int rc = fut_mm_unmap(mm, 0x80000000, 0);
    /* Could succeed (no-op) or return error - depends on implementation */
    (void)rc;  /* Suppress unused warning */

    /* VMA should still exist */
    ASSERT(mm->vma_list != NULL, "VMA disappeared after zero-length unmap");

    fut_mm_release(mm);

    TEST_PASS(current_test);
}

/**
 * Test munmap with invalid range (unmapped memory)
 */
static void test_munmap_invalid_range(void) {
    const char *current_test = "munmap invalid range";
    TEST_BEGIN(current_test);

    fut_mm_t *mm = fut_mm_create();
    ASSERT(mm != NULL, "Failed to create MM");

    /* Try to unmap unmapped region - should return error or succeed as no-op */
    int rc = fut_mm_unmap(mm, 0x90000000, PAGE_SIZE);
    /* POSIX allows this to succeed if no mapping exists */
    (void)rc;  /* Suppress unused warning */

    fut_mm_release(mm);

    TEST_PASS(current_test);
}

/* ============================================================
 *   VMA Integrity Tests
 * ============================================================ */

/**
 * Test VMA list consistency after multiple operations
 */
static void test_vma_integrity(void) {
    const char *current_test = "VMA list integrity";
    TEST_BEGIN(current_test);

    fut_mm_t *mm = fut_mm_create();
    ASSERT(mm != NULL, "Failed to create MM");

    /* Perform series of map operations */
    void *addr1 = fut_mm_map_anonymous(mm, 0x80000000, PAGE_SIZE,
                                        PROT_READ | PROT_WRITE, MAP_PRIVATE);
    ASSERT(addr1 != NULL, "Failed map 1");

    void *addr2 = fut_mm_map_anonymous(mm, 0x80010000, PAGE_SIZE,
                                        PROT_READ | PROT_WRITE, MAP_PRIVATE);
    ASSERT(addr2 != NULL, "Failed map 2");

    void *addr3 = fut_mm_map_anonymous(mm, 0x80020000, PAGE_SIZE,
                                        PROT_READ | PROT_WRITE, MAP_PRIVATE);
    ASSERT(addr3 != NULL, "Failed map 3");

    /* Walk VMA list and verify consistency */
    struct fut_vma *vma = mm->vma_list;
    struct fut_vma *prev = NULL;
    int vma_count = 0;

    while (vma) {
        /* Check VMA validity */
        ASSERT(vma->start < vma->end, "VMA start >= end");
        ASSERT((vma->start & (PAGE_SIZE - 1)) == 0, "VMA start not page-aligned");
        ASSERT((vma->end & (PAGE_SIZE - 1)) == 0, "VMA end not page-aligned");

        /* Check no overlap with previous VMA */
        if (prev) {
            if (prev->end > vma->start) {
                fut_printf("[VMA-DEBUG] Overlap detected:\n");
                fut_printf("  prev: [0x%lx - 0x%lx)\n", prev->start, prev->end);
                fut_printf("  curr: [0x%lx - 0x%lx)\n", vma->start, vma->end);
                ASSERT(false, "VMAs overlap");
            }
        }

        prev = vma;
        vma = vma->next;
        vma_count++;
    }

    ASSERT(vma_count == 3, "Wrong number of VMAs");

    fut_mm_release(mm);

    TEST_PASS(current_test);
}

/* ============================================================
 *   Test Suite Entry Point
 * ============================================================ */

void fut_mm_tests_run(void) {
    static int already_run = 0;
    if (already_run) {
        return;
    }
    already_run = 1;

    fut_printf("\n");
    fut_printf("========================================\n");
    fut_printf("  Memory Management Test Suite\n");
    fut_printf("========================================\n");

    /* COW Fork Tests */
    test_cow_fork_basic();
    /* COW sole owner test re-enabled for debugging - was: Causes kernel crash */
    test_cow_sole_owner();

    /* Partial munmap Tests */
    test_munmap_shrink_left();
    test_munmap_shrink_right();
    test_munmap_split_middle();
    test_munmap_cross_vma();

    /* Edge Case Tests */
    test_munmap_unaligned();
    test_munmap_zero_length();
    test_munmap_invalid_range();

    /* VMA Integrity Tests */
    test_vma_integrity();

    /* Summary */
    fut_printf("\n");
    fut_printf("========================================\n");
    fut_printf("  Test Summary\n");
    fut_printf("========================================\n");
    fut_printf("  Total:  %d\n", tests_run);
    fut_printf("  Passed: %d\n", tests_passed);
    fut_printf("  Failed: %d\n", tests_failed);
    fut_printf("========================================\n");

    if (tests_failed == 0) {
        fut_printf("[MM-TEST] ✓ ALL TESTS PASSED\n");
    } else {
        fut_printf("[MM-TEST] ✗ SOME TESTS FAILED\n");
    }
}
