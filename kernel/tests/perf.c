#include "perf.h"

#include <kernel/fut_task.h>
#include <kernel/fut_thread.h>

#include <stdbool.h>

#include "tests/test_api.h"

extern void fut_printf(const char *fmt, ...);

#ifdef DEBUG_PERF
#define PERFDBG(...) fut_printf(__VA_ARGS__)
#else
#define PERFDBG(...) do { } while (0)
#endif

static void fut_perf_print_line(const char *tag, const struct fut_perf_stats *stats) {
    uint64_t p50_ns = fut_cycles_to_ns(stats->p50);
    uint64_t p90_ns = fut_cycles_to_ns(stats->p90);
    uint64_t p99_ns = fut_cycles_to_ns(stats->p99);
    fut_printf("[PERF] %s p50=%llu p90=%llu p99=%llu\n",
               tag,
               (unsigned long long)p50_ns,
               (unsigned long long)p90_ns,
               (unsigned long long)p99_ns);
}

static void fut_perf_thread(void *arg) {
    (void)arg;

    struct fut_perf_stats ipc_stats = {0};
    struct fut_perf_stats ctx_stats = {0};
    struct fut_perf_stats blk_read = {0};
    struct fut_perf_stats blk_write = {0};
    struct fut_perf_stats net_small = {0};
    struct fut_perf_stats net_mtu = {0};

    if (fut_perf_run_ipc(&ipc_stats) != 0) {
        fut_printf("[PERF] ipc benchmark failed\n");
        fut_test_fail(0xP1);
        return;
    }
    fut_perf_print_line("ipc_rtt_ns", &ipc_stats);

    if (fut_perf_run_ctx_switch(&ctx_stats) != 0) {
        fut_printf("[PERF] ctx-switch benchmark failed\n");
        fut_test_fail(0xP2);
        return;
    }
    fut_perf_print_line("ctx_switch_ns", &ctx_stats);

    if (fut_perf_run_blk(&blk_read, &blk_write) != 0) {
        fut_printf("[PERF] block benchmark failed\n");
        fut_test_fail(0xP3);
        return;
    }
    fut_perf_print_line("blk_read_4k_ns", &blk_read);
    fut_perf_print_line("blk_write_4k_ns", &blk_write);

    if (fut_perf_run_net(&net_small, &net_mtu) != 0) {
        fut_printf("[PERF] net benchmark failed\n");
        fut_test_fail(0xP4);
        return;
    }
    fut_perf_print_line("net_loop_small_ns", &net_small);
    fut_perf_print_line("net_loop_mtu_ns", &net_mtu);

    fut_test_pass();
}

void fut_perf_selftest_schedule(struct fut_task *task) {
    if (!task) {
        return;
    }

    fut_thread_t *thread = fut_thread_create(task,
                                             fut_perf_thread,
                                             NULL,
                                             12 * 1024,
                                             180);
    if (!thread) {
        fut_printf("[PERF] failed to schedule harness thread\n");
    }
}
