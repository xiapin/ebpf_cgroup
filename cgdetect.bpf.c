#include "vmlinux.h"
#include "cgdetect.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 128 * 1024);
} rb SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);
    __type(value, struct mem_stat);
} filters SEC(".maps");

static inline int handle_cgroup_events(struct trace_event_raw_cgroup_event *ctx, int create)
{
    struct event *e;
    unsigned fname_off;

    e = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
    if (!e) {
        return 0;
    }

    e->create = create;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->root = (int)ctx->root;
    e->id = (int)ctx->id;
    e->level = (int)ctx->level;
    fname_off = ctx->__data_loc_path & 0xFFFF;
    bpf_probe_read_str(&e->path, CGRP_PATH_LEN, (void *)ctx + fname_off);

    bpf_ringbuf_submit(e, 0);

    return 0;
}

SEC("tp/cgroup/cgroup_mkdir")
int handle_cgroup_create(struct trace_event_raw_cgroup_event *ctx)
{
    return handle_cgroup_events(ctx, 1);
}

SEC("tp/cgroup/cgroup_rmdir")
int handle_cgroup_destroy(struct trace_event_raw_cgroup_event *ctx)
{
    return handle_cgroup_events(ctx, 0);
}

SEC("kprobe/try_charge")
int BPF_KPROBE(try_charge, struct mem_cgroup *memcg,
            gfp_t gfp_mask, unsigned int nr_pages)
{
    unsigned long mem, swap;

    // u32 cgroup_id = bpf_get_current_cgroup_id(); // invalid in cgroup_v1
    u32 cgroup_id = BPF_CORE_READ(memcg, css.cgroup, kn, id);

    BPF_CORE_READ_INTO(&mem, memcg, memory.usage.counter);
    BPF_CORE_READ_INTO(&swap, memcg, swap.usage.counter);

    struct mem_stat *stat = bpf_map_lookup_elem(&filters, &cgroup_id);
    if (!stat) {
        return 0;
    }

    if (mem < stat->mem_pages && swap < stat->swap_pages) {
        return 0;
    }

    u64 cur_ns = bpf_ktime_get_ns();
    if ((cur_ns - stat->last_ts) / 1000 < 10000000) { // report per 10s
        return 0;
    }
    stat->last_ts = cur_ns;
    bpf_map_update_elem(&filters, &cgroup_id, stat, 0);

    struct event *e = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
    if (!e) {
        return 0;
    }

    e->create = 2;
    e->id = cgroup_id;

    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_ringbuf_submit(e, 0);

    return 0;
}
