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