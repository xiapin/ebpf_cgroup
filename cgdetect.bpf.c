#include "vmlinux.h"
#include "cgdetect.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 128 * 1024);
} rb SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);
    __type(value, struct filters);
} filters SEC(".maps");

const int report_interval_us = 100000;

static inline int handle_cgroup_events
(struct trace_event_raw_cgroup_event *ctx, enum CGROUP_EVENT type)
{
    struct event *e;
    unsigned fname_off;

    e = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
    if (!e) {
        return 0;
    }

    e->e_type = type;
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
    return handle_cgroup_events(ctx, CGROUP_CREATE);
}

SEC("tp/cgroup/cgroup_rmdir")
int handle_cgroup_destroy(struct trace_event_raw_cgroup_event *ctx)
{
    return handle_cgroup_events(ctx, CGROUP_DESTROY);
}

__always_inline
int cgroup_event_submit
(enum CGROUP_EVENT e_type, u32 cgroup_id)
{
    struct event *e = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
    if (!e) {
        return 0;
    }

    e->e_type = e_type;
    e->id = cgroup_id;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_ringbuf_submit(e, 0);

    return 0;
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

    struct filters *f = bpf_map_lookup_elem(&filters, &cgroup_id);
    if (!f) {
        return 0;
    }

    if (mem < f->mem_pages && swap < f->swap_pages) {
        return 0;
    }

    u64 cur_ns = bpf_ktime_get_ns();
    if ((cur_ns - f->last_ts) / 1000 < report_interval_us) {
        return 0;
    }
    f->last_ts = cur_ns;
    bpf_map_update_elem(&filters, &cgroup_id, f, 0);

    return cgroup_event_submit(CGROUP_MEM_TRIG, cgroup_id);
}

SEC("kprobe/try_to_free_mem_cgroup_pages")
int BPF_KPROBE(try_to_free_mem_cgroup_pages, struct mem_cgroup *memcg,
                unsigned long nr_pages,
                gfp_t gfp_mask,
                bool may_swap)
{
    u32 cgroup_id = 0;

    BPF_CORE_READ_INTO(&cgroup_id, memcg, css.cgroup, kn, id);
    struct filters *f = bpf_map_lookup_elem(&filters, &cgroup_id);
    if (!f) {
        return 0;
    }

    u64 cur_ns = bpf_ktime_get_ns();
    if ((cur_ns - f->last_ts) / 1000 < report_interval_us) {
        return 0;
    }
    f->last_ts = cur_ns;
    bpf_map_update_elem(&filters, &cgroup_id, f, 0);

    return cgroup_event_submit(CGROUP_MEM_RECLAIM, cgroup_id);
}

SEC("kprobe/oom_kill_process")
int BPF_KPROBE(oom_kill_process, struct oom_control *oc, const char *message)
{
    struct event *e;
    u32 cgroup_id = 0;

    BPF_CORE_READ_INTO(&cgroup_id, oc, memcg, css.cgroup, kn, id);
    e = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
    if (!e) {
        return 0;
    }

    e->e_type = CGROUP_OOM;
    e->id = cgroup_id;
    bpf_probe_read_kernel(&e->comm, sizeof(e->comm), BPF_CORE_READ(oc, chosen, comm));
    bpf_ringbuf_submit(e, 0);

    return 0;
}

SEC("kprobe/files_cgroup_alloc_fd")
int BPF_KPROBE(files_cgroup_alloc_fd, struct files_struct *files, u64 n)
{
    u32 cgroup_id;
    u64 cur_open;

    BPF_CORE_READ_INTO(&cgroup_id, files, files_cgroup, css.cgroup, kn, id);
    struct filters *f = bpf_map_lookup_elem(&filters, &cgroup_id);
    if (!f) {
        return 0;
    }

    cur_open = BPF_CORE_READ(files, files_cgroup, open_handles.usage.counter);
    if (cur_open + n < f->files) {
        return 0;
    }

    return cgroup_event_submit(CGORUP_FILES, cgroup_id);
}

SEC("kprobe/copy_process")
int BPF_KPROBE(copy_process, struct pid *pid,
                int trace,
                int node,
                struct kernel_clone_args *args)
{
    u32 cgroup_id;
    u64 cur_pids;

    BPF_CORE_READ_INTO(&cgroup_id, args, cgrp, kn, id);
    struct filters *f = bpf_map_lookup_elem(&filters, &cgroup_id);
    if (!f) {
        return 0;
    }

    struct task_struct *current = (struct task_struct *)bpf_get_current_task();
    cur_pids = BPF_CORE_READ(current, real_cred, user, processes.counter);
    if (cur_pids < f->pids) {
        return 0;
    }

    return cgroup_event_submit(CGROUP_PIDS, cgroup_id);
}

SEC("kprobe/ep_insert")
int BPF_KPROBE(ep_insert,
            struct eventpoll *ep, const struct epoll_event *event,
            struct file *tfile, int fd, int full_check)
{
    u32 cgroup_id;
    u64 cur_epfds;

    struct task_struct *current = (struct task_struct *)bpf_get_current_task();
    BPF_CORE_READ_INTO(&cgroup_id, current, cgroups, dfl_cgrp, kn, id);
    struct filters *f = bpf_map_lookup_elem(&filters, &cgroup_id);
    if (!f) {
        return 0;
    }

    cur_epfds = BPF_CORE_READ(current, real_cred, user, epoll_watches.counter);
    if (cur_epfds < f->epoll_fds) {
        return 0;
    }

    return cgroup_event_submit(CGROUP_EPOLL_FDS, cgroup_id);
}