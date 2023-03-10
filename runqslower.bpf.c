// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2019 Facebook
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "runqslower.h"

#define TASK_RUNNING 0
#define BPF_F_CURRENT_CPU 0xffffffffULL

const volatile __u64 min_us = 0;
const volatile pid_t targ_pid = 0;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, u32);
	__type(value, u64);
} start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32)); // 暂不支持key/value形式，因此指定key、value的size
	__uint(value_size, sizeof(u32));
} events SEC(".maps");

/* record enqueue timestamp */
__always_inline
static int trace_enqueue(u32 tgid, u32 pid)
{
	u64 ts;

	if (!pid || (targ_pid && targ_pid != pid))
		return 0;

	ts = bpf_ktime_get_ns(); // key为pid，value为时间戳
	bpf_map_update_elem(&start, &pid, &ts, 0);
	return 0;
}

SEC("tp_btf/sched_wakeup")
int handle__sched_wakeup(u64 *ctx)
{
	/* TP_PROTO(struct task_struct *p) */
	struct task_struct *p = (void *)ctx[0];

	return trace_enqueue(p->tgid, p->pid);
}

SEC("tp_btf/sched_wakeup_new")
int handle__sched_wakeup_new(u64 *ctx)
{
	/* TP_PROTO(struct task_struct *p) */
	struct task_struct *p = (void *)ctx[0];

	return trace_enqueue(p->tgid, p->pid);
}

// $KERN_SRC/tools/lib/bpf/libbpf.c section_defs
SEC("tp_btf/sched_switch")
int handle__sched_switch(u64 *ctx)
{
	/* TP_PROTO(bool preempt, struct task_struct *prev,
	 *	    struct task_struct *next)
	 */
	struct task_struct *prev = (struct task_struct *)ctx[1];
	struct task_struct *next = (struct task_struct *)ctx[2];
	struct event event = {};
	u64 *tsp, delta_us;
	long state;
	u32 pid;

	/* ivcsw: treat like an enqueue event and store timestamp */
	// 如果被切换的任务的状态仍然是TASK_RUNNING，说明其又重新进入run队列，更新入队列的时间
	// if (prev->__state == TASK_RUNNING)
	if (prev->state == TASK_RUNNING)
		trace_enqueue(prev->tgid, prev->pid);

	pid = next->pid;

	/* fetch timestamp and calculate delta */
	tsp = bpf_map_lookup_elem(&start, &pid);
	if (!tsp)
		return 0;   /* missed enqueue */

	delta_us = (bpf_ktime_get_ns() - *tsp) / 1000;
	if (min_us && delta_us <= min_us)
		return 0;

	event.pid = pid;
	event.delta_us = delta_us;
	bpf_get_current_comm(&event.task, sizeof(event.task));

	/* output */
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
			      &event, sizeof(event));

	bpf_map_delete_elem(&start, &pid);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
