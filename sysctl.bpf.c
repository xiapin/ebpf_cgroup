/*
** Describe: Use ebpf to intercept the specified call of sysctl
** Reference: https://zhuanlan.zhihu.com/p/473093341
** Use Flow: ./sysctl
** # bpftool prog list
	##93##notice id: cgroup_sysctl  name sysctl_w_deny  tag 6e9a0dd5d77e7087  gpl
        loaded_at 2022-09-26T16:24:32+0800  uid 0
        xlated 200B  jited 126B  memlock 4096B  map_ids 19
        btf_id 55
        pids sysctl(2799)
** Attach: # bpftool cgroup attach /sys/fs/cgroup/ sysctl id 93 override
** Detach: # bpftool cgroup detach /sys/fs/cgroup/ sysctl id 93
** Show: # bpftool cgroup tree
*/

#include "vmlinux.h"
#include "sysctl.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, u32);
	__type(value, u32);
} hists SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 128 * 1024);
} rb SEC(".maps");

char comm[16];
/*
**	bpf_prog_attach
	case BPF_PROG_TYPE_CGROUP_DEVICE:
	case BPF_PROG_TYPE_CGROUP_SKB:
	case BPF_PROG_TYPE_CGROUP_SOCK:
	case BPF_PROG_TYPE_CGROUP_SOCK_ADDR:
	case BPF_PROG_TYPE_CGROUP_SOCKOPT:
	case BPF_PROG_TYPE_CGROUP_SYSCTL:
	case BPF_PROG_TYPE_SOCK_OPS:
		ret = cgroup_bpf_prog_attach(attr, ptype, prog);
在 proc_sys_call_handler -> BPF_CGROUP_RUN_PROG_SYSCTL -> __cgroup_bpf_run_filter_sysctl
-> BPF_PROG_RUN_ARRAY中生效
*/
SEC("cgroup/sysctl")
int sysctl_w_deny(struct bpf_sysctl *ctx) {
	struct data_t *data;
	u32 ret;
	u64 cgroup_id = 0;

	data = bpf_ringbuf_reserve(&rb, sizeof(struct data_t), 0);
	if (!data) {
		return 0;
	}

	cgroup_id = bpf_get_current_cgroup_id();
	data->cgroup_id = cgroup_id;
	data->write = (int)ctx->write;
	bpf_sysctl_get_name(ctx, data->sysctl_name, SYSCTL_NAME_LEN, 0);
	bpf_sysctl_get_current_value(ctx, data->cur_value, SYSCTL_VAL_LEN);
	bpf_sysctl_get_new_value(ctx, data->new_value, SYSCTL_VAL_LEN);

	if (ctx->write) {
		u32 *permis = bpf_map_lookup_elem(&hists, &cgroup_id);
		if (!permis || *permis == 0) {
			ret = 0;
			goto end;
		}
	}

	ret = 1;
end:
	bpf_ringbuf_submit(data, 0);
	return ret;
}
/*
** __cgroup_bpf_check_dev_permission -> device
**__cgroup_bpf_run_filter_getsockopt -> getsockopt
**__cgroup_bpf_run_filter_setsockopt -> setsockopt
**__cgroup_bpf_run_filter_sk -> 
**__cgroup_bpf_run_filter_skb -> 
**__cgroup_bpf_run_filter_sock_addr -> bind4 ?
**__cgroup_bpf_run_filter_sock_ops -> sock_ops
**__cgroup_bpf_run_filter_sysctl -> sysctl
*/
