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
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";
char name[32];

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
	if (ctx->write) {
		bpf_sysctl_get_name(ctx, name, sizeof(name) , 0);
		bpf_printk("write %s denied!\n", name);
		return 0;
	}
	else
		return 1;
}
/*
** __cgroup_bpf_check_dev_permission
**__cgroup_bpf_run_filter_getsockopt
**__cgroup_bpf_run_filter_setsockopt
**__cgroup_bpf_run_filter_sk
**__cgroup_bpf_run_filter_skb
**__cgroup_bpf_run_filter_sock_addr
**__cgroup_bpf_run_filter_sock_ops
**__cgroup_bpf_run_filter_sysctl
*/