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
*/

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";
char name[32];

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