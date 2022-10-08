#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";
char name[32];

enum {
	BPF_DEVCG_DEV_BLOCK	= (1ULL << 0),
	BPF_DEVCG_DEV_CHAR	= (1ULL << 1),
};

enum {
	BPF_DEVCG_ACC_MKNOD	= (1ULL << 0),
	BPF_DEVCG_ACC_READ	= (1ULL << 1),
	BPF_DEVCG_ACC_WRITE	= (1ULL << 2),
};

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
*/
SEC("cgroup/device")
int device_access(struct bpf_cgroup_dev_ctx *ctx) {
	short type = ctx->access_type & 0xFFFF;
#if 0 // for debug
	short access = ctx->access_type >> 16;
	char fmt[] = "  %d:%d    \n";

	switch (type) {
		case BPF_DEVCG_DEV_BLOCK:
			fmt[0] = 'b';
			break;
		case BPF_DEVCG_DEV_CHAR:
			fmt[0] = 'c';
			break;
		default:
			fmt[0] = '?';
			break;
	}

	if (access & BPF_DEVCG_ACC_READ)
		fmt[8] = 'r';

    if (access & BPF_DEVCG_ACC_WRITE)
        fmt[9] = 'w';

    if (access & BPF_DEVCG_ACC_MKNOD)
        fmt[10] = 'm';

	bpf_trace_printk(fmt, sizeof(fmt), ctx->major, ctx->minor);
#endif
	// only forbid /dev/zero and /dev/urandom
	if (ctx->major != 1 || type != BPF_DEVCG_DEV_CHAR)
            return 1;

	switch (ctx->minor) {
        case 5: /* 1:5 /dev/zero */
        case 9: /* 1:9 /dev/urandom */
            return 0;
    }


    // bpf_printk("access denied device %d:%d\n", ctx->major, ctx->minor);
    return 1;
}