#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

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

#define MINORBITS   20  
#define MINORMASK   ((1U << MINORBITS) - 1)  
#define MAJOR(dev)  ((unsigned int) ((dev) >> MINORBITS))  
#define MINOR(dev)  ((unsigned int) ((dev) & MINORMASK))  
#define MKDEV(ma,mi)    (((ma) << MINORBITS) | (mi))

dev_t dev_arr[5];

static __always_inline int dev_permit(dev_t dev)
{
	int i;
	for (i = 0; i < 5; i++) {
		if (dev_arr[i] == dev)
			return 1;
	}

	return 0;
}

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

	if (type != BPF_DEVCG_DEV_CHAR) {
		return 1;
	}

	if (dev_permit(MKDEV(ctx->major, ctx->minor))) {
		return 0;
	}

	// bpf_printk("access denied device %d\n", *devno);

	// // only forbid /dev/zero and /dev/urandom
	// if (ctx->major != 1 || type != BPF_DEVCG_DEV_CHAR)
    //         return 1;

	// switch (ctx->minor) {
    //     case 5: /* 1:5 /dev/zero */
    //     case 9: /* 1:9 /dev/urandom */
    //         return 0;
    // }

    // bpf_printk("acc ess denied device %d:%d devno:%ld\n", ctx->major, ctx->minor, *devno);
    return 1;
}