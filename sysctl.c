#include <fcntl.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <unistd.h>
#include <stdlib.h>

#include "bpf_utils.h"
#include "sysctl.h"
#include "sysctl.skel.h"

static int handler_event(void *ctx, void *data, size_t data_sz)
{
    const struct data_t *d = data;

    printf("tgid:%ld access:%d sysctl:%s curr:%s new:%s\n",
            d->tgid, d->write, d->sysctl_name, d->cur_value,
            d->new_value);

    return 0;
}

int main(int argc, char **argv)
{
    struct ring_buffer *rb;
    int err;
    if (argc != 2) {
        printf("usage: %s cgroup\n", argv[0]);
        return 1;
    }

    utils_set_rlimits();
    utils_sigact();

    __SKEL_DEFINE(sysctl, skel);
    skel = __BPF_OPEN_AND_LOAD(sysctl);
    __BPF_ATTACH(sysctl, skel);

    int cgrpfd = open(argv[1], O_RDONLY);
    if (cgrpfd < 0) {
        fprintf(stderr, "Failed to open %s\n", argv[1]);
        goto clean;
    }

    bpf_program__attach_cgroup(skel->progs.sysctl_w_deny, cgrpfd);

    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handler_event, NULL, NULL);
    if (!rb) {
        return 1;
    }

    // stat $(find /sys/fs/cgroup/ -name cgroup.procs | xargs grep -ws 5338 | cut -d ':' -f 1) | grep Inode
    unsigned long long tgid = 20838;
    unsigned int allow = 1;
    bpf_map_update_elem(bpf_map__fd(skel->maps.hists), &tgid, &allow, 0);

    while (!utils_should_exit()) {
        err = ring_buffer__poll(rb, 100); // timeout 100 ms
        if (err < 0) {
            printf("Error polling perf buffer:%d\n", err);
            break;
        }
    }

clean:
    __BPF_DETACH_AND_DESTROY(sysctl, skel);

    return 0;
}
