#include <fcntl.h>
#include <bpf/libbpf.h>
#include <unistd.h>
#include <stdlib.h>

#include "bpf_utils.h"
#include "sysctl.skel.h"

int main(int argc, char **argv)
{
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

    // TODO:
    bpf_program__attach_cgroup(skel->progs.sysctl_w_deny, cgrpfd);
    while (!utils_should_exit()) {
        sleep(10);
    }

clean:
    __BPF_DETACH_AND_DESTROY(sysctl, skel);

    return 0;
}