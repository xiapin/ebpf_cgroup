#include <bpf/libbpf.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

#include "bpf_utils.h"
#include "device.skel.h"

int main(int argc, char **argv)
{
    int err;

    if (argc != 2) {
        printf("usage: %s cgroup\n", argv[0]);
        return 1;
    }

    utils_set_rlimits();
    utils_sigact();

    __SKEL_DEFINE(device, skel);
    skel = __BPF_OPEN_AND_LOAD(device);
    __BPF_ATTACH(device, skel);

    int cgrpfd = open(argv[1], O_RDONLY);
    if (cgrpfd < 0) {
        fprintf(stderr, "Failed to open %s\n", argv[1]);
        goto clean;
    }

    if (bpf_program__attach_cgroup(skel->progs.device_access, cgrpfd)) {
        fprintf(stderr, "Failed to attach cgroup!\n");
	    goto clean;
    }

    while (!utils_should_exit()) {
        sleep(10);
    }

clean:
    __BPF_DETACH_AND_DESTROY(device, skel);

    return 0;
}
