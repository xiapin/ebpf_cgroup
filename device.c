#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

#include "bpf_utils.h"
#include "device.skel.h"

#define MINORBITS   20  
#define MINORMASK   ((1U << MINORBITS) - 1)  
#define MAJOR(dev)  ((unsigned int) ((dev) >> MINORBITS))  
#define MINOR(dev)  ((unsigned int) ((dev) & MINORMASK))  
#define MKDEV(ma,mi)    (((ma) << MINORBITS) | (mi))

static void add_denied_device(struct device_bpf *skel)
{
    // TODO: from configure file
    dev_t dev_zero = MKDEV(1, 5);
    skel->bss->dev_arr[0] = dev_zero;

    dev_t dev_random = MKDEV(1, 9);
    skel->bss->dev_arr[1] = dev_random;

    dev_t dev_kmsg = MKDEV(1, 11);
    skel->bss->dev_arr[2] = dev_kmsg;
}

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

    add_denied_device(skel);

    __BPF_ATTACH(device, skel);

    int cgrpfd = open(argv[1], O_RDONLY);
    if (cgrpfd < 0) {
        fprintf(stderr, "Failed to open %s\n", argv[1]);
        goto clean;
    }

    bpf_program__attach_cgroup(skel->progs.device_access, cgrpfd);

    while (!utils_should_exit()) {
        sleep(10);
    }

clean:
    __BPF_DETACH_AND_DESTROY(device, skel);

    return 0;
}
