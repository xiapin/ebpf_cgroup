#include <bpf/libbpf.h>
#include <unistd.h>
#include <stdio.h>
#include <getopt.h>
#include <fcntl.h>

#include "bpf_utils.h"
#include "sockaddr.skel.h"

int main(int argc, char **argv)
{
    if (argc != 2) {
        printf("usage: %s cgroup\n", argv[0]);
        return 1;
    }

    utils_sigact();
    utils_set_rlimits();

    __SKEL_DEFINE(sockaddr, skel);
    skel = __BPF_OPEN_AND_LOAD(sockaddr);
    __BPF_ATTACH(sockaddr, skel);

    int cgrpfd = open(argv[1], O_RDONLY);
    if (cgrpfd < 0) {
        fprintf(stderr, "Failed to open %s\n", argv[1]);
        goto clean;
    }

    bpf_program__attach_cgroup(skel->progs.sock_create_filter, cgrpfd);

    while (!utils_should_exit()) {
        sleep(10);
    }

clean:
    __BPF_DETACH_AND_DESTROY(sockaddr, skel);

    return 0;
}