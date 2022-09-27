#include "sysctl.skel.h"
#include <signal.h>
#include <fcntl.h>
#include <bpf/libbpf.h>
#include <unistd.h>
#include <sys/resource.h>
#include <stdlib.h>

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}

static void sig_act(void)
{
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
}

int main(int argc, char **argv)
{
    int err;
    struct sysctl_bpf *skel;

    if (argc != 2) {
        printf("usage: %s cgroup\n", argv[0]);
        return 1;
    }
    sig_act();

    struct rlimit rlim = {
        .rlim_cur = 512UL << 20, /* 512MB */
        .rlim_max = 512UL << 20,
    };
    if (setrlimit(RLIMIT_MEMLOCK, &rlim)) {
        fprintf(stderr, "set rlimit error!\n");
        return 1;
    }

    skel = sysctl_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton!\n");
        return 1;
    }

    err = sysctl_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach skeleton\n");
        return 1;
    }


    int cgrpfd = open(argv[1], O_RDONLY);
    if (cgrpfd < 0) {
        fprintf(stderr, "Failed to open %s\n", argv[1]);
        goto clean;
    }

    if (bpf_program__attach_cgroup(skel->progs.sysctl_w_deny, cgrpfd)) {
        fprintf(stderr, "Failed to attach cgroup!\n");
	goto clean;
    }

    while (!exiting) {
        sleep(10);
    }

clean:
    sysctl_bpf__detach(skel);
    sysctl_bpf__destroy(skel);

    return 0;
}
