#include "sysctl.skel.h"
#include <signal.h>
#include <bpf/libbpf.h>
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
/*
openat(AT_FDCWD, "/sys/fs/cgroup", O_RDONLY) = 3
bpf(BPF_PROG_GET_FD_BY_ID, {prog_id=138, next_id=0, open_flags=0}, 120)
bpf(BPF_PROG_ATTACH, {target_fd=3, attach_bpf_fd=4, attach_type=BPF_CGROUP_DEVICE, attach_flags=BPF_F_ALLOW_OVERRIDE, replace_bpf_fd=0}, 120) 
*/
    while (!exiting) {
        sleep(10);
    }

clean:
    sysctl_bpf__detach(skel);
    sysctl_bpf__destroy(skel);

    return 0;
}
