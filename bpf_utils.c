#include <sys/resource.h>
#include <stdio.h>
#include <signal.h>

int utils_set_rlimits(void)
{
    struct rlimit rlim = {
        .rlim_cur = 512UL << 20, /* 512MB */
        .rlim_max = 512UL << 20,
    };

    if (setrlimit(RLIMIT_MEMLOCK, &rlim)) {
        fprintf(stderr, "set rlimit error!\n");
        return 1;
    }

    return 0;
}

static volatile int exiting = 0;

static void sig_handler(int sig)
{
	exiting = 1;
}

void utils_sigact(void)
{
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
}

int utils_should_exit(void)
{
    return exiting;
}