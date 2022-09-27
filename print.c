#include <argp.h>
#include <bpf/libbpf.h>
#include <unistd.h>
#include <stdio.h>
#include <getopt.h>

#include "bpf_utils.h"
#include "print.h"
#include "print.skel.h"

struct {
    char comm[COMM_LEN];
    int pid;
} dump_process; // filter pid or process name

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static int handler_event(void *ctx, void *data, size_t data_sz)
{
    const struct data_t *d = data;

    printf("%s\n", d->buf);

    return 0;
}

static const char *short_opts = "hp:n:";

static void show_help(const char *self)
{
    printf("usage: %s [<flags>]\n\n"
           "-h,--help\t\tShow this help.\n"
           "-p,--pid\t\tSpecific process id.\n"
           "-n,--name\t\tSpecific process name\n", self);
}

static int parse_args(int argc, char **argv)
{
    int opt;
    int option_index = 0;

    struct option long_options[] = {
        {"help", no_argument, NULL, 'h'},
        {"pid", optional_argument, NULL, 'p'},
        {"name", optional_argument, NULL, 'n'},
    };

    while ((opt = getopt_long(argc, argv, short_opts, long_options, &option_index)) != -1) {
        switch (opt)
        {
        case 'n':
            strncpy(dump_process.comm, optarg, COMM_LEN);
            printf("specifc process name : %s\n", dump_process.comm);
            break;
        case 'p':
            dump_process.pid = atoi(optarg);
            printf("specific process pid : %d\n", dump_process.pid);
            break;
        case 'h':
        default:
            show_help(argv[0]);
            return -1;
        }
    }
    return 0;
}

int main(int argc, char **argv)
{
    struct ring_buffer *rb = NULL;
    int err;

    if (parse_args(argc, argv)) {
        return 1;
    }

    if (utils_set_rlimits()) {
        return 1;
    }
    utils_sigact();

    __SKEL_DEFINE(print, skel);
    skel = __BPF_OPEN(print);

    skel->bss->my_pid = dump_process.pid;
    strncpy((char *)skel->bss->filter, dump_process.comm, COMM_LEN);

    __BPF_LOAD(print, skel);
    __BPF_ATTACH(print, skel);

    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handler_event, NULL, NULL);
    if (!rb) {
        err = -1;
        goto clean;
    }

    while (!utils_should_exit()) {
        err = ring_buffer__poll(rb, 100); // timeout 100 ms
        if (err == -EINTR) {
            err = 0;
            break;
        }

        if (err < 0) {
            printf("Error polling perf buffer:%d\n", err);
            break;
        }
    }

clean:
    ring_buffer__free(rb);
    __BPF_DETACH_AND_DESTROY(print, skel);

    return 0;
}