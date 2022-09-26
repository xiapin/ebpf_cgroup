#include <signal.h>
#include <argp.h>
#include <bpf/libbpf.h>
#include <unistd.h>
#include <stdio.h>
#include <getopt.h>
#include <sys/resource.h>

#include "print.h"
#include "print.skel.h"

struct {
    char comm[COMM_LEN];
    int pid;
} dump_process; // filter pid or process name

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
    struct print_bpf *skel;
    int err;

    struct rlimit rlim = {
        .rlim_cur = 512UL << 20, /* 512MB */
        .rlim_max = 512UL << 20,
    };
    if (setrlimit(RLIMIT_MEMLOCK, &rlim)) {
        fprintf(stderr, "set rlimit error!\n");
        return 1;
    }

    sig_act();
    if (parse_args(argc, argv)) {
        return 1;
    }

    skel = print_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton!\n");
        return 1;
    }

    skel->bss->my_pid = dump_process.pid;
    strncpy((char *)skel->bss->filter, dump_process.comm, COMM_LEN);
    err = print_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        return 1;
    }

    err = print_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach skeleton\n");
        return 1;
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handler_event, NULL, NULL);
    if (!rb) {
        err = -1;
        goto clean;
    }

    while (!exiting) {
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
    print_bpf__destroy(skel);

    return 0;
}