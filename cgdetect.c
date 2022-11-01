#include <argp.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/stat.h>
#include <sys/vfs.h>

#include "bpf_utils.h"
#include "cgdetect.h"
#include "cgdetect.skel.h"

static int cgroupV2 = 0;
static unsigned int cgroup_id = 0;
static struct filters g_filter =
        {LONG_MAX, LONG_MAX, LONG_MAX, LONG_MAX, LONG_MAX, LONG_MAX};
static int report_interval_us = 100000; // default 100ms

static void cgroup_version_check(void)
{
#define CGROUP2_SUPER_MAGIC 0x63677270
    struct statfs buf;

    statfs("/sys/fs/cgroup", &buf);
    if (buf.f_type == CGROUP2_SUPER_MAGIC) {
        cgroupV2 = 1;
    }
}

static int handler_event(void *ctx, void *data, size_t data_sz)
{
    const struct event *e = data;

    switch (e->e_type) {
        case CGROUP_EPOLL_FDS:
            printf("comm:%s group_id:%d epoll fds beyond!\n", e->comm, e->id);
            break;
        case CGROUP_UNIX_SOCKETS:
            printf("comm:%s group_id:%d unix socket beyond!\n", e->comm, e->id);
            break;
        case CGROUP_PIDS:
            printf("comm:%s group_id:%d child processes beyond!\n", e->comm, e->id);
            break;
        case CGORUP_FILES:
            printf("comm:%s group_id:%d open files beyond!\n", e->comm, e->id);
            break;
        case CGROUP_MEM_RECLAIM:
            printf("comm:%s group_id:%d memory reclaim!\n", e->comm, e->id);
            break;
        case CGROUP_MEM_TRIG:
            printf("comm:%s group_id:%d memory trigger!\n", e->comm, e->id);
            break;
        case CGROUP_OOM:
            printf("comm:%s group_id:%d out of memory!\n", e->comm, e->id);
            break;
        case CGROUP_CREATE:
        case CGROUP_DESTROY:
            if (cgroupV2 || (!cgroupV2 && e->root == 1))
                fprintf(stderr, "%d\t%s\n", e->e_type, e->path);
            break;
        default:
            break;
    }
#if 0
    fprintf(stderr, "handle cgroup %s : root:%d id:%d level:%d path:%s\n",
            e->create ? "created" : "destroyed",
            e->root, e->id,
            e->level, e->path);
#endif

    return 0;
}

static int get_group_fd(const char *path)
{
    struct stat st;

    if (stat(path, &st)) {
        printf("file %s not exit!\n", path);
        return -1;
    }

    return st.st_ino;
}

static __u64 parse_memory_pages(const char *desc)
{
    __u64 bytes = 0;
    char c[4];

    sscanf(desc, "%ld%s", &bytes, c);
    if (c[0] == 'm' || c[0] == 'M') {
        bytes = bytes * 1024 * 1024;
    } else if (c[0] == 'k' || c[0] == 'K') {
        bytes = bytes * 1024;
    } else if (c[0] == 'g' || c[0] == 'G') {
        bytes = bytes * 1024 * 1024 * 1024;
    }

    return (bytes / 4096);
}

static int show_help(void)
{
    printf( "Usage: cgdetect [<flags>]\n\n"
            "-h --help              : Show this message\n"
            "-g --group=[path]      : Specific cgroup to be listen\n"
            "-m --memory=[M/G/K]    : Memory usage warning threshold\n"
            "-s --swap=[M/G/K]      : Swap usage threshold\n"
            "-f --files=count       : Open files threshold\n"
            "-p --pids=count        : Child processes threshold\n"
            "-e --epfd=count        : Epoll fds threshold\n"
            "-u --unix=count        : Unix sockets threshold\n"
            "-i --interval=us       : Set report interval\n"
            );

    return 0;
}

#ifndef LONG_MAX
#define LONG_MAX	((long)(~0UL >> 1))
#endif

static const char *s_opts = "hg:m:s:f:p:e:u:i:";
static struct option long_opt[] = {
    {"help", no_argument, NULL, 'h'},
    {"group", optional_argument, NULL, 'g'},
    {"memory", optional_argument, NULL, 'm'},
    {"swap", optional_argument, NULL, 's'},
    {"files", optional_argument, NULL, 'f'},
    {"pids", optional_argument, NULL, 'p'},
    {"epfd", optional_argument, NULL, 'e'},
    {"unix", optional_argument, NULL, 'u'},
    {"interval", optional_argument, NULL, 'i'},
};

static int argv_parse(int argc, char **argv)
{
    int opt;
    int option_index = 0;

    if (argc < 2) {
        return 0; // TODO only detect create and destroy
    }

    while ((opt = getopt_long(argc, argv, s_opts, long_opt, &option_index)) != -1) {
        switch (opt)
        {
            case 'h':
                show_help();
                exit(0);
                break;
            case 'g':
                cgroup_id = get_group_fd(optarg);
                printf("cgroup_id:%d ", cgroup_id);
                break;
            case 'm':
                g_filter.mem_pages = parse_memory_pages(optarg);
                printf("mem pages:%d ", g_filter.mem_pages);
                break;
            case 's':
                g_filter.swap_pages = parse_memory_pages(optarg);
                printf("swap pages:%d ", g_filter.swap_pages);
                break;
            case 'f':
                g_filter.files = atoll(optarg);
                printf("open files:%d ", g_filter.files);
                break;
            case 'p':
                g_filter.pids = atoll(optarg);
                printf("pids:%d ", g_filter.pids);
                break;
            case 'e':
                g_filter.epoll_fds = atoll(optarg);
                printf("epoll fds:%ld ", g_filter.epoll_fds);
                break;
            case 'u':
                g_filter.unix_sockets = atoll(optarg);
                printf("unix sockets:%ld ", g_filter.unix_sockets);
                break;
            case 'i':
                report_interval_us = atoll(optarg);
                break;
            default:
                show_help();
                exit(0);
                break;
        }
    }

    printf("to monitor!\n");

    return 0;
}

int main(int argc, char **argv)
{
    struct ring_buffer *rb = NULL;
    int err;

    argv_parse(argc, argv);

    if (utils_set_rlimits()) {
        return 1;
    }

    utils_sigact();
    cgroup_version_check();

    __SKEL_DEFINE(cgdetect, skel);
    skel = __BPF_OPEN(cgdetect);
    skel->rodata->report_interval_us = report_interval_us;

    __BPF_LOAD(cgdetect, skel);
    __BPF_ATTACH(cgdetect, skel);

    if (cgroup_id) {
        bpf_map_update_elem(bpf_map__fd(skel->maps.filters), &cgroup_id, &g_filter, 0);
    }

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
    __BPF_DETACH_AND_DESTROY(cgdetect, skel);

    return 0;
}
