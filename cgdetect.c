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
        case CGROUP_MEM_TRIG:
            printf("comm:%s group_id:%d out of memory!\n", e->comm, e->id);
            break;
        case CGROUP_OOM:
            printf("comm:%s group_id:%d memory trigger!\n", e->comm, e->id);
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

static int show_help(void)
{
    printf( "Usage: cgdetect [<flags>]\n\n"
            "-h --help  : Show this message\n"
            "-g --group : Specific cgroup to be listen\n"
            "-m --memory: Memory usage warning threshold\n"
            "-s --swap  : Swap usage warning threshold\n"
            );

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

static const char *s_opts = "hg:m:s:";
static int group_add(struct cgdetect_bpf *skel, int argc, char **argv)
{
    int opt;
    int option_index = 0;
    int cgroup_id = 0;
    struct mem_stat m = {0};

    if (argc < 2) {
        return 0; // TODO only detect create and destroy
    }

    struct option long_opt[] = {
        {"help", no_argument, NULL, 'h'},
        {"group", optional_argument, NULL, 'g'},
        {"memory", optional_argument, NULL, 'm'},
        {"swap", optional_argument, NULL, 's'},
        {},
    };

    while ((opt = getopt_long(argc, argv, s_opts, long_opt, &option_index)) != -1) {
        switch (opt)
        {
            case 'h':
                show_help();
                exit(0);
                break;
            case 'g':
                cgroup_id = get_group_fd(optarg);
                break;
            case 'm':
                m.mem_pages = parse_memory_pages(optarg);
                break;
            case 's':
                m.swap_pages = parse_memory_pages(optarg);
                break;
            default:
                show_help();
                exit(0);
                break;
        }
    }

    printf("Add group_id:%d mem(pages):%d swap:%d to monitor!\n",
            cgroup_id, m.mem_pages, m.swap_pages);

    bpf_map_update_elem(bpf_map__fd(skel->maps.filters), &cgroup_id, &m, 0);
    return 0;
}

int main(int argc, char **argv)
{
    struct ring_buffer *rb = NULL;
    int err;

    if (utils_set_rlimits()) {
        return 1;
    }

    utils_sigact();
    cgroup_version_check();

    __SKEL_DEFINE(cgdetect, skel);
    skel = __BPF_OPEN_AND_LOAD(cgdetect);
    __BPF_ATTACH(cgdetect, skel);

    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handler_event, NULL, NULL);
    if (!rb) {
        err = -1;
        goto clean;
    }

    group_add(skel, argc, argv);

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
