#include <argp.h>
#include <bpf/libbpf.h>
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
#if 0
    fprintf(stderr, "handle cgroup %s : root:%d id:%d level:%d path:%s\n",
            e->create ? "created" : "destroyed",
            e->root, e->id,
            e->level, e->path);
#endif
    if (cgroupV2 || (!cgroupV2 && e->root == 1))
        fprintf(stderr, "%d\t%s\n", e->create, e->path);

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
