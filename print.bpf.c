#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "print.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";
int my_pid = 0;
char filter[COMM_LEN];

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

SEC("kprobe/vfs_write")
int BPF_KPROBE(vfs_write, struct file *file, const char *buf, size_t count, loff_t *pos)
{
    int len = 0;
    struct data_t *e;
    char comm[COMM_LEN];
    int pid = bpf_get_current_pid_tgid() >> 32;

    bpf_get_current_comm(comm, COMM_LEN);
    if (my_pid != pid) {
        while (len++ < COMM_LEN - 1) {
            if (comm[len] != filter[len]) {
                return 0;
            }
        }
    }

    e = bpf_ringbuf_reserve(&rb, sizeof(struct data_t), 0);
    if (!e) {
        return 0;
    }

    e->count = CONTENT_LEN < count ? CONTENT_LEN : count;
    bpf_probe_read_user_str(&e->buf, e->count, buf);

    bpf_ringbuf_submit(e, 0);

    return 0;
}