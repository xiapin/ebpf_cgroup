#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("cgroup/sock_addr")
int sock_create_filter(struct bpf_sock_addr_kern *ctx)
{
    struct sockaddr *uaddr;
    char addr[16];
    unsigned short type;

    uaddr = BPF_CORE_READ(ctx, uaddr);
    type = BPF_CORE_READ(ctx, uaddr, sa_family);
    bpf_probe_read_user_str(&addr, sizeof(addr), uaddr->sa_data);

    // bpf_probe_read_user_str(&addr, sizeof(addr), );
    bpf_printk("type:%d addr:%s\n", type, addr); // sock addr need bind!!

    return 1; // 1:success
}

// SEC("cgroup/sock")
// int sk_create(struct sock *sk)
// {
// #if 0 // see ./include/linux/socket.h
//  *  AF_UNSPEC       0
//  *  AF_UNIX         1
//  *  AF_LOCAL        1
//  *  AF_INET         2
//  *  AF_AX25         3
//  *  AF_IPX          4
//  *  AF_APPLETALK    5
//  *  AF_NETROM       6
//  *  AF_BRIDGE       7
// #endif
//     short int type = BPF_CORE_READ(sk, sk_socket, type); // sk->sk_socket->type;
//     bpf_printk("socket create type:%d\n", type);

//     // if (type == 2) {
//     //     return 0;
//     // }

//     return 1; // 0.forbidden
// }