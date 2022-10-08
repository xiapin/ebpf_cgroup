#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

int _version SEC("version") = 1;

// https://tool.520101.com/wangluo/ipjisuan/
#define SRC1_IP4                0xAC100001U /* 172.16.0.1 */
#define SRC2_IP4                0x00000000U
#define SRC_REWRITE_IP4         0x7f000004U
#define DST_IP4                 0xC0A801FEU /* 192.168.1.254 */
#define DST_REWRITE_IP4         0x7f000001U
#define DST_PORT                4040
#define DST_REWRITE_PORT4       4444

SEC("cgroup/sendmsg4")
int sendmsg_v4_prog(struct bpf_sock_addr *ctx)
{
        if (ctx->type != SOCK_DGRAM) // udp
                return 0;
#if 0
        /* Rewrite source. */
        if (ctx->msg_src_ip4 == bpf_htonl(SRC1_IP4) ||
            ctx->msg_src_ip4 == bpf_htonl(SRC2_IP4)) {
                ctx->msg_src_ip4 = bpf_htonl(SRC_REWRITE_IP4);
        } else {
                /* Unexpected source. Reject sendmsg. */
                return 0;
        }

        /* Rewrite destination. */
        if ((ctx->user_ip4 >> 24) == (bpf_htonl(DST_IP4) >> 24) &&
             ctx->user_port == bpf_htons(DST_PORT)) {
                ctx->user_ip4 = bpf_htonl(DST_REWRITE_IP4);
                ctx->user_port = bpf_htons(DST_REWRITE_PORT4);
        } else {
                /* Unexpected source. Reject sendmsg. */
                return 0;
        }
#endif
        return 0;
}

SEC("cgroup/connect4")
int connect4(struct bpf_sock_addr *ctx)
{
//     struct sockaddr_in sa = {};
//     struct svc_addr *orig;

//     /* Force local address to 127.0.0.1:22222. */
//     sa.sin_family = AF_INET;
//     sa.sin_port = bpf_htons(22222);
//     sa.sin_addr.s_addr = bpf_htonl(0x7f000001);

//     if (bpf_bind(ctx, (struct sockaddr *)&sa, sizeof(sa)) != 0)
//         return 0;

//     /* Rewire service 1.2.3.4:60000 to backend 127.0.0.1:60123. */
//     if (ctx->user_port == bpf_htons(60000)) {
//         orig = bpf_sk_storage_get(&service_mapping, ctx->sk, 0,
//                                 BPF_SK_STORAGE_GET_F_CREATE);
//         if (!orig)
//             return 0;

//         orig->addr = ctx->user_ip4;
//         orig->port = ctx->user_port;

//         ctx->user_ip4 = bpf_htonl(0x7f000001);
//         ctx->user_port = bpf_htons(60123);
//     }

    // (net)0x50505df -> (host)0xdf050505 -> 223.5.5.5
    if (ctx->user_ip4 == 0x50505df) {
        bpf_printk("access denied: ip:0x%x port:%d\n", bpf_ntohl(ctx->user_ip4), ctx->user_port);
        return 0;
    }

    return 1;
}