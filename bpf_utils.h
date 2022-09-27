#ifndef _BPF_UTILS_H_
#define _BPF_UTILS_H_

#include <stdio.h>

int utils_set_rlimits(void);
void utils_sigact(void);
int utils_should_exit(void);

#define __SKEL_DEFINE(name, var)\
        struct name##_bpf *var;

#define __BPF_OPEN(name)\
        ({\
            struct name##_bpf *__skel = name##_bpf__open();\
            if (!__skel) {\
                fprintf(stderr, "Failed to open %s BPF skeleton!\n", #name);\
                return 1;\
            }\
            __skel;\
        })

#define __BPF_LOAD(name, skel)\
        do {\
            if (name##_bpf__load(skel)) {\
                fprintf(stderr, "Failed to load %s skel!\n", #name);\
                return 1;\
            }\
        } while(0);

#define __BPF_OPEN_AND_LOAD(name)\
        ({\
            struct name##_bpf *__skel = __BPF_OPEN(name);\
            __BPF_LOAD(name, __skel);\
            __skel;\
        })

#define __BPF_ATTACH(name, skel)\
        do {\
            if (name##_bpf__attach(skel)) {\
                fprintf(stderr, "Failed to attach %s skel!\n", #name);\
                return 1;\
            }\
        } while(0);

#define __BPF_DETACH_AND_DESTROY(name, skel)\
        {name##_bpf__detach(skel);\
        name##_bpf__destroy(skel);}

#endif