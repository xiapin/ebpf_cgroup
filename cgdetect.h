#ifndef __CGDETECT_H__
#define __CGDETECT_H__

#define COMM_LEN        16
#define CGRP_PATH_LEN   128

enum CGROUP_EVENT {
    CGROUP_DESTROY      = 0,
    CGROUP_CREATE,
    CGROUP_MEM_TRIG,
    CGROUP_OOM,
};

struct event {
    enum CGROUP_EVENT e_type; // 1.create 0.destroy 2.beyond
    int root;
    int id;
    int level;
    char comm[COMM_LEN];
    char path[CGRP_PATH_LEN];
};

struct mem_stat {
    long unsigned int mem_pages;
    long unsigned int swap_pages;
    long unsigned int last_ts;
};

#endif
