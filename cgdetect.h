#ifndef __CGDETECT_H__
#define __CGDETECT_H__

#define COMM_LEN        16
#define CGRP_PATH_LEN   128

enum CGROUP_EVENT {
    CGROUP_DESTROY      = 0,
    CGROUP_CREATE,
    CGROUP_MEM_TRIG,
    CGROUP_MEM_RECLAIM,
    CGROUP_OOM,
    CGORUP_FILES,
    CGROUP_PIDS,
    CGROUP_EPOLL_FDS,
    CGROUP_UNIX_SOCKETS,
};

struct event {
    enum CGROUP_EVENT e_type;
    int root;
    int id;
    int level;
    char comm[COMM_LEN];
    char path[CGRP_PATH_LEN];
};

struct filters {
    long unsigned int files;
    long unsigned int mem_pages; // memory
    long unsigned int pids;
    long unsigned int swap_pages;
    long unsigned int last_ts;
    long unsigned int epoll_fds;
    long unsigned int unix_sockets;
};

#endif
