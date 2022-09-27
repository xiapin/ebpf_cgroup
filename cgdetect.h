#ifndef __CGDETECT_H__
#define __CGDETECT_H__

#define COMM_LEN        16
#define CGRP_PATH_LEN   128

struct event {
    int create; // 1.create 0.destroy
    int root;
    int id;
    int level;
    char comm[COMM_LEN];
    char path[CGRP_PATH_LEN];
};

#endif
