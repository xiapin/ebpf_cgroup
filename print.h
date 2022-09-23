#ifndef __PRINT_H__
#define __PRINT_H__

#define CONTENT_LEN     (128*1024)
#define COMM_LEN        16

struct data_t {
    int count;
    char buf[CONTENT_LEN];
};

#endif