#pragma once

#define SYSCTL_NAME_LEN 64
#define SYSCTL_VAL_LEN  32

struct data_t {
    unsigned long long tgid; // real_parent
    char sysctl_name[SYSCTL_NAME_LEN];
    char cur_value[SYSCTL_VAL_LEN];
    char new_value[SYSCTL_VAL_LEN];
    int write;
};