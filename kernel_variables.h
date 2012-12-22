#ifndef KERNEL_VARIABLES_H
#define KERNEL_VARIABLES_H

#include "sysmap.h"

#define KVAR(type, name) type name = (type) rk_##name

extern void** sys_call_table;
extern struct list_head* modules;
extern struct proc_dir_entry* proc_root;

#endif
