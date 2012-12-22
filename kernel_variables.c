#include "kernel_variables.h"

KVAR(void**, sys_call_table);
KVAR(struct list_head*, modules);
KVAR(struct proc_dir_entry*, proc_root);
