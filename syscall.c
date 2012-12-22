#include <linux/kernel.h>
#include <linux/module.h>

#include "kernel_variables.h"
#include "syscall.h"

int sys_call_table_pte_perm;

int set_addr_rw(unsigned long addr)
{
  unsigned int level;
  int result;

  // Get the page table entry
  pte_t* pte = lookup_address(addr, &level);

  // Save the permissions
  result = pte->pte;

  // Set the new permissions
  pte->pte |= _PAGE_RW;

  return result;
}

// Restore page table permissions
void set_pte_permissions(unsigned long addr, int perm)
{
  unsigned int level;

  // Get the page table entry
  pte_t* pte = lookup_address(addr, &level);

  // Set the new permissions
  pte->pte = perm;
}

inline void syscall_table_modify_begin(void)
{
  sys_call_table_pte_perm = set_addr_rw((unsigned long) get_syscall_table_addr());
}

inline void syscall_table_modify_end(void)
{
  set_pte_permissions((unsigned long) get_syscall_table_addr(), sys_call_table_pte_perm);
}
