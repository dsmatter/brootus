#include <linux/kernel.h>
#include <linux/module.h>

#include "kernel_variables.h"

void** sys_call_table = NULL;
KVAR(struct list_head*, modules);
KVAR(struct proc_dir_entry*, proc_root);

void** get_syscall_table_addr_from_first_call(unsigned long handler_addr)
{
  unsigned char* p;

  // Search until the end of the following page
  unsigned char* end = (unsigned char*) ((handler_addr & ~(PAGE_SIZE-1)) + 2*PAGE_SIZE);

  for (p = (unsigned char*) handler_addr; p < end; p++) {
    // Search for the call instruction
    // Byte sequence: 0xff 0x14 0x85
    if (*p == 0xff && *(p+1) == 0x14 && *(p+2) == 0x85) {
      // Get the 32-bit displacement
      unsigned int* result = (unsigned int*) (p+3);
      return (void**) *result;
    }
  }
  // We didn't find it
  return NULL;
}

void** get_syscall_table_addr(void)
{
  void** result;
  unsigned long syscall_handler_addr;

  if (sys_call_table != NULL) {
    return sys_call_table;
  }

  // Get the address of the syscall handler function
  rdmsrl(MSR_IA32_SYSENTER_EIP, syscall_handler_addr);

  // Search the syscall table address
  result = get_syscall_table_addr_from_first_call(syscall_handler_addr);
  return result;
}
