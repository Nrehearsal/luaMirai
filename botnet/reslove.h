#ifndef RESOLVE_H
#define RESOLVE_H
#include <stdint.h>

void reslove_dns_lookup(const char* domain, ipv4_t* target_ip);

#endif
