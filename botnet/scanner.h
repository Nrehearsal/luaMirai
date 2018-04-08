#ifndef SCANNER_H
#define SCANNER_H

#define scan_port 23

#include "customize.h"
struct host_info{
	ipv4_t hostip;
	char username[32];
	char password[32];
	uint8_t username_len;
	uint8_t password_len;
}; 
#define PER_TIME_MAX 128

#endif
