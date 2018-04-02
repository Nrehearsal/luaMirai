#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <string.h>
#include <errno.h>


#include "includes.h"
#include "dns_format.h"
#include "reslove.h"

//Refer to the DNS protocol manual for more details.
//----------------DNS_PACKET--------------------/
//----------------------------------------------/
//----------------dns_header--------------------/
//----------------query_domain_name-------------/
//----------------dns_question------------------/
//----------------dns_answer_name_pointer-------/
//----------------dns_resource------------------/
//----------------dns_answer_address/CNAME...---/

static struct dns_header *dnsh = NULL; 
static char *dns_query_name = NULL;
static struct dns_question *dnsq = NULL; 
static struct dns_resource *dnsr = NULL;
static char *dns_answer_name = NULL;
static uint8_t *dns_answer_address = NULL;

static uint16_t dns_header_id = 0;


/*Example:
 *dns_query_name: www.baidu.com
 *After Fill: 3www5baidu4com0
 */
static void reslove_fill_dns_query_name(char* dns_query_name_space, const char* src_domain)
{
	int i = 0;
	int current_len = 0;
	int domain_len = strlen(src_domain) + 1;
	//start with length of each period of domain string
	char* start_number_packet = dns_query_name_space;
	//start with character for domain string
	char* start_char_packet = dns_query_name_space+1;

	char nowchar = 0;

	for(i = 0; i < domain_len; i++)
	{
		nowchar = *src_domain++;	
		if (nowchar == '.' || nowchar == 0)
		{
			*start_number_packet = current_len;
			start_number_packet = start_char_packet++;
			current_len = 0;	
		}
		else
		{
			*start_char_packet++ = nowchar;	
			current_len++;
		}
	}
	*start_char_packet = 0;
}

static int reslove_fill_request_packet(char* packet, const char* domain)
{
	//file dns_header
	dnsh = (struct dns_header*)packet;
	//id
	dns_header_id = 0x142f;
	dnsh->id = dns_header_id;
	//flags
	//00000001 00000000
	//Recursion desired
	dnsh->flags = htons(1 << 8);
	//Questions
	dnsh->question_count = htons(1);
	//Answer RRs
	dnsh->answer_count= htons(0);
	//Authority RRs
	dnsh->auth_count = htons(0);
	//Additional RRs
	dnsh->addit_count = htons(0);

	//dns_query_name = response + offset(sizeof(struct dns_header))
	dns_query_name = (char*)(dnsh + 1);
	reslove_fill_dns_query_name(dns_query_name, domain);

	//fill dns_question dnsq = sizeof(dnst) + strlen(dns_query_name) + 1
	dnsq = (struct dns_question*)(dns_query_name + strlen(dns_query_name) + 1);
	dnsq->query_type = htons(DNS_QUERY_TYPE);
	dnsq->query_class = htons(DNS_QUERY_CLASS);

	return sizeof(struct dns_header) + strlen(dns_query_name) + 1 + sizeof(struct dns_question);
}

static BOOL reslove_checkresponse(const char* response, const int response_packet_len, const int request_packet_len)
{
	if (response_packet_len < request_packet_len)
	{
		return FALSE;	
	}

	dnsh = (struct dns_header*)response;
	//See DNS protocol for more detial;	
	if (dnsh->id != dns_header_id || dnsh->answer_count == 0)
	{
		return FALSE;	
	}

	return TRUE;
}

static void reslove_unbox_response_packet(const char* response, ipv4_t* target_ip)
{
	/*static struct dns_header *dnsh = NULL; 
	 * static char *dns_query_name = NULL;
	 * static struct dns_question *dnsq = NULL; 
	 */
	int dns_query_name_len = strlen(dns_query_name) + 1;

	dnsh = (struct dns_header*)response;
	dns_query_name = (char*)(dnsh+1);
	dnsq = (struct dns_question*)(dns_query_name + dns_query_name_len);
	dns_answer_name = (char*)(dnsq+1);
	
	uint16_t answer_count = ntohs(dnsh->answer_count);
	//fetch answer
	while(answer_count-- > 0)
	{
		/*each name space occupated 2 bytes of a dns response packet
		 *---------------------answer_ares-------------------------/
		 *--------------------name_pointer------------------------/
		 *--------------------dns_answer_resource------------------/
		 *--------------------data/CNAME/...-----------------------/
		 */

		dnsr = (struct dns_resource*)(dns_answer_name+2);
		dns_answer_address = (uint8_t*)(dnsr+1);
		if (ntohs(dnsr->qtype) == DNS_QUERY_TYPE && ntohs(dnsr->qclass) == DNS_QUERY_CLASS && ntohs(dnsr->data_len) == 4)
		{
			uint8_t tmp_buf[4];
			for (int i =0; i < 4; i++)
			{
				tmp_buf[i] = dns_answer_address[i];	
				//printf("%d\n", tmp_buf[i]);
			}
			//&target_ip = (uint32_t *)tmp_buf;
			memcpy(target_ip, tmp_buf, sizeof(tmp_buf));
			break;
		}
		else
		{
			//go to next answer snippet	
			*target_ip = 0;
			printf("[Reslove]len--------------%d\n", ntohs(dnsr->data_len));
			dns_answer_name = (char*)(dns_answer_address + ntohs(dnsr->data_len));
		}
	}
}

void reslove_dns_lookup(const char* domain, ipv4_t* target_ip)
{
	*target_ip = 0;
	int fd = -1;
	int ret;
	struct sockaddr_in dns_serv_addr;
	int attempts = 0;
	char request[2048], response[2048];

	//prepare the data
	int packet_len = reslove_fill_request_packet(request, domain);

	bzero(&dns_serv_addr, sizeof(struct sockaddr_in));
	dns_serv_addr.sin_family = AF_INET;
	dns_serv_addr.sin_addr.s_addr = INET_ADDR(8,8,8,8);
	dns_serv_addr.sin_port = htons(53);

	while(attempts++ < 5)
	{
		fd_set fdset;
		struct timeval timeline;	
		int nfds = 0;
		if (fd != -1)
		{
			close(fd);	
		}

		fd = socket(AF_INET, SOCK_DGRAM, 0);
		if (fd == -1)
		{
			printf("[Reslove]Failed to create a new socket, errno:%d\n", errno);
			sleep(1);
			continue;
		}

		ret = connect(fd, (struct sockaddr*)&dns_serv_addr, sizeof(struct sockaddr_in));
		if (ret == -1)
		{
			printf("[reslove]Failed to connect to dns_server, errno:%d\n", errno);	
			sleep(1);
			continue;
		}

		ret = send(fd, request, packet_len, MSG_NOSIGNAL);
		if (ret == -1)
		{
			printf("[Reslove]Failed to send query packet, errno:%d\n", errno);	
			sleep(1);
			continue;
		}

		//initialize the parmater
		fcntl(F_SETFL, fd, O_NONBLOCK|fcntl(F_GETFL, fd, 0));

		FD_ZERO(&fdset);
		FD_SET(fd, &fdset);
		timeline.tv_usec = 0;
		timeline.tv_sec = 5;

		/*For better performance
		 *use select to deal with dns protocol data packet;
		 */
		nfds = select(fd+1, &fdset, NULL, NULL, &timeline);
		if (nfds == -1)
		{
			printf("[Reslove]Select failed\n");
			break;		
		}
		else if (nfds == 0)
		{
			printf("[Reslove]Cat not resolve %s to ip_addr After %d attempts\n", domain, attempts);	
			*target_ip = 0;
			continue;
		}
		else if(FD_ISSET(fd, &fdset))
		{
			printf("[Reslove]Get response from DNS server\n");
			ret = recvfrom(fd, response, sizeof(response), MSG_NOSIGNAL, NULL, NULL);	

			//Detect whether a valid data packet
			if(reslove_checkresponse(response, ret, packet_len))
			{
				printf("[Reslove]Response data from dns server is vailed, Try to unbox packet\n");
				//unbox response
				reslove_unbox_response_packet(response, target_ip);
				break;
			}
			else
			{
				*target_ip = 0;
				continue;	
			}
		}
	}
	close(fd);
}

/*int main(int argc, char** argv)
{
	ipv4_t target_ip = 0;
	struct in_addr netbyte;
	reslove_dns_lookup(argv[1], &target_ip);
	//printf("%d\n", target_ip);
	netbyte.s_addr = target_ip;
	printf("Find domain host:%s\n", inet_ntoa(netbyte));

	return 0;
}*/
