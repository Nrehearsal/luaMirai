#include <stdint.h>
#include <netinet/ip.h>
#include <linux/tcp.h>
#include <sys/types.h>

uint16_t checksum_ip(uint16_t* tiph, int hlength)
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

uint16_t checksum_tcpudp(struct iphdr *iph, uint16_t *tcpudphd, uint16_t data_len)
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
