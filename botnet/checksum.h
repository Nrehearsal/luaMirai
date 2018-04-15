#ifndef CHECK_SUM_H
#define CHECK_SUM_H
#include <stdint.h>
#include <netinet/ip.h>
#include <linux/tcp.h>

uint16_t checksum_ip(uint16_t* tiph, int hlength);
uint16_t checksum_tcpudp(struct iphdr *iph, uint16_t *tcpudphd, uint16_t data_len);

#endif
