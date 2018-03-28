#ifndef DNS_FORMAT_H
#define DNS_FORMAT_H
#include <stdint.h>

struct dns_header{
	uint16_t id, flags, question_count, answer_count, auth_count, addit_count;
};
struct dns_question{
	uint16_t query_type, query_class;
};

//GCC parameter--->not aligned
struct dns_resource{
	uint16_t qtype, qclass;
	uint32_t ttl;
	uint16_t data_len;
}__attribute__((packed));


#define DNS_QUERY_TYPE 1
#define DNS_QUERY_CLASS 1
#endif
