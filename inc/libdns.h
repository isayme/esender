#ifndef _LIBDNS_H
#define _LIBDNS_H

#include "defs.h"

#define DNS_SERVER_PORT 53

#define DNS_DOMAIN_MAX_LEN 128

#define DNS_PKT_MAX_LEN 512
#define DNS_DOMAIN_MAX_OFFSET 63

#pragma pack(1)

typedef struct dns_hdr_t
{
    // ID，响应报文回应和请求报文一样的ID
    UINT16 id; // identification number
#define DNS_RD_YES  1 // 要求递归查询
    UINT8 rd :1; // recursion desired
#define DNS_TC_YES 1 // 截取的，出错
    UINT8 tc :1; // truncated message
#define DNS_AA_AUTH 1 // 授权应答，仅在响应报文有效
    UINT8 aa :1; // authoritive answer
#define DNS_OPC_STD 0   // 标准请求
#define DNS_OPC_RES 1   // 反向查询
#define DNS_OPC_SSR 2   // 服务器状态请求
    UINT8 opcode :4; // purpose of message
#define DNS_QR_REQ 0    // 查询报文
#define DNS_QR_RES 1    // 响应报文
    UINT8 qr :1; // query/response flag

#define DNS_RCCODE_OK 0
#define DNS_RCCODE_FERR 1
#define DNS_RCCODE_SERR 2   
#define DNS_RCCODE_NERR 3
    UINT8 rcode :4; // response code

    UINT8 z :3; // its z! reserved
#define DNS_RA_YES 1 // 服务端返回，以指定服务器是否可递归查询
    UINT8 ra :1; // recursion available
      
    UINT16 q_count; // number of question entries
    UINT16 ans_count; // number of answer entries
    UINT16 auth_count; // number of authority entries
    UINT16 add_count; // number of resource entries
}dns_hdr_t;

typedef struct dns_query_t {
#define DNS_QUERY_TYPE_A 1
#define DNS_QUERY_TYPE_AAAA 2
#define DNS_QUERY_TYPE_SRV 3
#define DNS_QUERY_TYPE_PTR 12
#define DNS_QUERY_TYPE_MX 15
    UINT16 q_type;
#define DNS_QER_CLS_INTENET 1
    UINT16 q_class;
}dns_query_t;

typedef struct dns_ans_t {
    UINT16 type;
    UINT16 class;
    UINT32 ttl;
    UINT16 dlen;
}dns_ans_t;

#pragma pack()

typedef int (*LIBDNS_CALLBACK)(UINT8 *domain, UINT8 *rel, dns_ans_t *dns_ans);

INT32 libdns_init(UINT8 **srv_ip, INT32 num, LIBDNS_CALLBACK func);
INT32 libdns_uninit();
INT32 libdns_query(UINT8 *domain);

#endif