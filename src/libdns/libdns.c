#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <stdlib.h> 
#include <string.h>

#include "defs.h"
#include "liblog.h"
#include "libudp.h"
#include "libdns.h"

static UINT8 **g_srv_ips = NULL;
static INT32 g_srv_num = 0;
static LIBDNS_CALLBACK g_callback = NULL;


// 返回解码后第一个非MX域名记录的位置
static INT32 dns_get_mx_domain(UINT8 *pkt, INT32 pos, UINT8 *rel, INT32 rpos)
{
    INT32 i, ret;

    // 等于0说明已结束
    while (pkt[pos] != 0)
    {
        // 压缩的长度最长不可大于DNS_DOMAIN_MAX_OFFSET，如果大于，则与其之后一个字节共同指向一个字符串指针
        if (pkt[pos] <= DNS_DOMAIN_MAX_OFFSET)
        {
            // 递归调用此函数
            if (rpos)
            {
                rel[rpos] = '.';
                rpos++;
            }

            // 拷贝字符
            for (i = 0; i < pkt[pos]; i++)
            {
                rel[rpos + i] = pkt[pos + 1 + i];
            }
            // 更新字符下标
            rpos = rpos + pkt[pos];
            pos = pos + pkt[pos] + 1;
        }
        else
        {
            ret = pos + 2;

            pos = ntohs(*(UINT16 *)(pkt + pos)) & 0x3fff;
            dns_get_mx_domain(pkt, pos, rel, rpos);
            
            return ret;
        }
    }

    rel[rpos] = '\0';
    ret = pos + 1;
    return ret;
}

static INT32 dns_query(UINT8 *pkt, UINT8 *domain, UINT16 type)
{
    dns_hdr_t *dns_hdr= (dns_hdr_t *)pkt;
    dns_query_t *dns_query;
    UINT8 *d_tmp;
    INT32 cnt_pos, data_pos;

    memset(pkt, 0, DNS_PKT_MAX_LEN);
    dns_hdr->id = htons(random());
    dns_hdr->qr = DNS_QR_REQ;
    dns_hdr->opcode = DNS_OPC_STD;
    dns_hdr->rd = DNS_RD_YES;
    dns_hdr->q_count = htons(1);

    d_tmp = domain;
    cnt_pos = sizeof(dns_hdr_t);
    data_pos = sizeof(dns_hdr_t) + 1;

    while (*d_tmp != '\0')
    {
        if (*d_tmp != '.')
        {
            pkt[data_pos] = *d_tmp;
            data_pos += 1;
            pkt[cnt_pos] += 1;
        }
        else
        {
            cnt_pos = data_pos;
            data_pos += 1;
        }

        d_tmp++;
    }

    dns_query = (dns_query_t *)(pkt + data_pos + 1);
    dns_query->q_type = htons(DNS_QUERY_TYPE_MX);
    dns_query->q_class = htons(DNS_QER_CLS_INTENET);

    return data_pos + 1 + sizeof(dns_query_t);
}

static int dnsudp_callback(struct sockaddr addr, UINT8 *buff, INT32 blen)
{
    INT32 i;
    dns_hdr_t *dns_hdr = (dns_hdr_t *)buff;
    dns_query_t *dns_query = NULL;
    dns_ans_t *dns_ans;
    UINT8 *ans_ptr;
    UINT16 offset;
    static UINT8 rel[DNS_DOMAIN_MAX_LEN];
    static UINT8 domain[DNS_DOMAIN_MAX_LEN];

    if (dns_hdr->qr != DNS_QR_RES)
    {
        PRINTF(LEVEL_ERROR, "not respond pkt.\n");
        return R_ERROR;
    }
    if (ntohs(dns_hdr->ans_count) == 0)
    {
        PRINTF(LEVEL_ERROR, "respond count is [%d].\n", dns_hdr->ans_count);
        return R_ERROR;
    }

    ans_ptr = buff + sizeof(dns_hdr_t);

    if (1 != ntohs(dns_hdr->q_count)) return R_ERROR;   // 自定义的DNS请求只有一个

    for (i = 0; i < ntohs(dns_hdr->q_count); i++)
    {
        dns_get_mx_domain(buff, ans_ptr - buff, domain, 0);
        //PRINTF(LEVEL_DEBUG, "Domain : [%s].\n", domain);
        while (*ans_ptr != 0)
        {
            ans_ptr += (*ans_ptr + 1);
        }
        ans_ptr += 1;

        dns_query = (dns_query_t *)ans_ptr;
        ans_ptr += sizeof(dns_query_t);
    }

    PRINTF(LEVEL_DEBUG, "answer count = %d.\n", ntohs(dns_hdr->ans_count));
    for (i = 0; i < ntohs(dns_hdr->ans_count); i++)
    {
        // 压缩时
        if (*ans_ptr > DNS_DOMAIN_MAX_OFFSET)
        {
            ans_ptr += 2;
        }
        else
        {
            while (*ans_ptr != 0)
            {
                ans_ptr += (*ans_ptr + 1);
            }
            ans_ptr += 1;
        }

        dns_ans = (dns_ans_t *)ans_ptr;

        if (dns_ans->type != dns_query->q_type)
        {
            PRINTF(LEVEL_ERROR, "answer tpye [%d] not [%d].\n", dns_ans->type, dns_query->q_type);
            return R_ERROR;
        }

        ans_ptr = ans_ptr + sizeof(dns_ans_t) + 2; // add 2 byte for "preference"

        offset = ans_ptr - buff;

        ans_ptr = buff + dns_get_mx_domain(buff, offset, rel, 0);
        ((LIBDNS_CALLBACK)g_callback)(domain, rel, dns_ans);
        PRINTF(LEVEL_DEBUG, "Domain:[%s] MX = [%s].\n", domain, rel);
    }

    return R_OK;
}

INT32 libdns_init(UINT8 **srv_ip, INT32 num, LIBDNS_CALLBACK func)
{
    INT32 i;

    if (NULL == srv_ip || num <= 0)
    {
        PRINTF(LEVEL_ERROR, "arguments error.\n");
        return R_ERROR;
    }

    if (NULL != g_srv_ips)
    {
        PRINTF(LEVEL_WARNING, "somewhere already the module.\n");
        return R_OK;
    }

    g_srv_ips = malloc(num * sizeof(UINT8 *));
    if (NULL == g_srv_ips)
    {
        PRINTF(LEVEL_ERROR, "apply for memory error.\n");
        goto _err;
    }
    memset(g_srv_ips, 0, num * sizeof(UINT8 *));

    for (i = 0; i < num; i++)
    {
        if (strlen((char *)srv_ip[i]) <= 0)
        {
            goto _err;
        }

        g_srv_ips[i] = malloc(DNS_DOMAIN_MAX_LEN);
        if (NULL == g_srv_ips[i])
        {
            PRINTF(LEVEL_ERROR, "apply for memory error.\n");
            goto _err;
        }

        memset(g_srv_ips[i], 0, DNS_DOMAIN_MAX_LEN);
        strncpy((char *)g_srv_ips[i], (char *)srv_ip[i], DNS_DOMAIN_MAX_LEN);
    }

    g_srv_num = i;
    g_callback = func;

    udp_init(0, dnsudp_callback);

    return R_OK;
_err:
    libdns_uninit();

    return R_ERROR;
}

INT32 libdns_uninit()
{
    INT32 i;

    if (NULL != g_srv_ips)
    {
        for (i = 0; i < g_srv_num; i++)
        {
            if (NULL != g_srv_ips[i])
            {
                free(g_srv_ips[i]);
            }
        }

        free(g_srv_ips);
    }

    return R_OK;
}

INT32 libdns_query(UINT8 *domain)
{
    INT32 len;
    UINT8 pkt[DNS_PKT_MAX_LEN];
    static INT32 idx = 0;

    len = dns_query(pkt, domain, DNS_QUERY_TYPE_MX);
    if (R_ERROR == udp_send(g_srv_ips[idx++ % g_srv_num], (UINT16)DNS_SERVER_PORT, pkt, len))
    {
        PRINTF(LEVEL_ERROR, "udp send to [%s:%d] error.", g_srv_ips[idx % g_srv_num], DNS_SERVER_PORT);
        return R_ERROR;
    }

    return R_OK;
}
