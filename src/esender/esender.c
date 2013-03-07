#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <signal.h>
#include <pthread.h>
#include <time.h>
#include <errno.h>

#include <curl/curl.h>

#include "defs.h"
#include "liblog.h"
#include "libdns.h"

#define EMAIL_MAX_LEN DNS_DOMAIN_MAX_LEN
typedef struct email_info_t {
    UINT8 from[EMAIL_MAX_LEN];
    UINT8 to[EMAIL_MAX_LEN];

    UINT8 smtp[EMAIL_MAX_LEN];
    UINT8 e_file[EMAIL_MAX_LEN];
}email_info_t;
static email_info_t g_e_info = {0};

static UINT8 *g_dns_ips[DNS_DOMAIN_MAX_LEN] = {
    (UINT8 *)"8.8.8.8",
    (UINT8 *)"8.8.4.4",
};

static int esender_dns_callback(UINT8 *domain, UINT8 *rel, dns_ans_t *dns_ans)
{
    if (0 == strlen(g_e_info.smtp))
    {
        snprintf(g_e_info.smtp, EMAIL_MAX_LEN, "smtp://%s:25", rel);
    }
    return R_OK;
}

static size_t read_email(void *ptr, size_t size, size_t nmemb, void *userp)
{
    size_t read;
    char *line = NULL;
    size_t len = 0;

    read = getline(&line, &len, (FILE*)userp);

    if (-1 == read)
    {
        if (line)
            free(line);
        fclose((FILE*)userp);
        return 0;
    }

    memcpy(ptr, line, read);
    if (line)
        free(line);

    PRINTF(LEVEL_DEBUG, "read [%d] bytes.\n", read);
    return read;
}

static void help()
{
    printf("Usage : esender [OPTIONS]\n");
    printf("    -f <address>    sender email address\n");
    printf("    -t <address>    receiver email address\n");
    printf("    -e <file>       file name include email content\n");
    printf("    -h              print helo infomation\n");
}

int main(int argc, char **argv)
{
    CURL *curl;
    CURLcode res;
    struct curl_slist *recipients = NULL;
    int ch;

    FILE *fp = NULL;
    
    //liblog_level(1);

    while ((ch = getopt(argc, argv, ":f:t:e:h")) != -1)
    {
        switch (ch)
        {
            case 'f':
                snprintf(g_e_info.from, EMAIL_MAX_LEN, "%s", optarg);
                break;
            case 't':
                snprintf(g_e_info.to, EMAIL_MAX_LEN, "%s", optarg);
                break;
            case 'e':
                snprintf(g_e_info.e_file, EMAIL_MAX_LEN, "%s", optarg);
                break;
            case 'h':
            default:
                help();
                return -1;
                break;
        }
    }
    if (strlen(g_e_info.from) == 0) { help(); return -1; }
    if (strlen(g_e_info.to) == 0) { help(); return -1; }
    if (strlen(g_e_info.e_file) == 0) { help(); return -1; }


    fp = fopen(g_e_info.e_file, "rb");
    if (NULL == fp)
    {
        PRINTF(LEVEL_ERROR, "fopen [%s] error.\n", g_e_info.e_file);
        return -1;
    }
    
    libdns_init(g_dns_ips, 2, esender_dns_callback);sleep(1);

    UINT8 *dst_domain = strstr(g_e_info.to, "@");
    if (NULL == dst_domain)
    {
        PRINTF(LEVEL_ERROR, "destination email address not valid.\n");
        return -1;
    }
    libdns_query(dst_domain + 1);sleep(1);

    if (0 == strlen(g_e_info.smtp))
    {
        PRINTF(LEVEL_ERROR, "get mx record error.\n");
        return -1;
    }
    PRINTF(LEVEL_INFORM, "got smtp server : [%s].\n", g_e_info.smtp);

    curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, g_e_info.smtp);

        curl_easy_setopt(curl, CURLOPT_MAIL_FROM, g_e_info.from);

        recipients = curl_slist_append(recipients, g_e_info.to);
        curl_easy_setopt(curl, CURLOPT_MAIL_RCPT, recipients);

        curl_easy_setopt(curl, CURLOPT_READFUNCTION, read_email);
        curl_easy_setopt(curl, CURLOPT_READDATA, fp);

        curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

        res = curl_easy_perform(curl);
        if(res != CURLE_OK)
            fprintf(stderr, "curl_easy_perform() failed: %s\n",
                curl_easy_strerror(res));

        curl_slist_free_all(recipients);
        curl_easy_cleanup(curl);
    }

    return 0;
}