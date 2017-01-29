
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include <time.h>
#include <netinet/in.h>
#include <linux/types.h>

//Include header of netfilter, and libqueue for packet filtering
#include <linux/netfilter.h>        /* for NF_ACCEPT */
#include <libnetfilter_queue/libnetfilter_queue.h>


#define FN_ART "bear.art"
#define FN_CONFIG "bear.conf"

typedef int (*PTR_MOD_DETECT)(char*, size_t);
typedef int (*PTR_MOD_INIT)();

char *mod_name[100], *mod_fn[100];
unsigned char mod_loaded[100] = {0};
unsigned int mod_count = 0;

PTR_MOD_DETECT mod_detect[100] = {NULL};



static char encoding_table[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                                'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                                'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
                                'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                                'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
                                'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                                'w', 'x', 'y', 'z', '0', '1', '2', '3',
                                '4', '5', '6', '7', '8', '9', '+', '/'};
static char *decoding_table = NULL;
static int mod_table[] = {0, 2, 1};


char *base64_encode(const unsigned char *data,
                    size_t input_length,
                    size_t *output_length) {
    unsigned int i, j;

    *output_length = 4 * ((input_length + 2) / 3);

    char *encoded_data = malloc(*output_length+10);
    memset(encoded_data, 0, *output_length+10);
    if (encoded_data == NULL) return NULL;

    for (i = 0, j = 0; i < input_length;) {

        uint32_t octet_a = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t octet_b = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t octet_c = i < input_length ? (unsigned char)data[i++] : 0;

        uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

        encoded_data[j++] = encoding_table[(triple >> 3 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 2 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 1 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 0 * 6) & 0x3F];
    }

    for (i = 0; i < mod_table[input_length % 3]; i++)
        encoded_data[*output_length - 1 - i] = '=';

    return encoded_data;
}


//Parsing IP header
//Input: Raw packet data of IP Layer
//Output: Header information
int parse_ipv4(unsigned char *internet_data)
{
    //Version = 4 first bits of header
    unsigned char ver = internet_data[0] >> 4;
    if (ver!=4 && ver!=6)
    {
        printf("Unknown Internet protocol, can't parse !\n");
        return 1;
    }

    if (ver==6)
    {
        printf("Detected ipv6, but not supported !\n");
        return 1;
    }

    //192.168.10.10
    //10.10.10.10
    //10.10.10.20

    
    
    printf("\tInternet Protocol: ipv4\n");
    printf("\tHeader length: %u bytes\n", internet_data[0]&0x0f * 4); 
    printf("\tTransport Protocol (icmp=1, tcp=6, udp=17): %u\n", internet_data[9]);
    printf("\tSource IP: %u.%u.%u.%u\n", internet_data[12], internet_data[13], internet_data[14], internet_data[15]);
    printf("\tDestination IP: %u.%u.%u.%u\n", internet_data[16], internet_data[17], internet_data[18], internet_data[19]);

    return 0;
}

void saveLog(char* pkt, size_t len, time_t *rawtime, char* m_name)
{
    char fn[256] = {0};
    
    struct tm *timeinfo = localtime(rawtime);

    snprintf(fn, sizeof(fn), "log/bear-%4d-%2d-%2d.log", timeinfo->tm_year+1900, timeinfo->tm_mon+1, timeinfo->tm_mday);

    size_t outlen;
    char* outbuf = base64_encode(pkt, len, &outlen);
    FILE* fd = fopen(fn, "a");
    if (fd)
    {
        fprintf(fd, "%d--%s--%s\n", *(int*)rawtime, m_name, outbuf);
        fclose(fd);
    }
    free(outbuf);
}


static int callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
          struct nfq_data *nfa, void *data)
{
    u_int32_t id = 0;
    struct nfqnl_msg_packet_hdr *ph;
    struct nfqnl_msg_packet_hw *hwph;
    unsigned int i, len_buf;
    unsigned char *buf_ip;


    ph = nfq_get_msg_packet_hdr(nfa);
    if (ph) {
        id = ntohl(ph->packet_id);
        printf(">id=%u  hw_protocol=0x%04x  ", ntohs(ph->hw_protocol), id);
    }


    hwph = nfq_get_packet_hw(nfa);
    if (hwph) {
        int hlen = ntohs(hwph->hw_addrlen);

        printf("hw_src_addr=");
        for (i = 0; i < hlen-1; i++) printf("%02x:", hwph->hw_addr[i]);
        printf("%02x  ", hwph->hw_addr[hlen-1]);
    }


    len_buf = nfq_get_payload(nfa, &buf_ip);
    if (len_buf >= 0) {
        printf("ip_data_len=%d\n", len_buf);
        buf_ip[len_buf] = 0;
        for (i=0; i<mod_count; ++i)
            if (mod_loaded[i])
            {
                if (!mod_detect[i](buf_ip, len_buf))
                {
                    time_t rawtime = time(NULL);
                    printf("[%d] Detect by module - %s - Redirect\n", (int)rawtime, mod_name[i]);
                    saveLog(buf_ip, len_buf, &rawtime, mod_name[i]);
                    return nfq_set_verdict2(qh, id, NF_ACCEPT, 0xffffffff, 0, NULL);
                }
            }
    }

    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}




//Decorating <3
void loadBear()
{
    FILE* fd = fopen(FN_ART, "r");
    if (fd==NULL) return;
    char buf[256];
    while (!feof(fd))
    {
        memset(buf, 0, sizeof(buf));
        fgets(buf, sizeof(buf), fd);
        printf("%s",buf);
    }
    fclose(fd);
}

//Load/parsing Config and init module

int loadConfig()
{
    FILE* fd = fopen(FN_CONFIG, "r");
    if (fd==NULL) return 0;
    char buf[256], name[256], fn[256];

    while (!feof(fd))
    {
        memset(buf, 0, sizeof(buf));
        fgets(buf, sizeof(buf), fd);
        if (strcmp(buf, "[module]\n")==0)
        {
            if (feof(fd)) break;
            memset(name, 0, sizeof(name));
            fgets(name, sizeof(name), fd);

            if (feof(fd)) break;
            memset(fn, 0, sizeof(fn));
            fgets(fn, sizeof(fn), fd);

            name[strlen(name)-1] = 0;
            fn[strlen(fn)-1] = 0;
            
            if (strncmp(name, "name=", 5)==0 && strncmp(fn, "file=", 5)==0)
            {

                if (mod_count<50)
                {
                    mod_name[mod_count] = strdup((char*)(name+5));
                    mod_fn[mod_count] = strdup((char*)(fn+5));
                    printf("\t* %s - %s\n", mod_name[mod_count], mod_fn[mod_count]);
                    mod_loaded[mod_count++] = 0;
                }
                else
                {
                    printf("\t[!] Cannot load more than 50 modules\n");
                    break;
                }
            }
        }
    }

    printf("\t[!] Loaded - %d modules\n", mod_count);
    fclose(fd);

    if (mod_count==0) return 0;
    return 1;
}

int initModule()
{
    void* func_hd;
    PTR_MOD_INIT ptr;

    unsigned int i = 0;
    for (i=0; i<mod_count; ++i)
    {
        printf("\t* Init - %s\n", mod_name[i]);
        func_hd = dlopen(mod_fn[i], RTLD_LAZY);
        if (func_hd)
        {
            ptr = dlsym(func_hd, "mod_init");
            if (ptr)
            {
                ptr();
                if (mod_detect[i] = dlsym(func_hd, "mod_detect"))
                {
                    mod_loaded[i] = 1;
                    printf("\t-> OK!\n");
                    continue;    
                }
                
            }
        }
        printf("\t-> Failed!\n");

    }
    return 1;
}

//Main program
int main(int argc, char **argv, char** env)
{
    struct nfq_handle *hd;
    struct nfq_q_handle *queue_hd;
    int fd_hd;
    char buf_dlink[4096];
    size_t len_recv;

    loadBear();

    printf("[+] Open new handle\n");
    hd = nfq_open();
    if (!hd) {
        printf("...\n[-] Error during nfq_open()\n");
        exit(1);
    }

    printf("[+] Unbinding existing nf_queue handler for AF_INET (if any)\n");
    if (nfq_unbind_pf(hd, AF_INET) < 0) {
        printf("...\n[-] Error during nfq_unbind_pf()\n");
        exit(1);
    }

    printf("[+] Binding new handle as nf_queue handler for AF_INET\n");
    if (nfq_bind_pf(hd, AF_INET) < 0) {
        printf("...\n[-] Error during nfq_bind_pf()\n");
        exit(1);
    }

    printf("[+] Binding callback function to queue number 0\n");
    queue_hd = nfq_create_queue(hd, 0, &callback, NULL);
    if (!queue_hd) {
        printf("...\n[-] Error during nfq_create_queue()\n");
        exit(1);
    }

    printf("[+] Setting COPY_PACKET mode\n");
    if (nfq_set_mode(queue_hd, NFQNL_COPY_PACKET, 0xffff) < 0) {
        printf("...\n[-] Can't set COPY_PACKET mode\n");
        exit(1);
    }

    printf("[+] Load configuration\n");
    if (!loadConfig())
    {
        printf("...\n[-] Load config failed\n");
        exit(1);
    }

    printf("[+] Init detector modules\n");
    if (!initModule())
    {
        printf("...\n[-] Failed\n");
        exit(1);
    }


    printf("[+] Starting HoneyBear...\n");
    fd_hd = nfq_fd(hd);
    while ((len_recv = recv(fd_hd, buf_dlink, sizeof(buf_dlink), 0)) && len_recv >= 0) {
        nfq_handle_packet(hd, buf_dlink, len_recv);
    }

    printf("[+] Unbinding handler from queue number 0\n");
    nfq_destroy_queue(queue_hd);

    printf("[+] Unbinding current handler from AF_INET\n");
    nfq_unbind_pf(hd, AF_INET);

    printf("[+] Closing library handle\n");
    nfq_close(hd);

    printf("[!] Done! Bye\n");

    exit(0);
}