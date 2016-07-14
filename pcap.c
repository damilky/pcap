#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>

struct ethernet_header {
    unsigned char   destination_address[6];
    unsigned char   source_address[6];
    unsigned short  type;
};
struct ip_header {
#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned int ip_hl:4;
    unsigned int ip_v:4;
#endif
#if __BYTE_ORDER == __BIG_ENDIAN
    unsigned int ip_v:4;
    unsigned int ip_hl:4;
#endif
    u_int8_t ip_tos;
    u_short ip_len;
    u_short ip_id;
    u_short ip_off;
#define IP_RF 0x8000
#define IP_DF 0x4000
#define IP_MF 0x2000
#define IP_OFFMASK 0x1fff
    u_int8_t ip_ttl;
    u_int8_t ip_p;
    u_short ip_sum;
    struct in_addr ip_src, ip_dst;
};

struct tcp
{
    u_int16_t th_sport;
    u_int16_t th_dport;
    tcp_seq th_seq;
    tcp_seq th_ack;
#  if __BYTE_ORDER == __LITTLE_ENDIAN
    u_int8_t th_x2:4;
    u_int8_t th_off:4;
#  endif
#  if __BYTE_ORDER == __BIG_ENDIAN
    u_int8_t th_off:4;
    u_int8_t th_x2:4;
#  endif
    u_int8_t th_flags;
#  define TH_FIN    0x01
#  define TH_SYN    0x02
#  define TH_RST    0x04
#  define TH_PUSH   0x08
#  define TH_ACK    0x10
#  define TH_URG    0x20
    u_int16_t th_win;
    u_int16_t th_sum;
    u_int16_t th_urp;
};

void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
    struct ethernet_header *ep;
    struct ip_header *iph;
    struct tcphdr *tcph;

    ep = (struct ethernet_header *)pkt_data;
    printf("%02x:%02x:%02x:%02x:%02x:%02x \n", ep->destination_address[0],ep->destination_address[1],ep->destination_address[2],ep->destination_address[3],ep->destination_address[4],ep->destination_address[5]);
    printf("%02x:%02x:%02x:%02x:%02x:%02x \n", ep->source_address[0],ep->source_address[1],ep->source_address[0],ep->source_address[0],ep->source_address[0],ep->source_address[0]);
    printf("%x\n",ntohs(ep->type));
    if (ntohs(ep->type) == ETHERTYPE_IP)
    {
        iph = (struct ip_header *)(pkt_data+sizeof(struct ethernet_header));
        printf("IP 패킷\n");
        printf("Version     : %d\n", iph->ip_v);
        printf("Header Len  : %d\n", iph->ip_hl);
        printf("Ident       : %d\n", ntohs(iph->ip_id));
        printf("TTL         : %d\n", iph->ip_ttl);
        printf("Src Address : %s\n", inet_ntoa(iph->ip_src));
        printf("Dst Address : %s\n", inet_ntoa(iph->ip_dst));

    }
    if (iph->ip_p == IPPROTO_TCP)
    {
        tcph = (struct tcp *)(pkt_data +sizeof(struct ethernet_header)+(iph->ip_hl * 4));
        printf("Src Port : %d\n" , ntohs(tcph->source));
        printf("Dst Port : %d\n" , ntohs(tcph->dest));
    }

}


int main(int argc, char *argv[])

{
    pcap_t *handle;
    char *dev, errbuf[PCAP_ERRBUF_SIZE];


    dev = pcap_lookupdev(errbuf);

    if (dev == NULL) {

        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);

        return(2);

    }

    printf("Device: %s\n", dev);



    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return(2);
    }
    pcap_loop(handle, 0, packet_handler,NULL); // 세번째 인자 : 패킷이 도착시 callback해줄 함수

    return(0);

}
