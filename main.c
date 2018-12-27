#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <pcap.h>
#include <stdio.h>
#include <string.h>

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN  6

/* Ethernet header */
struct sniff_ethernet {
    u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
    u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
    u_short ether_type; /* IP? ARP? RARP? etc */
};

/* ARP packet */
struct sniff_arp {
    u_short hw_type;    /* Harware type - Should always be 1 - Ethernet */
    u_short proto_type; /* Protocol type - Should always be 0x0800 - IPv4 */
    u_char hw_size;     /* Hardware address size - Should always be 6 on Ethernet */
    u_char proto_size;  /* Protocol size - Should always be 4 on IPv4 */
    u_short opcode;     /* ARP Opcode - 1=request, 2=reply */
    u_char sender_mac[ETHER_ADDR_LEN]; /* Source hardware address */
    u_char sender_addr[4];  /* Source IP Address */
    u_char target_mac[ETHER_ADDR_LEN]; /* Destination hardware address */
    u_char target_addr[4];  /* Destination IP Address */
};

/* IP header */
struct sniff_ip {
    u_char ip_vhl;      /* version << 4 | header length >> 2 */
    u_char ip_tos;      /* type of service */
    u_short ip_len;     /* total length */
    u_short ip_id;      /* identification */
    u_short ip_off;     /* fragment offset field */
#define IP_RF 0x8000        /* reserved fragment flag */
#define IP_DF 0x4000        /* dont fragment flag */
#define IP_MF 0x2000        /* more fragments flag */
#define IP_OFFMASK 0x1fff   /* mask for fragmenting bits */
    u_char ip_ttl;      /* time to live */
    u_char ip_p;        /* protocol */
    u_short ip_sum;     /* checksum */
    struct in_addr ip_src,ip_dst; /* source and dest address */
};
#define IP_HL(ip)       (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)        (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
    u_short th_sport;   /* source port */
    u_short th_dport;   /* destination port */
    tcp_seq th_seq;     /* sequence number */
    tcp_seq th_ack;     /* acknowledgement number */
    u_char th_offx2;    /* data offset, rsvd */
#define TH_OFF(th)  (((th)->th_offx2 & 0xf0) >> 4)
    u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short th_win;     /* window */
    u_short th_sum;     /* checksum */
    u_short th_urp;     /* urgent pointer */
};

/* ethernet headers are always exactly 14 bytes */
#define SIZE_ETHERNET 14

struct sniff_ipv6 {
    uint32_t version_class_flow;
    u_short payload_len;
    u_char next_header;
    u_char hop_limit;
    struct in6_addr src;
    struct in6_addr dest;
};

struct sniff_icmp6 {
    u_char type;
    u_char code;
    u_short csum;
};

struct sniff_icmp6_ns {
    u_int reserved;
    struct in6_addr target_address;
};

bpf_u_int32 mask;       /* Our netmask */
bpf_u_int32 net;        /* Our IP */

// From https://github.com/regit/nufw/blob/master/src/libs/nubase/ipv6.c

/**
 * Check if a IPv6 address is a IPv4 or not.
 *
 * \return 1 for IPv4 and 0 for IPv6
 */
int is_ipv4(const struct in6_addr *addr)
{
    if (ntohl(addr->s6_addr32[2]) != 0x0000ffff)
        return 0;
    if (addr->s6_addr32[0] != 0 || addr->s6_addr32[1] != 0)
        return 0;
    return 1;
}


/**
 * Format IPv6 address in specified string buffer.
 * Use IPv4 format ("192.168.0.1") for IPv4 in IPv6 address (::ffff:192.168.0.2).
 *
 * If protocol is not NULL, it will contains the address family:
 * AF_INET (IPv4) or AF_INET6 (IPv6).
 *
 * Returns new allocated string.
 */
void format_ipv6(const struct in6_addr *addr, char *buffer, size_t buflen, uint8_t *protocol)
{
    if (is_ipv4(addr)) {
        struct in_addr addr4;
        addr4.s_addr = addr->s6_addr32[3];
        if (protocol) *protocol = AF_INET;
        if (inet_ntop(AF_INET, &addr4, buffer, buflen) == NULL)
        {
            /* error */
            strncpy(buffer, "<ipv4>", buflen);
        }
    } else {
        if (protocol) *protocol = AF_INET6;
        if (inet_ntop(AF_INET6, addr, buffer, buflen) == NULL)
        {
            /* error */
            strncpy(buffer, "<ipv6>", buflen);
        }
    }
    /* always write nul byte at the end */
    if (0 < buflen) buffer[buflen-1] = 0;
}

void dump_struct(void* ptr, uint32_t size){

    for(uint32_t i=0; i<size; i++){
        printf("%02X ", *(((unsigned char*)ptr)+i));
        if(i % 16 == 15) printf("\n");
    }

}

void dump_arp(const struct sniff_arp* arp){
    printf("Source MAC: ");
    for(uint8_t i=0; i<6; i++){
        printf("%02X", arp->sender_mac[i]);
        if(i<5) printf(":");
    }
    printf("\r\n");

    printf("Target MAC: ");
    for(uint8_t i=0; i<6; i++){
        printf("%02X", arp->target_mac[i]);
        if(i<5) printf(":");
    }
    printf("\r\n");

    printf("Source IP: ");
    for(uint8_t i=0; i<4; i++){
        printf("%d", arp->sender_addr[i]);
        if(i<3) printf(".");
    }
    printf("\r\n");

    printf("Destination IP: ");
    for(uint8_t i=0; i<4; i++){
        printf("%d", arp->target_addr[i]);
        if(i<3) printf(".");
    }
    printf("\r\n");
}

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
    const struct sniff_ethernet *ethernet; /* The ethernet header */
    const struct sniff_arp *arp; /* The ARP header */
    const struct sniff_ipv6 *ipv6; /* The IPv6 header */
    const struct sniff_icmp6 *icmp6; /* The ICMPv6 header */
    const struct sniff_icmp6_ns *icmp6_ns; /* The ICMPv6 Neighbour Solicitation */

    u_int size_ip;
    u_int size_tcp;

    /*for(uint16_t i = 0; i<64; i++){
        printf("%02X ", packet[i]);
        if(i % 16 == 15){
            printf("\r\n");
        }
    }*/

    ethernet = (struct sniff_ethernet*)(packet);

    if(ntohs(ethernet->ether_type) == 0x0806){     // ARP
        arp = (struct sniff_arp*)(packet + sizeof(struct sniff_ethernet));

        uint32_t target_addr = arp->target_addr[3];
        target_addr = target_addr << 8;
        target_addr += arp->target_addr[2];
        target_addr = target_addr << 8;
        target_addr += arp->target_addr[1];
        target_addr = target_addr << 8;
        target_addr += arp->target_addr[0];

        if((target_addr & mask) != net){
            // Out of subnet ARP
            printf("WARNING: Out of network ARP packet received\r\n");
            dump_arp(arp);
        }
    }else if(ntohs(ethernet->ether_type) == 0x86dd){
        ipv6 = (struct sniff_ipv6*)(packet + sizeof(struct sniff_ethernet));

        if(ipv6->next_header == 58){
            unsigned char src_addr[64], dest_addr[64];

            format_ipv6(&(ipv6->src), src_addr, 64, NULL);
            format_ipv6(&(ipv6->dest), dest_addr, 64, NULL);

            icmp6 = (struct sniff_icmp6*)(packet + sizeof(struct sniff_ipv6) + sizeof(struct sniff_ethernet));

            if(icmp6->type == 133){
                // Router solicitation
                printf("Router solicitation from %s\n", src_addr);
            }else if(icmp6->type == 134){
                // Router advertisement
                printf("Router advertisement from %s\n", src_addr);
            }else if(icmp6->type == 135){
                // Neighbour solicitation
                icmp6_ns = (struct sniff_icmp6_ns*)(packet + sizeof(struct sniff_ethernet) + sizeof(struct sniff_ipv6) + sizeof(struct sniff_icmp6));
                format_ipv6(&(icmp6_ns->target_address), dest_addr, 64, NULL);
                printf("Neighbour solicitation for %s from %s\n", dest_addr, src_addr);

            }else if(icmp6->type == 136){
                // Neighbour advertisement
                printf("Neighbour advertisement for %s from %s\n", src_addr, dest_addr);
            }
        }
    }
}

 int main(int argc, char *argv[])
 {
    pcap_t *handle;         /* Session handle */
    char *dev;          /* The device to sniff on */
    char errbuf[PCAP_ERRBUF_SIZE];  /* Error string */
    struct bpf_program fp;      /* The compiled filter */
    char filter_exp[] = "arp or icmp6"; // or ( icmp6 && (ip6[40] >= 133 && ip6[40] <= 136 ) ) ";  /* The filter expression */
    struct pcap_pkthdr header;  /* The header that pcap gives us */
    const u_char *packet;       /* The actual packet */

    /* Define the device */
    if(argc > 1){
        /* Find the properties for the device */
        if (pcap_lookupnet(argv[1], &net, &mask, errbuf) == -1) {
            fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
            net = 0;
            mask = 0;
        }
        /* Open the session in promiscuous mode */
        handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);
        if (handle == NULL) {
            fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
            return(2);
        }
    }else{
        dev = pcap_lookupdev(errbuf);
        if (dev == NULL) {
            fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
            return(2);
        }
        /* Find the properties for the device */
        if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
            fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
            net = 0;
            mask = 0;
        }
        /* Open the session in promiscuous mode */
        handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
        if (handle == NULL) {
            fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
            return(2);
        }
    }

    printf("My network: %d.%d.%d.%d / %d.%d.%d.%d\r\n", 
        (net >>  0) & 0xFF,
        (net >>  8) & 0xFF,
        (net >> 16) & 0xFF,
        (net >> 24) & 0xFF,
        (mask >>  0) & 0xFF,
        (mask >>  8) & 0xFF,
        (mask >> 16) & 0xFF,
        (mask >> 24) & 0xFF
        );
    /* Compile and apply the filter */
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }
    /* Grab a packet */
    pcap_loop(handle, 0, process_packet, NULL);
    /* And close the session */
    pcap_close(handle);
    return(0);
 }
