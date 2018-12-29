#include <stdlib.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <pcap.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <signal.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <sys/time.h>

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
    u_int version_class_flow;
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
    union
    {
        uint32_t  icmp6_un_data32[1]; /* type-specific field */
        uint16_t  icmp6_un_data16[2]; /* type-specific field */
        uint8_t   icmp6_un_data8[4];  /* type-specific field */
    } icmp6_dataun;
};

struct sniff_icmp6_ns {
    struct in6_addr target_address;
};

struct sniff_icmp6_na {
    struct in6_addr target_address;
};

struct sniff_icmp6_ra {
    u_int reachable;
    u_int retransmit;
};

struct sniff_icmp6_option {
    u_char type;
    u_char length;
};

struct icmp6_ra_opt_prefix {
    uint8_t type;
    uint8_t length;
    uint8_t prefix_length;
    uint8_t flags;
    uint32_t valid_lifetime;
    uint32_t preferred_lifetime;
    uint32_t reserved2;
    struct in6_addr prefix;
};

struct icmp6_option_list {
    struct sniff_icmp6_option *option;
    void* data;
    struct icmp6_option_list *next;
};

struct wqm_stats {
    uint32_t arp;
    uint32_t arp_wrongnet;      // ARP packets seen in the wrong network
    uint32_t arp_mac_changed;   // ARP packets seen with a different MAC to the last one we saw
    uint32_t arp_gratuitous;    // ARP packets that are gratuitous (sent to the Broadcast MAC)
    uint32_t icmp6;             // Total number of ICMPv6 packets seen
    uint32_t icmp6_ns_wrongnet; // ICMPv6 neighbour solicit packets seen for a network that was not local at program startup
    uint32_t icmp6_na_wrongnet; // ICMPv6 neighbour advertisement packets seen for a network that was not local at program startup
    uint32_t icmp6_ra_wrongnet; // ICMPv6 router advertisement packets seen for a network that was not local at program startup
};

struct wqm_opts {
    bool human_readable;    // Enable human readable output
};

struct wqm_stats program_stats;
struct wqm_opts program_options;


bpf_u_int32 mask;       /* Our netmask */
bpf_u_int32 net;        /* Our IP */
struct sockaddr_in6 *net6; // Our IPv6 address
struct sockaddr_in6 *mask6; // Our IPv6 netmask
u_char mask6_prefix_bits;


time_t last_stats; // Last stats dump timer

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

void time_header(void){
    char buf[64];
    time_t timer;
    struct tm* tm_info;

    time(&timer);
    tm_info = localtime(&timer);
    strftime(buf, 64, "%F %T", tm_info);
    if(program_options.human_readable){
        printf("[%s] ", buf);
    }else{
        printf("%s ", buf);
    }
}

void dump_struct(void* ptr, uint32_t size){

    for(uint32_t i=0; i<size; i++){
        printf("%02X ", *(((unsigned char*)ptr)+i));
        if(i % 16 == 15) printf("\n");
    }

}

int format_mac(char* buffer, uint32_t size, const unsigned char* mac){
    if(size < 17) return -1; // We can't fit a MAC in this
    
    for(uint8_t i=0; i<6; i++){
        sprintf(buffer+i*3, "%02X", mac[i]);
        if(i<5) sprintf(buffer+i*3+2, ":");
    }
    
    return 0;
}


int format_ip(char* buffer, uint32_t size, const unsigned char* ip){
    if(size < 17) return -1; // We can't fit an IP in this
    
    for(uint8_t i=0; i<4; i++){
        sprintf(buffer+i*4, "%03d", ip[i]);
        if(i<3) sprintf(buffer+i*4+3, ".");
    }
    
    return 0;
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

// Generate a linked list of options from an arbitrary data stream
struct icmp6_option_list* process_icmp6_options(void* opt_start, u_short max_length){
    struct icmp6_option_list* head;
    struct icmp6_option_list* cur;
    struct icmp6_option_list* last;
    #ifdef DEBUG
    printf("process_icmp6_options(<ptr>, %p, %d)\n", opt_start, max_length);
    #endif
    
    if(max_length == 0){
        return NULL;
    }
    
    void *ptr_start = opt_start;
    head = NULL;
    last = NULL;
    
    struct sniff_icmp6_option* tmp_opt;
    
    while(max_length > sizeof(struct sniff_icmp6_option)){
        tmp_opt = (struct sniff_icmp6_option*)ptr_start;
        cur = malloc( sizeof(struct icmp6_option_list) );
        cur->option = tmp_opt;
        cur->next = NULL;
        cur->data = opt_start;
        #ifdef DEBUG
        printf("Added IPv6 Option %d (Length: %d) from %p\n", cur->option->type, cur->option->length, ptr_start);
        #endif
        if(last != NULL) last->next = cur;
        last = cur;
        if(head == NULL) head = cur;
        max_length -= tmp_opt->length * 8;
        ptr_start += tmp_opt->length * 8;
    }
    
    return head;
}

int free_icmp6_options(struct icmp6_option_list* options){
    struct icmp6_option_list* tmp;
    struct icmp6_option_list* cur;
    
    tmp = options;
    
    while(tmp){
        cur = tmp;
        tmp = tmp->next;
        free(cur);
    }
}

// From https://stackoverflow.com/questions/37786946/how-to-compare-ipv6-address-in-c-without-using-memcmp
int compare_ipv6(struct in6_addr *ipA, struct in6_addr *ipB)
{
    int i = 0;
    for(i = 0; i < 16; ++i) // Don't use magic number, here just for example
    {
        if (ipA->s6_addr[i] < ipB->s6_addr[i])
            return -1;
        else if (ipA->s6_addr[i] > ipB->s6_addr[i])
            return 1;
    }
    return 0;
}

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
    const struct sniff_ethernet *ethernet; /* The ethernet header */
    const struct sniff_arp *arp; /* The ARP header */
    const struct sniff_ipv6 *ipv6; /* The IPv6 header */
    const struct sniff_icmp6 *icmp6; /* The ICMPv6 header */
    const struct sniff_icmp6_na *icmp6_na; /* The ICMPv6 Neighbour Advertisement */
    const struct sniff_icmp6_ns *icmp6_ns; /* The ICMPv6 Neighbour Solicitation */
    const struct sniff_icmp6_ra *icmp6_ra; /* The ICMPv6 Router Advertisement */
    struct icmp6_option_list *icmp6_options; /* The ICMPv6 options - TLV format */
    u_int size_ip;
    u_int size_tcp;
    char smac[20], dmac[20];

    /*for(uint16_t i = 0; i<64; i++){
        printf("%02X ", packet[i]);
        if(i % 16 == 15){
            printf("\r\n");
        }
    }*/

    ethernet = (struct sniff_ethernet*)(packet);
    format_mac(smac, sizeof(smac), ethernet->ether_shost);
    format_mac(dmac, sizeof(dmac), ethernet->ether_dhost);
    
    if(ntohs(ethernet->ether_type) == 0x0806){     // ARP
        program_stats.arp++;
        arp = (struct sniff_arp*)(packet + sizeof(struct sniff_ethernet));

        bool gratuitous = 0;

        uint32_t target_addr = arp->target_addr[3];
        target_addr = target_addr << 8;
        target_addr += arp->target_addr[2];
        target_addr = target_addr << 8;
        target_addr += arp->target_addr[1];
        target_addr = target_addr << 8;
        target_addr += arp->target_addr[0];
        
        uint32_t source_addr = arp->sender_addr[3];
        source_addr = source_addr << 8;
        source_addr += arp->sender_addr[2];
        source_addr = source_addr << 8;
        source_addr += arp->sender_addr[1];
        source_addr = source_addr << 8;
        source_addr += arp->sender_addr[0];

        if(target_addr == source_addr){
            gratuitous = 1;
            program_stats.arp_gratuitous++;
        }

        if((target_addr & mask) != net){
            program_stats.arp_wrongnet++;
            // Out of subnet ARP
            time_header();
            if(program_options.human_readable){
                printf("WARNING: Out of network ARP packet received\r\n");
                dump_arp(arp);
            }else{
                char sip[18], dip[18], arpsmac[20], arpdmac[20];
                char oos_type[32];
                
                if(gratuitous){
                    sprintf(oos_type, "gratuitous,wrongnet");
                }else{
                    sprintf(oos_type, "wrongnet");
                }
                
                format_ip(sip, sizeof(sip), arp->sender_addr);
                format_ip(dip, sizeof(dip), arp->target_addr);
                format_mac(arpsmac, sizeof(arpsmac), arp->sender_mac);
                format_mac(arpdmac, sizeof(arpdmac), arp->target_mac);
                
                printf("ALERT ARP %s smac=%s dmac=%s arp_sip=%s arp_dip=%s arp_smac=%s arp_dmac=%s\r\n", oos_type, smac, dmac, sip, dip, arpsmac, arpdmac);
            }
        }
    }else if(ntohs(ethernet->ether_type) == 0x86dd){
        ipv6 = (struct sniff_ipv6*)(packet + sizeof(struct sniff_ethernet));

        uint16_t payload_len = ((ipv6->payload_len & 0xFF00) >> 8) + ((ipv6->payload_len & 0x00FF) << 8);

        if(ipv6->next_header == 58){
            #ifdef DEBUG
            printf("Packet ptr: %p\n", packet);
            #endif
            
            program_stats.icmp6++;
            
            unsigned char src_addr[64], dest_addr[64];

            format_ipv6(&(ipv6->src), src_addr, 64, NULL);
            format_ipv6(&(ipv6->dest), dest_addr, 64, NULL);

            icmp6 = (struct sniff_icmp6*)(packet + sizeof(struct sniff_ipv6) + sizeof(struct sniff_ethernet));

            if(icmp6->type == 133){
                // Router solicitation
                time_header();
                printf("Router solicitation from %s\n", src_addr);
            }else if(icmp6->type == 134){
                // Router advertisement
                icmp6_ra = (struct sniff_icmp6_ra*)(packet + sizeof(struct sniff_ethernet) + sizeof(struct sniff_ipv6) + sizeof(struct sniff_icmp6));
                // Parse options to get prefix
                icmp6_options = process_icmp6_options((void*)(packet + sizeof(struct sniff_ethernet) + sizeof(struct sniff_ipv6) + sizeof(struct sniff_icmp6) + sizeof(struct sniff_icmp6_ra)),
                                                      payload_len - sizeof(struct sniff_icmp6) - sizeof(struct sniff_icmp6_ra));
                
                #ifdef DEBUG
                printf("Router advertisement from %s\n", src_addr);
                printf("ICMP6 options: %p\n", icmp6_options);
                #endif
                while(icmp6_options){
                    #ifdef DEBUG
                    printf("Option: %d, Len %d\n", icmp6_options->option->type, icmp6_options->option->length);
                    #endif
                    
                    if(icmp6_options->option->type == 3){
                        // Prefix information option
                        const struct icmp6_ra_opt_prefix *prefix = (struct icmp6_ra_opt_prefix*) ( icmp6_options->data );
                        if(
                            (compare_ipv6(&prefix->prefix, &net6->sin6_addr) != 0) || 
                            ( (prefix->prefix_length != mask6_prefix_bits) && (compare_ipv6(&prefix->prefix, &net6->sin6_addr) == 0) )
                          ){
                            program_stats.icmp6_ra_wrongnet++;
                            // Wrong network
                            char prefix_formatted[128];
                            inet_ntop(AF_INET6, &prefix->prefix, prefix_formatted, sizeof(prefix_formatted));
                            if(program_options.human_readable){
                                time_header();
                                printf("ALERT ICMPv6 RA for incorrect subnet received from %s (Subnet: %s/%d)\n", smac, prefix_formatted, prefix->prefix_length);
                            }else{
                                time_header();
                                printf("ALERT ICMPv6 ra_wrongnet smac=%s dmac=%s icmp6_sip=%s icmp6_dip=%s icmp6_ra_prefix=%s/%d\n", smac, dmac, src_addr, dest_addr, prefix_formatted, prefix->prefix_length);
                            }
                        }
                    }
                    
                    icmp6_options = icmp6_options->next;
                }
                free_icmp6_options(icmp6_options);
            }else if(icmp6->type == 135){
                // Neighbour solicitation
                icmp6_ns = (struct sniff_icmp6_ns*)(packet + sizeof(struct sniff_ethernet) + sizeof(struct sniff_ipv6) + sizeof(struct sniff_icmp6));
                format_ipv6(&(icmp6_ns->target_address), dest_addr, 64, NULL);
                time_header();
                printf("Neighbour solicitation for %s from %s\n", dest_addr, src_addr);

            }else if(icmp6->type == 136){
                // Neighbour advertisement
                icmp6_na = (struct sniff_icmp6_na*)(packet + sizeof(struct sniff_ethernet) + sizeof(struct sniff_ipv6) + sizeof(struct sniff_icmp6));
                format_ipv6(&(icmp6_na->target_address), dest_addr, 64, NULL);
                time_header();
                printf("Neighbour advertisement for %s from %s\n", src_addr, dest_addr);
            }
        }
    }
}

void stats_dumper(void){
    time_header();
    printf("STAT arp=%d arp_wrongnet=%d arp_mac_changed=%d arp_gratuitous=%d icmp6=%d icmp6_ns_wrongnet=%d icmp6_na_wrongnet=%d icmp6_ra_wrongnet=%d\r\n",
        program_stats.arp,
        program_stats.arp_wrongnet,
        program_stats.arp_mac_changed,
        program_stats.arp_gratuitous,
        program_stats.icmp6,
        program_stats.icmp6_ns_wrongnet,
        program_stats.icmp6_na_wrongnet,
        program_stats.icmp6_ra_wrongnet
    );
    memset(&program_stats, 0, sizeof(struct wqm_stats));
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
    struct ifaddrs *ifa, *ifa_tmp;
    struct itimerval initial, updated;
    
    // Stats timer functions
    struct sigaction sa;
    struct itimerval stats_timer;
    
    // Hook onto SIGALARM
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = &stats_dumper;
    sigaction(SIGALRM, &sa, NULL);
    
    // Set a 60 second timer
    stats_timer.it_value.tv_sec = 60;
    stats_timer.it_value.tv_usec = 0;
    /* ... and every 250 msec after that. */
    stats_timer.it_interval.tv_sec = 60;
    stats_timer.it_interval.tv_usec = 0;
    setitimer (ITIMER_REAL, &stats_timer, NULL);


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
        dev = argv[1];
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

    if (getifaddrs(&ifa) == -1) {
        fprintf(stderr, "getifaddrs failed\n");
        return 2;
    }

    ifa_tmp = ifa;
    while (ifa_tmp) {
        if( (strcmp(ifa_tmp->ifa_name, dev) == 0) &&
            (ifa_tmp->ifa_addr) && 
            (ifa_tmp->ifa_addr->sa_family == AF_INET6) ) {
                // create IPv6 string
                net6 = (struct sockaddr_in6*) (ifa_tmp->ifa_addr);
                if((((uint16_t)net6) & 0xfe80) != 0xfe80){
                    mask6 = (struct sockaddr_in6*) ifa_tmp->ifa_netmask;
                    for(uint8_t i = 0; i < 16; i++)
                        net6->sin6_addr.s6_addr[i] &= mask6->sin6_addr.s6_addr[i];
                    mask6_prefix_bits = 0;
                    for(uint8_t i = 0; i < 16; i++)
                        for(uint8_t j = 0; j < 8; j++)
                            mask6_prefix_bits += (mask6->sin6_addr.s6_addr[i] >> j) & 0x01;
                    break;
                }
        }
        ifa_tmp = ifa_tmp->ifa_next;
    }

    #ifdef DEBUG
    printf("sizeof(struct sniff_ipv6): %d\n", sizeof(struct sniff_ipv6));
    printf("sizeof(struct sniff_icmp6): %d\n", sizeof(struct sniff_icmp6));
    printf("sizeof(struct sniff_icmp6_ra): %d\n", sizeof(struct sniff_icmp6_ra));
    printf("My network (IPv4): %d.%d.%d.%d / %d.%d.%d.%d\r\n", 
        (net >>  0) & 0xFF,
        (net >>  8) & 0xFF,
        (net >> 16) & 0xFF,
        (net >> 24) & 0xFF,
        (mask >>  0) & 0xFF,
        (mask >>  8) & 0xFF,
        (mask >> 16) & 0xFF,
        (mask >> 24) & 0xFF
        );
        
    char v6print1[64], v6print2[64];
    inet_ntop(AF_INET6, &net6->sin6_addr, v6print1, sizeof(v6print1));
    inet_ntop(AF_INET6, &mask6->sin6_addr, v6print2, sizeof(v6print2));
    printf("My network (IPv6): %s / %d\r\n", v6print1, mask6_prefix_bits);
    #endif
    
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
