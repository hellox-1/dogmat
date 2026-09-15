#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <netinet/ip_icmp.h>
#include <time.h>

#define SNAP_LEN 1518

void packet_handler(
    u_char *args,
    const struct pcap_pkthdr *header,
    const u_char *packet
)
{
    (void)args;

    printf("\n========================================\n");

    time_t raw_time = header->ts.tv_sec;
    struct tm *time_info = localtime(&raw_time);

    printf("Time      : %02d:%02d:%02d.%06ld\n",
           time_info->tm_hour,
           time_info->tm_min,
           time_info->tm_sec,
           header->ts.tv_usec);

    printf("Size      : %u bytes\n", header->len);

    if (header->caplen < sizeof(struct ether_header))
        return;

    const struct ether_header *eth =
        (const struct ether_header *)packet;

    unsigned short ether_type = ntohs(eth->ether_type);

    printf("Ethernet  : ");

    if (ether_type == ETHERTYPE_IP)
        printf("IPv4\n");
    else if (ether_type == ETHERTYPE_IPV6)
        printf("IPv6\n");
    else if (ether_type == ETHERTYPE_ARP)
        printf("ARP\n");
    else
        printf("Unknown (0x%04x)\n", ether_type);

    if (ether_type == ETHERTYPE_ARP)
    {
        printf("Protocol  : ARP\n");
        return;
    }

    if (ether_type == ETHERTYPE_IP)
    {
        const struct ip *ip =
            (const struct ip *)(packet + sizeof(struct ether_header));

        char src[INET_ADDRSTRLEN];
        char dst[INET_ADDRSTRLEN];

        inet_ntop(AF_INET, &ip->ip_src, src, sizeof(src));
        inet_ntop(AF_INET, &ip->ip_dst, dst, sizeof(dst));

        printf("IPv4      : %s -> %s\n", src, dst);
        printf("TTL       : %d\n", ip->ip_ttl);

        int ip_header_len = ip->ip_hl * 4;

        if (ip->ip_p == IPPROTO_TCP)
        {
            const struct tcphdr *tcp =
                (const struct tcphdr *)
                ((const u_char *)ip + ip_header_len);

            unsigned short src_port = ntohs(tcp->th_sport);
            unsigned short dst_port = ntohs(tcp->th_dport);

            printf("Protocol  : TCP\n");
            printf("Ports     : %u -> %u\n",
                   src_port, dst_port);

            printf("Flags     : ");

            if (tcp->th_flags & TH_SYN)
                printf("SYN ");

            if (tcp->th_flags & TH_ACK)
                printf("ACK ");

            if (tcp->th_flags & TH_FIN)
                printf("FIN ");

            if (tcp->th_flags & TH_RST)
                printf("RST ");

            if (tcp->th_flags & TH_PUSH)
                printf("PSH ");

            printf("\n");

            if (src_port == 80 || dst_port == 80)
                printf("Application: HTTP\n");

            else if (src_port == 443 || dst_port == 443)
                printf("Application: HTTPS/TLS\n");

            else if (src_port == 22 || dst_port == 22)
                printf("Application: SSH\n");

            else if (src_port == 25 || dst_port == 25)
                printf("Application: SMTP\n");

            else
                printf("Application: Unknown TCP\n");
        }

        else if (ip->ip_p == IPPROTO_UDP)
        {
            const struct udphdr *udp =
                (const struct udphdr *)
                ((const u_char *)ip + ip_header_len);

            unsigned short src_port = ntohs(udp->uh_sport);
            unsigned short dst_port = ntohs(udp->uh_dport);

            printf("Protocol  : UDP\n");
            printf("Ports     : %u -> %u\n",
                   src_port, dst_port);

            if (src_port == 53 || dst_port == 53)
                printf("Application: DNS\n");

            else if (src_port == 67 || dst_port == 67 ||
                     src_port == 68 || dst_port == 68)
                printf("Application: DHCP\n");

            else if (src_port == 123 || dst_port == 123)
                printf("Application: NTP\n");

            else if (src_port == 443 || dst_port == 443)
                printf("Application: QUIC / HTTP3\n");

            else if (src_port == 5353 || dst_port == 5353)
                printf("Application: mDNS\n");

            else
                printf("Application: Unknown UDP\n");
        }

        else if (ip->ip_p == IPPROTO_ICMP)
        {
            printf("Protocol  : ICMP\n");
        }

        else
        {
            printf("Protocol  : IP protocol %d\n",
                   ip->ip_p);
        }
    }

    else if (ether_type == ETHERTYPE_IPV6)
    {
        const struct ip6_hdr *ip6 =
            (const struct ip6_hdr *)
            (packet + sizeof(struct ether_header));

        char src[INET6_ADDRSTRLEN];
        char dst[INET6_ADDRSTRLEN];

        inet_ntop(AF_INET6,
                  &ip6->ip6_src,
                  src,
                  sizeof(src));

        inet_ntop(AF_INET6,
                  &ip6->ip6_dst,
                  dst,
                  sizeof(dst));

        printf("IPv6      : %s -> %s\n", src, dst);

        printf("Next Header: %d\n",
               ip6->ip6_nxt);

        if (ip6->ip6_nxt == IPPROTO_TCP)
            printf("Protocol  : TCP\n");

        else if (ip6->ip6_nxt == IPPROTO_UDP)
            printf("Protocol  : UDP\n");

        else if (ip6->ip6_nxt == IPPROTO_ICMPV6)
            printf("Protocol  : ICMPv6\n");

        else
            printf("Protocol  : IPv6 protocol %d\n",
                   ip6->ip6_nxt);
    }

    printf("========================================\n");
}

int main(int argc, char *argv[])
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    char *device;

    if (argc > 1)
    {
        device = argv[1];
    }
    else
    {
        device = pcap_lookupdev(errbuf);

        if (device == NULL)
        {
            fprintf(stderr,
                    "Could not find interface: %s\n",
                    errbuf);

            return 1;
        }
    }

    printf("Network interface: %s\n", device);

    handle = pcap_open_live(
        device,
        SNAP_LEN,
        1,
        1000,
        errbuf
    );

    if (handle == NULL)
    {
        fprintf(stderr,
                "Could not open interface: %s\n",
                errbuf);

        return 1;
    }

    printf("Starting packet capture...\n");
    printf("Press Ctrl+C to stop.\n");

    pcap_loop(
        handle,
        -1,
        packet_handler,
        NULL
    );

    pcap_close(handle);

    return 0;
}
