#include <errno.h>
#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "sxe-log.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <linux/netfilter.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <libipq.h>

#define PACKET_BUF_SIZE 2048

// this number comes from: sysctl net.core.wmem_max
#define MAX_SO_RCVBUF 131071

//  modprobe iptable_filter
//  modprobe ip_queue
//  apt-get install iptables-dev

static void
log_packet(ipq_packet_msg_t * packet)
{
    struct iphdr  * ip;
    ip  = (struct iphdr *)packet->payload;
    struct in_addr src_addr = {ip->saddr};
    struct in_addr dst_addr = {ip->daddr};

    SXEL6("ip_ptr:      '%p'",    ip);
    SXEL6("ip_ihl:      '0x%x'",  ip->ihl);
    SXEL6("ip_version:  '0x%x'",  ip->version);
    SXEL6("ip_tos:      '0x%x'",  ip->tos);
    SXEL6("ip_tot_len:  '%hu'",   ntohs(ip->tot_len));
    SXEL6("ip_id:       '%hu'",   ntohs(ip->id));
    SXEL6("ip_frag_off: '0x%hx'", ntohs(ip->frag_off));
    SXEL6("ip_ttl:      '0x%x'",  ip->ttl);
    SXEL6("ip_protocol: '0x%x'",  ip->protocol);
    SXEL6("ip_check:    '0x%hx'", ntohs(ip->check));
    SXEL6("ip_saddr:    '0x%x'",  ntohl(ip->saddr));
    SXEL6("ip_daddr:    '0x%x'",  ntohl(ip->daddr));

    unsigned short src_port = 0;
    unsigned short dst_port = 0;
    const char * proto_name = "";

    switch (ip->protocol) {

    case 0x11: // UDP
        {
        struct udphdr * udp;
        udp = (struct udphdr *)  (packet->payload + (4 * ip->ihl));
        SXEL6("udp_source:  '%hu'",   ntohs(udp->source));
        SXEL6("udp_dest:    '%hu'",   ntohs(udp->dest));
        src_port = ntohs(udp->source);
        dst_port = ntohs(udp->dest);
        proto_name = "UDP";
        }
        break;

    case 0x06: // TCP
        {
        struct tcphdr * tcp;
        tcp = (struct tcphdr *)  (packet->payload + (4 * ip->ihl));
        SXEL6("tcp_source:  '%hu'",   ntohs(tcp->source));
        SXEL6("tcp_dest:    '%hu'",   ntohs(tcp->dest));
        src_port = ntohs(tcp->source);
        dst_port = ntohs(tcp->dest);
        proto_name = "TCP";
        }
        break;

    default:
        proto_name = "Unknown";
        break;
    }

    printf("%s:%u ",        inet_ntoa(src_addr), src_port);
    printf("%s:%u %s %u\n", inet_ntoa(dst_addr), dst_port, proto_name, ntohs(ip->tot_len));
}


static void
run_ipq_filter(void)
{
    int                 status;
    unsigned char       pbuf[PACKET_BUF_SIZE];
    ipq_packet_msg_t  * packet;
    struct ipq_handle * handle;

    handle = ipq_create_handle(0, PF_INET);
    if (handle == NULL) { goto ERROR_OUT; }

    status = ipq_set_mode(handle, IPQ_COPY_PACKET, PACKET_BUF_SIZE);
    if (status < 0) { goto ERROR_OUT; }

    int rcvbuf = MAX_SO_RCVBUF;
    status = setsockopt(handle->fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
    if (status) { goto ERROR_OUT; }

    while (true) {
        status = ipq_read(handle, pbuf, PACKET_BUF_SIZE, 0);
        if (status < 0) { goto ERROR_OUT; }

        switch (ipq_message_type(pbuf)) {

        case NLMSG_ERROR:
            SXEL1("NLMSG_ERROR: Received error code: %d", ipq_get_msgerr(pbuf));
            ipq_perror(NULL);
            exit(-1);
            break;

        case IPQM_PACKET:
            packet = ipq_get_packet(pbuf);
            SXEL6(" ");
            SXEL6("Packet received from queue");
            SXED6(packet->payload, packet->data_len);
            log_packet(packet);
            status = ipq_set_verdict(handle, packet->packet_id, NF_ACCEPT, 0, NULL);
            if (status < 0) { goto ERROR_OUT; }
            break;

        default:
            goto ERROR_OUT;
            break;
        }
    }

ERROR_OUT:
    ipq_perror(NULL);
    ipq_destroy_handle(handle);
}

int
main(int argc, char *argv[])
{
    (void)argc;
    SXEL1("%s running...", argv[0]);
    run_ipq_filter();
    return 0;
}
