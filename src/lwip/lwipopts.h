/* lwIP configuration for the zunnel server netstack.
 *
 * lwIP only terminates TCP here; UDP and ICMP are handled directly in Zig.
 * All lwIP calls are serialised by a single mutex on the Zig side, so we run
 * in NO_SYS mode without any lwIP-level locking.
 */
#ifndef ZUNNEL_LWIPOPTS_H
#define ZUNNEL_LWIPOPTS_H

#define NO_SYS                      1
#define SYS_LIGHTWEIGHT_PROT        0
#define LWIP_TIMERS                 1
#define LWIP_SOCKET                 0
#define LWIP_NETCONN                0
#define LWIP_ALTCP                  0

/* Memory: let libc malloc back everything so connection count is not bounded
 * by static pools. */
#define MEM_LIBC_MALLOC             1
#define MEMP_MEM_MALLOC             1
#define MEM_ALIGNMENT               8

/* Protocols */
#define LWIP_IPV4                   1
#define LWIP_IPV6                   0
#define LWIP_ARP                    0
#define LWIP_ETHERNET               0
#define LWIP_ICMP                   0
#define LWIP_RAW                    0
#define LWIP_UDP                    0
#define LWIP_TCP                    1
#define LWIP_DNS                    0
#define LWIP_DHCP                   0
#define LWIP_AUTOIP                 0
#define LWIP_ACD                    0
#define LWIP_IGMP                   0
#define IP_REASSEMBLY               0
#define IP_FRAG                     0
#define IP_FORWARD                  0

/* The kernel already validated incoming checksums. */
#define CHECKSUM_CHECK_IP           0
#define CHECKSUM_CHECK_TCP          0
#define CHECKSUM_GEN_IP             1
#define CHECKSUM_GEN_TCP            1

/* TCP tuning: 1500 MTU TUN, large windows with window scaling. */
#define TCP_MSS                     1460
#define LWIP_WND_SCALE              1
#define TCP_RCV_SCALE               3
#define TCP_WND                     (256 * 1024)
#define TCP_SND_BUF                 (256 * 1024)
#define TCP_SNDLOWAT                (16 * TCP_MSS)
#define TCP_SND_QUEUELEN            (4 * TCP_SND_BUF / TCP_MSS)
#define MEMP_NUM_TCP_SEG            (8 * 1024)
#define MEMP_NUM_TCP_PCB            4096
#define MEMP_NUM_TCP_PCB_LISTEN     4
#define TCP_LISTEN_BACKLOG          0
#define TCP_QUEUE_OOSEQ             1
#define LWIP_TCP_KEEPALIVE          0
#define TCP_OVERSIZE                TCP_MSS

/* Netif */
/* One netif per tunnel. Accepted pcbs are bound to their netif via the
 * per-tunnel listener (tcp_bind_netif); everything else (e.g. RSTs for unknown
 * connections) is routed back out of the netif the input arrived on. */
#define LWIP_SINGLE_NETIF           0
#define LWIP_HOOK_IP4_ROUTE_SRC(src, dest) zunnel_route_src((src), (dest))
#define LWIP_NETIF_LOOPBACK         0
#define LWIP_HAVE_LOOPIF            0
#define LWIP_NETIF_STATUS_CALLBACK  0
#define LWIP_NETIF_LINK_CALLBACK    0

/* Misc */
#define LWIP_STATS                  0
#define LWIP_STATS_DISPLAY          0
#define PPP_SUPPORT                 0
#define LWIP_DEBUG                  0

#endif /* ZUNNEL_LWIPOPTS_H */
