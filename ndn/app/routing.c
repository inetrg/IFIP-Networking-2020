#include "net/gnrc/netif.h"
#include "ccn-lite-riot.h"
#include "ccnl-pkt-builder.h"
#include "ccnl-callbacks.h"
#include "ccnl-producer.h"

extern gnrc_netif_t *mynetif;
extern char hwaddr_str[GNRC_NETIF_L2ADDR_MAXLEN * 3];

static struct ccnl_face_s *_intern_face_get(char *addr_str)
{
    uint8_t relay_addr[GNRC_NETIF_L2ADDR_MAXLEN];
    memset(relay_addr, UINT8_MAX, GNRC_NETIF_L2ADDR_MAXLEN);
    size_t addr_len = gnrc_netif_addr_from_str(addr_str, relay_addr);

    if (addr_len == 0) {
        printf("Error: %s is not a valid link layer address\n", addr_str);
        return NULL;
    }

    sockunion sun;
    sun.sa.sa_family = AF_PACKET;
    memcpy(&(sun.linklayer.sll_addr), relay_addr, addr_len);
    sun.linklayer.sll_halen = addr_len;
    sun.linklayer.sll_protocol = htons(ETHERTYPE_NDN);

    return ccnl_get_face_or_create(&ccnl_relay, 0, &sun.sa, sizeof(sun.linklayer));
}

void install_routes(char *laddr, char *toaddr, char *nhaddr)
{
    if(strncmp(hwaddr_str, laddr, strlen(laddr))) {
        /* not for me => bail */
        return;
    }

    char *prefix_str[64];
    memset(prefix_str, 0, sizeof(prefix_str));
    memcpy(prefix_str, toaddr, strlen(toaddr));

    int suite = CCNL_SUITE_NDNTLV;
    struct ccnl_prefix_s *prefix = ccnl_URItoPrefix((char *)prefix_str, suite, NULL);
    struct ccnl_face_s *fibface = _intern_face_get(nhaddr);
    fibface->flags |= CCNL_FACE_FLAGS_STATIC;
    ccnl_fib_add_entry(&ccnl_relay, prefix, fibface);
}
