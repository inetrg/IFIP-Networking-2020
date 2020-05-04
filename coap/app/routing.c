#include "net/ipv6/addr.h"
#include "net/gnrc/netif.h"
#include "net/gnrc/ipv6/nib.h"

extern gnrc_netif_t *mynetif;
extern char hwaddr_str[GNRC_NETIF_L2ADDR_MAXLEN * 3];

void install_routes(char *laddr, char *toaddr_str, char *nhaddr_str)
{
    ipv6_addr_t toaddr, nhaddr;

    if(strncmp(laddr, hwaddr_str, strlen(laddr))) {
        /* not for me => bail */
        return;
    }

    ipv6_addr_from_str(&toaddr, toaddr_str);
    ipv6_addr_from_str(&nhaddr, nhaddr_str);
    gnrc_ipv6_nib_ft_add(&toaddr, IPV6_ADDR_BIT_LEN, &nhaddr, mynetif->pid, 0);
}
