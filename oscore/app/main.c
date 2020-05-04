#include "net/gcoap.h"
#include "msg.h"
#include "shell.h"
#include "evtimer.h"
#include "evtimer_msg.h"
#include "random.h"

#ifndef IPV6_PREFIX
#define IPV6_PREFIX         { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,  0, 0, 0, 0, 0, 0, 0, 0 }
#endif
#ifndef IPV6_PREFIX_LEN
#define IPV6_PREFIX_LEN     (64U)
#endif

gnrc_netif_t *mynetif;
uint8_t hwaddr[GNRC_NETIF_L2ADDR_MAXLEN];
char hwaddr_str[GNRC_NETIF_L2ADDR_MAXLEN * 3];
extern unsigned reqtx, resprx;

static const ipv6_addr_t _ipv6_prefix = { .u8 = IPV6_PREFIX };

ipv6_addr_t _my_link_local, _my_global;
char _my_link_local_str[IPV6_ADDR_MAX_STR_LEN];
char _my_global_str[IPV6_ADDR_MAX_STR_LEN];
ipv6_addr_t _global_consumer, _global_producer;

#define MAIN_QUEUE_SIZE (4)
static msg_t _main_msg_queue[MAIN_QUEUE_SIZE];

extern void send_static_request(uint16_t nodeid);
extern gcoap_listener_t app_listener;
extern void setup_security(void);

extern void install_routes(char *laddr, char *toaddr_str, char *nhaddr_str);

uint16_t narr[] = NARR;

static evtimer_t evtimer;
static evtimer_msg_event_t events[NARRNUM];

#define EVENT_TIME (1500 + random_uint32_range(0, 1000))

static int _send_get(int argc, char **argv) {
    (void)argc;
    (void)argv;
    evtimer_init_msg(&evtimer);
    for (unsigned i = 0; i < NARRNUM; i++) {
        events[i].event.offset = (i+1) * 500;
        events[i].msg.content.value = i;
        evtimer_add_msg(&evtimer, &events[i], sched_active_pid);
    }
    unsigned i = 0;
    while ((i++) < 1000 * NARRNUM) {
        msg_t m;
        msg_receive(&m);
        send_static_request(narr[m.content.value]);
        events[m.content.value].event.offset = EVENT_TIME;
        evtimer_add_msg(&evtimer, &events[m.content.value], sched_active_pid);
    }
    return 0;
}

static const shell_command_t shell_commands[] = {
    { "send", "", _send_get },
    { NULL, NULL, NULL }
};

int main(void)
{
    gcoap_register_listener(&app_listener);

    msg_init_queue(_main_msg_queue, MAIN_QUEUE_SIZE);
    char line_buf[SHELL_DEFAULT_BUFSIZE];

    /* find first netif */
    mynetif = gnrc_netif_iter(NULL);

    uint16_t src_len = 8U;
    gnrc_netapi_set(mynetif->pid, NETOPT_SRC_LEN, 0, &src_len, sizeof(src_len));
#ifdef BOARD_NATIVE
    gnrc_netapi_get(mynetif->pid, NETOPT_ADDRESS, 0, hwaddr, sizeof(hwaddr));
#else
    gnrc_netapi_get(mynetif->pid, NETOPT_ADDRESS_LONG, 0, hwaddr, sizeof(hwaddr));
#endif
    gnrc_netif_addr_to_str(hwaddr, sizeof(hwaddr), hwaddr_str);

    /* get first ipv6 address from netif */
    gnrc_netif_ipv6_addrs_get(mynetif, &_my_link_local, sizeof(_my_link_local));
    ipv6_addr_to_str(_my_link_local_str, &_my_link_local, sizeof(_my_link_local_str));

    /* set global ipv6 address */
    memcpy(&_my_global, &_my_link_local, sizeof(_my_global));
    ipv6_addr_init_prefix(&_my_global, &_ipv6_prefix, IPV6_PREFIX_LEN);
    ipv6_addr_to_str(_my_global_str, &_my_global, sizeof(_my_global_str));
    gnrc_netif_ipv6_addr_add(mynetif, &_my_global, IPV6_PREFIX_LEN, GNRC_NETIF_IPV6_ADDRS_FLAGS_STATE_VALID);

    printf("addr;%s;", hwaddr_str);
    printf("%s;", _my_link_local_str);
    printf("%s\n", _my_global_str);

#define ROUTE(myid, laddr, toaddr, nhaddr) install_routes(laddr, toaddr, nhaddr);
#if EXP_MULTI
#include "routesmulti.inc"
#else
#include "routes.inc"
#endif
#undef ROUTE

    random_init(*((uint32_t *)hwaddr));

#if GW
    xtimer_sleep(5);
    _send_get(0, NULL);
    xtimer_sleep(10);
    printf("end;%u;%u\n", reqtx, resprx);
#endif

    shell_run(shell_commands, line_buf, sizeof(line_buf));

    return 0;
}
