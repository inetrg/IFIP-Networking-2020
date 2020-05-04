#include <stdio.h>

#include "msg.h"
#include "shell.h"
#include "ccn-lite-riot.h"
#include "net/gnrc/netif.h"
#include "net/gnrc/pktdump.h"
#include "ccnl-callbacks.h"
#include "ccnl-producer.h"
#include "ccnl-ext-hmac.h"
#include "random.h"

/* main thread's message queue */
#define MAIN_QUEUE_SIZE     (8)
static msg_t _main_msg_queue[MAIN_QUEUE_SIZE];

gnrc_netif_t *mynetif;
uint8_t hwaddr[GNRC_NETIF_L2ADDR_MAXLEN];
char hwaddr_str[GNRC_NETIF_L2ADDR_MAXLEN * 3];
unsigned reqtx, resprx;
extern unsigned long rreqtx;

static unsigned char int_buf[CCNL_MAX_PACKET_SIZE];
static unsigned char data_buf[CCNL_MAX_PACKET_SIZE];

extern void install_routes(char *laddr, char *toaddr, char *nhaddr);

uint16_t narr[] = NARR;

static evtimer_t evtimer;
static evtimer_msg_event_t events[NARRNUM];

#if NDN_SEC
#include "crypto.h"
static uint8_t hmac_key[64] = { 0 };
uint8_t nonce[13] = { 0 };
uint8_t aes_key[16] = "secretPSK";
#endif

#define EVENT_TIME (1500 + random_uint32_range(0, 1000))

char *get_addr(uint16_t id)
{
#define MYMAP(NR,ID,ADDR)                                       \
    if (id == ID) {                                             \
        return ADDR;                                            \
    }
#include "idaddr.inc"
#undef MYMAP
    return NULL;
}

int my_app_RX(struct ccnl_relay_s *ccnl, struct ccnl_content_s *c)
{
    (void) ccnl;
    char s[CCNL_MAX_PREFIX_SIZE];
    unsigned long resprxt1 = 0, resprxt2 = 0;
    (void) resprxt1;
    (void) resprxt2;
    (void) s;

    resprxt1 = xtimer_now_usec();

#if NDN_SEC
    static uint8_t md[32];
    static size_t mdlen = sizeof(md);

    ccnl_hmac256_sign(hmac_key, sizeof(hmac_key), c->pkt->buf->data, c->pkt->buf->datalen - 34, md, &mdlen);

    uint16_t temp;
    dtls_decrypt((const unsigned char *)c->pkt->content, 10, (unsigned char *)&temp, nonce, aes_key, sizeof(aes_key), NULL, 0);
#endif

    ccnl_prefix_to_str(c->pkt->pfx, s, CCNL_MAX_PREFIX_SIZE);

    resprxt2  = xtimer_now_usec();

#if EXP_L2_PRINT==0
    printf("resprx;%lu;%lu;%.*s\n", resprxt1, resprxt2, 5, s+19);
#endif
    resprx++;

    return 0;
}


static void send_static_request(uint16_t nodeid)
{
    unsigned long reqtxt1 = 0, reqtxt2 = 0, reqtxt3 = 0;
    (void) reqtxt1;
    (void) reqtxt2;
    (void) reqtxt3;
    char req_uri[32];
    struct ccnl_prefix_s *prefix = NULL;
    static unsigned long i = 0;

    reqtx++;

    reqtxt1 = xtimer_now_usec();

    memset(int_buf, 0, CCNL_MAX_PACKET_SIZE);
    snprintf(req_uri, 32, "/temperature/%s/%05lu", get_addr(nodeid), i++);
    prefix = ccnl_URItoPrefix(req_uri, CCNL_SUITE_NDNTLV, NULL);

    reqtxt2 = xtimer_now_usec();

    ccnl_send_interest(prefix, int_buf, CCNL_MAX_PACKET_SIZE, NULL);
    ccnl_prefix_free(prefix);

    reqtxt3 = xtimer_now_usec();

#if EXP_L2_PRINT==0
    printf("reqtx;%lu;%lu;%lu;%05lu;%lu\n", reqtxt1, reqtxt2, reqtxt3, i-1, rreqtx);
#endif
}

static int _send_get(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    evtimer_init_msg(&evtimer);
    for (unsigned i = 0; i < NARRNUM; i++) {
        events[i].event.offset = (i+1) * 500;
        events[i].msg.content.value = i;
        evtimer_add_msg(&evtimer, &events[i], sched_active_pid);
    }
    unsigned i = 0;
    while ((i++) < 1000) {
        msg_t m;
        msg_receive(&m);
        send_static_request(i);
        events[m.content.value].event.offset = EVENT_TIME;
        evtimer_add_msg(&evtimer, &events[m.content.value], sched_active_pid);
    }
    return 0;
}

static struct ccnl_content_s *sensor_cont_and_cache(struct ccnl_relay_s *relay, struct ccnl_pkt_s *pkt)
{
    (void) pkt;
    (void) relay;
    size_t offs = CCNL_MAX_PACKET_SIZE;

//    char buffer[33];
//    size_t len = sprintf(buffer, "%s", "{\"id\":\"0x12a77af232\",\"val\":\"on\"}");
//    buffer[len]='\0';

    size_t reslen = 0;

#if NDN_SEC
    uint16_t temp_raw = 2124;
    uint8_t temp[16];
    uint16_t keyid = 0;
    int aeslen = dtls_encrypt((const unsigned char *)&temp_raw, sizeof(temp_raw), temp, nonce, aes_key, sizeof(aes_key), NULL, 0);

    ccnl_ndntlv_prependSignedContent(pkt->pfx, (unsigned char*) &temp, aeslen, NULL, NULL, hmac_key, (uint8_t *)&keyid, sizeof(keyid), &offs, data_buf, &reslen);
#else
    uint16_t temp = 2124;

    ccnl_ndntlv_prependContent(pkt->pfx, (unsigned char*) &temp, sizeof(temp), NULL, NULL, &offs, data_buf, &reslen);
#endif

    size_t len = sizeof(temp);

    unsigned char *olddata;
    unsigned char *data = olddata = data_buf + offs;

    uint64_t typ;

    if (ccnl_ndntlv_dehead(&data, &reslen, &typ, &len) || typ != NDN_TLV_Data) {
        puts("ERROR in producer_func");
        return 0;
    }

    struct ccnl_content_s *c = 0;
    struct ccnl_pkt_s *pk = ccnl_ndntlv_bytes2pkt(typ, olddata, &data, &reslen);
    //puts("CREATE CONTENT");
    c = ccnl_content_new(&pk);
    if (c) {
        //c->flags |= CCNL_CONTENT_FLAGS_STATIC;
        ccnl_content_add2cache(relay, c);
    }

    return c;
}

struct ccnl_content_s *sensor_producer_func(struct ccnl_relay_s *relay,
                                            struct ccnl_face_s *from,
                                            struct ccnl_pkt_s *pkt) {
    (void) relay;
    (void) from;

    if(pkt->pfx->compcnt == 3) { /* /hwaddr/temperature/<value> */
        if (!memcmp(pkt->pfx->comp[1], hwaddr_str, 5) &&
            !memcmp(pkt->pfx->comp[0], "temperature", pkt->pfx->complen[0])) {
            return sensor_cont_and_cache(relay, pkt);
        }
    }
    return NULL;
}

static const shell_command_t shell_commands[] = {
    { "send", "", _send_get },
    { NULL, NULL, NULL }
};

int main(void)
{
    msg_init_queue(_main_msg_queue, MAIN_QUEUE_SIZE);

    ccnl_core_init();

    ccnl_start();

    mynetif = gnrc_netif_iter(NULL);
    ccnl_open_netif(mynetif->pid, GNRC_NETTYPE_CCN);

    uint16_t src_len = 8U;
    gnrc_netapi_set(mynetif->pid, NETOPT_SRC_LEN, 0, &src_len, sizeof(src_len));
#ifdef BOARD_NATIVE
    gnrc_netapi_get(mynetif->pid, NETOPT_ADDRESS, 0, hwaddr, sizeof(hwaddr));
#else
    gnrc_netapi_get(mynetif->pid, NETOPT_ADDRESS_LONG, 0, hwaddr, sizeof(hwaddr));
#endif
    gnrc_netif_addr_to_str(hwaddr, sizeof(hwaddr), hwaddr_str);

#if 0
#ifdef MODULE_NETIF
    gnrc_netreg_entry_t dump = GNRC_NETREG_ENTRY_INIT_PID(GNRC_NETREG_DEMUX_CTX_ALL,
                                                          gnrc_pktdump_pid);
    gnrc_netreg_register(GNRC_NETTYPE_CCN_CHUNK, &dump);
#endif
#endif

    printf("addr;%s\n", hwaddr_str);

#if GW==0
    ccnl_set_local_producer(sensor_producer_func);
#endif

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
    puts("start");
    _send_get(0, NULL);
    xtimer_sleep(10);
    printf("end;%u;%u\n", reqtx, resprx);
#endif

    char line_buf[SHELL_DEFAULT_BUFSIZE];
    shell_run(shell_commands, line_buf, SHELL_DEFAULT_BUFSIZE);
    return 0;
}
