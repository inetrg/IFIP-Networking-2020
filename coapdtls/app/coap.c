#include <net/gcoap.h>

#include "od.h"
#include "random.h"
#include "dtls.h"

unsigned reqtx = 0, resprx = 0;
extern unsigned long rreqtx;

extern sock_dtls_t _tl_sock;
static sock_udp_ep_t remote = { .family = AF_INET6, .port = GCOAP_PORT,};

void get_addr(uint16_t id, ipv6_addr_t *address)
{
#define MYMAP(NR,ID,ADDR)                                       \
    if (id == ID) {                                             \
        char addrstr[] = ADDR;                                  \
        ipv6_addr_from_str(address, addrstr);                   \
        return;                                                 \
    }
#include "idaddr.inc"
#undef MYMAP
}

static void handle_static_response(const struct gcoap_request_memo *memo, coap_pkt_t *pdu, const sock_udp_ep_t *remote)
{
    (void)remote;
    unsigned long resprxt1 = 0, resprxt2 = 0;
    uint16_t msgid = ntohs(pdu->hdr->id);
    (void) msgid;
    (void) resprxt1;
    (void) resprxt2;

    resprxt1 = xtimer_now_usec();

    if (memo->state != GCOAP_MEMO_RESP) {
#if EXP_L2_PRINT==0
        printf("error;Request returned without a response\n");
#endif
        return;
    }

    resprxt2 = xtimer_now_usec();
#if EXP_L2_PRINT==0
    printf("resprx;%lu;%lu;%u\n", resprxt1, resprxt2, msgid);
#endif
    resprx++;

#if COAPDTLSSESSION
    if (random_uint32_range(0, 10) == 0) {
        remote = &memo->remote_ep;
        sock_dtls_session_t session;
        /* convert sock_udp_ep_t to sock_dtls_session_t */
        session.dtls_session.port = remote->port;
        session.dtls_session.ifindex = remote->netif;
        session.dtls_session.size = sizeof(ipv6_addr_t) + sizeof(unsigned short);
        memcpy(&session.dtls_session.addr, &remote->addr.ipv6, sizeof(ipv6_addr_t));
        memcpy(&session.ep, remote, sizeof(sock_udp_ep_t));
        dtls_peer_t *peer = dtls_get_peer(_tl_sock.dtls_ctx, &session.dtls_session);
        dtls_reset_peer(_tl_sock.dtls_ctx, peer);

//        sock_dtls_session_destroy(&_tl_sock, &session);
    }
#endif
    return;
}

void send_static_request(uint16_t nodeid) {
    unsigned long reqtxt1 = 0, reqtxt2 = 0, reqtxt3 = 0;
    (void) reqtxt1;
    (void) reqtxt2;
    (void) reqtxt3;

    uint8_t buf[GCOAP_PDU_BUF_SIZE];
    coap_pkt_t pdu;
    ipv6_addr_t addr;
    uint16_t msgid;
    (void) msgid;

    reqtx++;

    reqtxt1 = xtimer_now_usec();

    if (gnrc_netif_numof() == 1) {
        /* assign the single interface found in gnrc_netif_numof() */
        remote.netif = (uint16_t)gnrc_netif_iter(NULL)->pid;
    }
    else {
        remote.netif = SOCK_ADDR_ANY_NETIF;
    }

    /* parse destination address */
    get_addr(nodeid, &addr);
    memcpy(&remote.addr.ipv6[0], &addr.u8[0], sizeof(addr.u8));

    // Can't pre-set a path, the request must be empty at protection time
    ssize_t bytes;
    bytes = gcoap_request(&pdu, &buf[0], GCOAP_PDU_BUF_SIZE, COAP_METHOD_GET, "/temperature");
    if (bytes < 0) {
#if EXP_L2_PRINT==0
        printf("error;Failed to initialize request\n");
#endif
        return;
    }

    msgid = ntohs(pdu.hdr->id);

    coap_hdr_set_type(pdu.hdr, COAP_TYPE_CON);

    reqtxt2 = xtimer_now_usec();
    int bytes_sent = gcoap_req_send(buf, pdu.payload - (uint8_t*)pdu.hdr + pdu.payload_len, &remote, handle_static_response, NULL);
    if (bytes_sent <= 0) {
#if EXP_L2_PRINT==0
        printf("error;sending\n");
#endif
        return;
    }
    reqtxt3 = xtimer_now_usec();
#if EXP_L2_PRINT==0
    printf("reqtx;%lu;%lu;%lu;%u;%lu\n", reqtxt1, reqtxt2, reqtxt3, msgid, rreqtx);
#endif

    return;
}

static ssize_t app_coap(coap_pkt_t* pdu, uint8_t *buf, size_t len, void *ctx)
{
    (void)ctx;
    unsigned long reqrxt1 = 0, reqrxt2 = 0, resptxt1 = 0, resptxt2 = 0, resptxt3 = 0;
    (void) reqrxt1;
    (void) reqrxt2;
    (void) resptxt1;
    (void) resptxt2;
    (void) resptxt3;

    reqrxt1 = xtimer_now_usec();
    uint16_t msgid = ntohs(pdu->hdr->id);
    (void) msgid;
    reqrxt2 = xtimer_now_usec();
#if EXP_L2_PRINT==0
    printf("reqrx;%lu;%lu;%u\n", reqrxt1, reqrxt2, msgid);
#endif

    resptxt1 = xtimer_now_usec();
    gcoap_resp_init(pdu, buf, len, COAP_CODE_CONTENT);
    size_t resp_len = coap_opt_finish(pdu, COAP_OPT_FINISH_PAYLOAD);
    msgid = ntohs(pdu->hdr->id);
    resptxt2 = xtimer_now_usec();

    uint16_t temp = 2124;
    memcpy(pdu->payload, &temp, sizeof(temp));
    resptxt3 = xtimer_now_usec();
#if EXP_L2_PRINT==0
    printf("resptx;%lu;%lu;%lu;%u\n", resptxt1, resptxt2, resptxt3, msgid);
#endif

    return resp_len + sizeof(temp);
}

static const coap_resource_t _resources[] = {
    { "/temperature", COAP_GET, app_coap, NULL },
};

gcoap_listener_t app_listener = {
    &_resources[0],
    ARRAY_SIZE(_resources),
    NULL,
    NULL
};
