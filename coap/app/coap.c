#include <net/gcoap.h>
#include "od.h"

#if CHACHAPOLY
#include "monocypher.h"
uint8_t chacha_key[32] = "secretPSK";
uint8_t nonce[24] = { 0 };
#elif AESCCM
#include "crypto.h"
uint8_t nonce[13] = { 0 };
uint8_t aes_key[16] = "secretPSK";
uint16_t keyid = 0;
#endif

unsigned reqtx = 0, resprx = 0;
extern unsigned long rreqtx;

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


#if CHACHAPOLY
    uint16_t temp;
    crypto_unlock((uint8_t *)&temp, chacha_key, nonce, ((uint8_t *)pdu->payload)+2, pdu->payload, 2);
#elif AESCCM
    uint16_t temp;
    dtls_decrypt(((const unsigned char *) pdu->payload)+4, 10, (unsigned char *)&temp, nonce, aes_key, sizeof(aes_key), NULL, 0);
#endif

    resprxt2 = xtimer_now_usec();
#if EXP_L2_PRINT==0
    printf("resprx;%lu;%lu;%u\n", resprxt1, resprxt2, msgid);
#endif
    resprx++;
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

#if CHACHAPOLY
    uint8_t mac[16];
    uint16_t temp_encr;
    crypto_lock(mac, (uint8_t *)&temp_encr, chacha_key, nonce, (uint8_t *)&temp, sizeof(temp));
    memcpy(pdu->payload, &temp_encr, sizeof(temp_encr));
    memcpy(pdu->payload + sizeof(temp_encr), mac, sizeof(mac));
#elif AESCCM
    memcpy(pdu->payload, (uint8_t *)&keyid, 2);
    memcpy(pdu->payload + 2, nonce, 2);
    int aeslen = dtls_encrypt((const unsigned char *)&temp, sizeof(temp), pdu->payload+4, nonce, aes_key, sizeof(aes_key), NULL, 0);
#endif

    resptxt3 = xtimer_now_usec();
#if EXP_L2_PRINT==0
    printf("resptx;%lu;%lu;%lu;%u\n", resptxt1, resptxt2, resptxt3, msgid);
#endif
#if CHACHAPOLY
    return resp_len + sizeof(temp_encr) + sizeof(mac);
#elif AESCCM
    return resp_len + 2 + 2 + aeslen;
#else
    return resp_len + sizeof(temp);
#endif
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
