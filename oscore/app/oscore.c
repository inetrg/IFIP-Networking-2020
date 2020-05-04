#include <net/gcoap.h>
#include <oscore_native/message.h>
#include <oscore/message.h>
#include <oscore/contextpair.h>
#include <oscore/context_impl/primitive.h>
#include <oscore/protection.h>

#define SENDER_KEY {50, 136, 42, 28, 97, 144, 48, 132, 56, 236, 152, 230, 169, 50, 240, 32, 112, 143, 55, 57, 223, 228, 109, 119, 152, 155, 3, 155, 31, 252, 28, 172}
#define RECIPIENT_KEY {213, 48, 30, 177, 141, 6, 120, 73, 149, 8, 147, 186, 42, 200, 145, 65, 124, 137, 174, 9, 223, 74, 56, 85, 170, 0, 10, 201, 255, 243, 135, 81}
#define COMMON_IV {100, 240, 189, 49, 77, 75, 224, 60, 39, 12, 43, 28, 17}

extern void temperature_parse(oscore_msg_protected_t *in, void *vstate);
extern void temperature_build(oscore_msg_protected_t *out, const void *vstate);

static sock_udp_ep_t remote = { .family = AF_INET6, .port = 5683,};

unsigned reqtx = 0, resprx = 0;
extern unsigned long rreqtx;

#if GW
static struct oscore_context_primitive prims[NARRNUM] = {
#define MYMAP(NR,ID,ADDR)                       \
    {                                           \
    .aeadalg = 10,                              \
    .common_iv = COMMON_IV,                     \
    .recipient_id_len = 0,                      \
    .recipient_key = RECIPIENT_KEY,             \
    .sender_id_len = 1,                         \
    .sender_id = "\x08",                        \
    .sender_key = SENDER_KEY,                   \
    },
#include "idaddr.inc"
#undef MYMAP
};
static oscore_context_t seccs[NARRNUM] = {
#define MYMAP(NR,ID,ADDR)                       \
{                                               \
    .type = OSCORE_CONTEXT_PRIMITIVE,           \
    .data = (void*)(&prims[NR]),                \
},
#include "idaddr.inc"
#undef MYMAP
};
#else
static struct oscore_context_primitive prim = {
    .aeadalg = 10,
    .common_iv = COMMON_IV,
    .recipient_id = "\x08",
    .recipient_id_len = 1,
    .recipient_key = SENDER_KEY,
    .sender_id_len = 0,
//    .sender_id = NODE_KID,
    .sender_key = RECIPIENT_KEY,
};

static oscore_context_t secc = {
    .type = OSCORE_CONTEXT_PRIMITIVE,
    .data = (void*)(&prim),
};
#endif

oscore_context_t *get_security(uint16_t recipient_id)
{
#if GW
    (void) recipient_id;
#define MYMAP(NR,ID,ADDR) if (recipient_id == ID) { return &seccs[NR]; }
#include "idaddr.inc"
#undef MYMAP
    return NULL;
#else
    (void) recipient_id;
    return &secc;
#endif
}

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

#if GW
ssize_t app_oscore(coap_pkt_t *pdu, uint8_t *buf, size_t len, void *ctx)
{
    (void) ctx;
    uint8_t errorcode = COAP_CODE_INTERNAL_SERVER_ERROR;
    return gcoap_response(pdu, buf, len, errorcode);
}
#else
ssize_t app_oscore(coap_pkt_t *pdu, uint8_t *buf, size_t len, void *ctx)
{
    unsigned long reqrxt1 = 0, reqrxt2 = 0, resptxt1 = 0, resptxt2 = 0, resptxt3 = 0;
    (void) reqrxt1;
    (void) reqrxt2;
    (void) resptxt1;
    (void) resptxt2;
    (void) resptxt3;
    reqrxt1 = xtimer_now_usec();
    uint16_t msgid = ntohs(pdu->hdr->id);
    (void) msgid;

    (void) ctx;

    enum oscore_unprotect_request_result oscerr;
    oscore_oscoreoption_t header;
    oscore_requestid_t request_id;
    const char *errormessage = "";
    (void) errormessage;

    uint8_t errorcode = COAP_CODE_INTERNAL_SERVER_ERROR;

    // This is nanocoap's shortcut (compare to unprotect-demo, where we iterate through the outer options)
    uint8_t *header_data;
    ssize_t header_size = coap_opt_get_opaque(pdu, 9, &header_data);
    if (header_size < 0) {
        errormessage = "No OSCORE option found";
        // Having a </> resource in parallel to OSCORE is not supported here.
        errorcode = COAP_CODE_PATH_NOT_FOUND;
        goto error;
    }
    bool parsed = oscore_oscoreoption_parse(&header, header_data, header_size);
    if (!parsed) {
        errormessage = "OSCORE option unparsable";
        errorcode = COAP_CODE_BAD_OPTION;
        goto error;
    }

    // FIXME: this should be in a dedicated parsed_pdu_to_oscore_msg_native_t process
    // (and possibly foolishly assuming that there is a payload marker)
    pdu->payload --;
    pdu->payload_len ++;
    oscore_msg_native_t pdu_read = { .pkt = pdu };
    oscore_msg_protected_t incoming_decrypted;

    oscore_context_t *mysecc = &secc;
    oscerr = oscore_unprotect_request(pdu_read, &incoming_decrypted, header, mysecc, &request_id);

    if (oscerr != OSCORE_UNPROTECT_REQUEST_OK) {
        if (oscerr != OSCORE_UNPROTECT_REQUEST_DUPLICATE) {
            errormessage = "Unprotect failed";
            errorcode = COAP_CODE_BAD_REQUEST;
            goto error;
        }
    }

    uint16_t responsecode;
    temperature_parse(&incoming_decrypted, &responsecode);

    oscore_msg_native_t pdu_read_out = oscore_release_unprotected(&incoming_decrypted);
    reqrxt2 = xtimer_now_usec();
#if EXP_L2_PRINT==0
    printf("reqrx;%lu;%lu;%u\n", reqrxt1, reqrxt2, msgid);
#endif
    assert(pdu_read_out.pkt == pdu);

    resptxt1 = xtimer_now_usec();
    gcoap_resp_init(pdu, buf, len, COAP_CODE_CONTENT);
    msgid = ntohs(pdu->hdr->id);

    enum oscore_prepare_result oscerr2;
    oscore_msg_native_t pdu_write = { .pkt = pdu };
    oscore_msg_protected_t outgoing_plaintext;

    oscerr2 = oscore_prepare_response(pdu_write, &outgoing_plaintext, mysecc, &request_id);
    if (oscerr2 != OSCORE_PREPARE_OK) {
        errormessage = "Context not usable";
        errorcode = COAP_CODE_SERVICE_UNAVAILABLE;
        goto error;
    }

    temperature_build(&outgoing_plaintext, &responsecode);
    resptxt2 = xtimer_now_usec();

    enum oscore_finish_result oscerr4;
    oscore_msg_native_t pdu_write_out;
    oscerr4 = oscore_encrypt_message(&outgoing_plaintext, &pdu_write_out);
    if (oscerr4 != OSCORE_FINISH_OK) {
        errormessage = "Error finishing";
        goto error;
    }
    assert(pdu == pdu_write_out.pkt);

    resptxt3 = xtimer_now_usec();
#if EXP_L2_PRINT==0
    printf("resptx;%lu;%lu;%lu;%u\n", resptxt1, resptxt2, resptxt3, msgid);
#endif
    return (pdu->payload - buf) + pdu->payload_len;

error:
    resptxt3 = xtimer_now_usec();
#if EXP_L2_PRINT==0
    printf("error;%s;%u\n", errormessage, msgid);
#endif
    return gcoap_response(pdu, buf, len, errorcode);
}
#endif

static void handle_static_response(const struct gcoap_request_memo *memo, coap_pkt_t *pdu, const sock_udp_ep_t *remote)
{
    (void)remote;
    unsigned long resprxt1 = 0, resprxt2 = 0;
    uint16_t msgid = ntohs(pdu->hdr->id);
    (void) resprxt1;
    (void) resprxt2;
    (void) msgid;

    resprxt1 = xtimer_now_usec();
    oscore_requestid_t *request_id = (oscore_requestid_t *)&memo->oscore_request_id;

    if (memo->state != GCOAP_MEMO_RESP) {
#if EXP_L2_PRINT==0
        printf("error;Request returned without a response\n");
#endif
        return;
    }
    oscore_oscoreoption_t header;

    // This is nanocoap's shortcut (compare to unprotect-demo, where we iterate through the outer options)
    uint8_t *header_data;
    ssize_t header_size = coap_opt_get_opaque(pdu, 9, &header_data);
    if (header_size < 0) {
#if EXP_L2_PRINT==0
        printf("error;No OSCORE option in response!;%u\n", msgid);
#endif
        return;
    }
    bool parsed = oscore_oscoreoption_parse(&header, header_data, header_size);
    if (!parsed) {
#if EXP_L2_PRINT==0
        printf("error;OSCORE option unparsable\n");
#endif
        return;
    }
    // FIXME: this should be in a dedicated parsed_pdu_to_oscore_msg_native_t process
    // (and possibly foolishly assuming that there is a payload marker)
    pdu->payload --;
    pdu->payload_len ++;
    oscore_msg_native_t pdu_read = { .pkt = pdu };

    oscore_msg_protected_t msg;

    oscore_context_t *secc = (oscore_context_t *)request_id->sctx;
    enum oscore_unprotect_response_result success = oscore_unprotect_response(pdu_read, &msg, header, secc, request_id);

    if (success == OSCORE_UNPROTECT_RESPONSE_OK) {
        uint8_t code = oscore_msg_protected_get_code(&msg);
        if (code == COAP_CODE_205) {
            //printf("Result: Changed\n");
        }
        else {
            //printf("Unknown code in result: %d.%d\n", code >> 5, code & 0x1f);
            return;
        }
    } else {
#if EXP_L2_PRINT==0
        printf("error;unprotecting response\n");
#endif
        return;
    }

    uint8_t *payload;
    size_t payload_length;
    oscore_msgerr_protected_t err = oscore_msg_protected_map_payload(&msg, &payload, &payload_length);
    if (oscore_msgerr_protected_is_error(err)) {
#if EXP_L2_PRINT==0
        printf("error;accessing payload\n");
#endif
        return;
    }
//    uint16_t temp;
//    memcpy(&temp, payload, sizeof(temp));
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
    oscore_msg_protected_t oscmsg;
    oscore_requestid_t request_id;
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
    int err;
    err = gcoap_req_init(&pdu, buf, sizeof(buf), COAP_POST, NULL);
    if (err != 0) {
#if EXP_L2_PRINT==0
        printf("error;Failed to initialize request\n");
#endif
        return;
    }

    msgid = ntohs(pdu.hdr->id);

    coap_hdr_set_type(pdu.hdr, COAP_TYPE_CON);

    oscore_msg_native_t native = { .pkt = &pdu };

    oscore_context_t *secc = get_security(nodeid);
    if (oscore_prepare_request(native, &oscmsg, secc, &request_id) != OSCORE_PREPARE_OK) {
#if EXP_L2_PRINT==0
        printf("error;Failed to prepare request encryption\n");
#endif
        return;
    }

    oscore_msg_protected_set_code(&oscmsg, COAP_GET);
    
    oscore_msgerr_protected_t oscerr;
    oscerr = oscore_msg_protected_append_option(&oscmsg, COAP_OPT_URI_PATH, (uint8_t*)"temperature", 11);
    if (oscore_msgerr_protected_is_error(oscerr)) {
#if EXP_L2_PRINT==0
        printf("error;Failed to add option\n");
#endif
        return;
    }

    oscerr = oscore_msg_protected_trim_payload(&oscmsg, 0);
    if (oscore_msgerr_protected_is_error(oscerr)) {
#if EXP_L2_PRINT==0
        printf("error;Failed to truncate payload\n");
#endif
        return;
    }

    oscore_msg_native_t pdu_write_out;
    if (oscore_encrypt_message(&oscmsg, &pdu_write_out) != OSCORE_FINISH_OK) {
#if EXP_L2_PRINT==0
        printf("error;Failed to encrypt message\n");
#endif
        return;
    }

    request_id.sctx = (void *)secc;

    reqtxt2 = xtimer_now_usec();
    int bytes_sent = gcoap_req_send(buf, pdu.payload - (uint8_t*)pdu.hdr + pdu.payload_len, &remote, handle_static_response, &request_id);
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
