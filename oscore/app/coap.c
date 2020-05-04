#include <net/gcoap.h>
#include "od.h"

extern ssize_t app_oscore(coap_pkt_t *pdu, uint8_t *buf, size_t len, void *ctx);

static const coap_resource_t _resources[] = {
    { "/", COAP_POST, app_oscore, NULL },
};

gcoap_listener_t app_listener = {
    &_resources[0],
    ARRAY_SIZE(_resources),
    NULL,
    NULL
};
