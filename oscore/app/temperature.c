#include <oscore_native/message.h>
#include <oscore/message.h>
#include <oscore/contextpair.h>
#include <oscore/context_impl/primitive.h>
#include <oscore/protection.h>

void temperature_parse(oscore_msg_protected_t *in, void *vstate)
{
    uint16_t *responsecode = vstate;

    switch (oscore_msg_protected_get_code(in)) {
        case COAP_GET:
            *responsecode = COAP_CODE_205;
            break;
        default:
            *responsecode = COAP_CODE_METHOD_NOT_ALLOWED;
            break;
    }
}

void temperature_build(oscore_msg_protected_t *out, const void *vstate)
{
    const uint16_t *responsecode = vstate;

    oscore_msg_protected_set_code(out, *responsecode);

    if (*responsecode == COAP_CODE_205) {
        uint8_t *payload;
        size_t payload_length;
        oscore_msgerr_protected_t err = oscore_msg_protected_map_payload(out, &payload, &payload_length);
        if (oscore_msgerr_protected_is_error(err)) {
            oscore_msg_protected_set_code(out, COAP_CODE_INTERNAL_SERVER_ERROR);
            oscore_msg_protected_trim_payload(out, 0);
            return;
        }
        uint16_t temp = 2124;
        memcpy(payload, &temp, sizeof(temp));
        oscore_msg_protected_trim_payload(out, sizeof(temp));
    } else {
        oscore_msg_protected_trim_payload(out, 0);
    }
}
