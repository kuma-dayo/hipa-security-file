#ifndef HIPA_SECFILE_H
#define HIPA_SECFILE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    HIPA_OK = 0,
    HIPA_ERR_BASE64 = -1,
    HIPA_ERR_MAGIC  = -2,
    HIPA_ERR_FORMAT = -3,
    HIPA_ERR_NOMEM  = -4,
} hipa_status;

long hipa_base64_decode(const char *text, size_t text_len,
                        uint8_t *out, size_t out_cap);

hipa_status hipa_decrypt_container(const uint8_t *blob, size_t blob_len,
                                   uint8_t **out, size_t *out_len);

hipa_status hipa_decrypt(const char *raw_text, size_t raw_len,
                         uint8_t **out, size_t *out_len);

uint32_t hipa_key_hash(const char *name, uint32_t channel_key);

const char *hipa_strerror(hipa_status s);

#ifdef __cplusplus
}
#endif

#endif
