#include "hipa_secfile.h"
#include "sbox.h"

#include <stdlib.h>
#include <string.h>

static uint8_t SA[256], SB[256], SK[256];
static int g_boxes_ready = 0;

static void build_boxes(void)
{
    if (g_boxes_ready) return;
    for (int x = 0; x < 256; x++) {
        SA[x] = HIPA_SBOX2[HIPA_SBOX1[x]];
        SB[x] = HIPA_SBOX2[HIPA_SBOX3[x]];
        SK[x] = HIPA_SBOX1[HIPA_SBOX2[x]];
    }
    g_boxes_ready = 1;
}

static const char B64_ALPHABET[] =
    "JscAp92$eUdnSKLBaTiQrZM!ImklVWjwxoh6gDPOyzN01GH4qEtuCR7F8XYv5bf3";

static void b64_table(int8_t tbl[256])
{
    for (int i = 0; i < 256; i++) tbl[i] = -1;
    for (int i = 0; i < 64; i++) tbl[(uint8_t)B64_ALPHABET[i]] = (int8_t)i;
}

long hipa_base64_decode(const char *text, size_t text_len,
                        uint8_t *out, size_t out_cap)
{
    int8_t tbl[256];
    b64_table(tbl);

    size_t produced = 0;
    int quad[4];
    int have = 0;

    for (size_t i = 0; i < text_len; i++) {
        unsigned char ch = (unsigned char)text[i];
        if (ch == '^') break;
        int8_t v = tbl[ch];
        if (v < 0) break;
        quad[have++] = v;
        if (have == 4) {
            uint8_t o0 = (uint8_t)((quad[0] << 2) | (quad[1] >> 4));
            uint8_t o1 = (uint8_t)((quad[1] << 4) | (quad[2] >> 2));
            uint8_t o2 = (uint8_t)((quad[2] << 6) | quad[3]);
            if (out) {
                if (produced + 3 > out_cap) return HIPA_ERR_NOMEM;
                out[produced] = o0; out[produced + 1] = o1; out[produced + 2] = o2;
            }
            produced += 3;
            have = 0;
        }
    }
    if (have) {
        while (have < 4) quad[have++] = 0;
        uint8_t o0 = (uint8_t)((quad[0] << 2) | (quad[1] >> 4));
        uint8_t o1 = (uint8_t)((quad[1] << 4) | (quad[2] >> 2));
        uint8_t o2 = (uint8_t)((quad[2] << 6) | quad[3]);
        if (out) {
            if (produced + 3 > out_cap) return HIPA_ERR_NOMEM;
            out[produced] = o0; out[produced + 1] = o1; out[produced + 2] = o2;
        }
        produced += 3;
    }
    return (long)produced;
}

#define HIPA_RK_LEN 544

static void key_schedule(uint32_t seed, uint8_t rk[HIPA_RK_LEN])
{
    static const uint8_t PERM[32] = {
        0, 4, 8, 12, 16, 20, 24, 28,  1, 5, 9, 13, 17, 21, 25, 29,
        2, 6, 10, 14, 18, 22, 26, 30,  3, 7, 11, 15, 19, 23, 27, 31
    };
    memset(rk, 0x13, HIPA_RK_LEN);
    rk[0] = (uint8_t)seed;  rk[1] = (uint8_t)(seed >> 8);
    rk[2] = (uint8_t)(seed >> 16); rk[3] = (uint8_t)(seed >> 24);
    rk[32] = rk[0]; rk[33] = rk[1]; rk[34] = rk[2]; rk[35] = rk[3];

    for (int it = 0; it < 15; it++) {
        const uint8_t *in = rk + 32 * (it + 1);
        uint8_t *out = rk + 32 * (it + 2);
        for (int k = 0; k < 32; k++)
            out[k] = SK[in[PERM[(k + 1) & 31]]];
    }
}

static void decrypt_block(const uint8_t in[16], const uint8_t rk[HIPA_RK_LEN],
                          uint8_t out[16])
{
    uint8_t s[16], ns[16];
    memcpy(s, in, 16);
    for (int r = 0; r < 16; r++) {
        const uint8_t *hi = rk + 16 * (33 - 2 * r);
        const uint8_t *lo = rk + 16 * (32 - 2 * r);
        for (int i = 0; i < 16; i++)
            ns[i] = SB[lo[(i + 8) & 15] ^ SA[hi[i] ^ s[i]]];
        memcpy(s, ns, 16);
    }
    memcpy(out, s, 16);
}

static uint32_t rd_u32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

hipa_status hipa_decrypt_container(const uint8_t *blob, size_t blob_len,
                                   uint8_t **out, size_t *out_len)
{
    build_boxes();

    if (blob_len < 12) return HIPA_ERR_FORMAT;
    uint32_t magic = rd_u32(blob);
    if (magic != 20231212u && magic != 20211102u) return HIPA_ERR_MAGIC;
    uint32_t len1 = rd_u32(blob + 4);

    size_t v23 = (size_t)8 + len1 + (magic == 20231212u ? 8u : 0u);
    if (v23 + 8 > blob_len) return HIPA_ERR_FORMAT;

    uint32_t seed = rd_u32(blob + v23);
    uint32_t len2 = rd_u32(blob + v23 + 4);
    const uint8_t *ct = blob + v23 + 8;
    if (v23 + 8u + len2 > blob_len) return HIPA_ERR_FORMAT;

    uint8_t rk[HIPA_RK_LEN];
    key_schedule(seed, rk);
    const uint8_t *iv = rk;

    uint8_t *dec = (uint8_t *)malloc(len2 ? len2 : 1);
    if (!dec) return HIPA_ERR_NOMEM;

    size_t nb = ((size_t)len2 + 15) / 16;
    for (size_t bi = 0; bi < nb; bi++) {
        uint8_t cb[16] = {0}, db[16];
        size_t off = 16 * bi;
        size_t sz = (off + 16 <= len2) ? 16 : (len2 - off);
        memcpy(cb, ct + off, sz);
        decrypt_block(cb, rk, db);
        const uint8_t *prev = (bi > 0) ? (ct + off - 16) : iv;
        for (size_t i = 0; i < sz; i++)
            dec[off + i] = db[i] ^ prev[i];
    }

    uint8_t *pt = (uint8_t *)malloc(len2 ? len2 : 1);
    if (!pt) { free(dec); return HIPA_ERR_NOMEM; }
    size_t nd = len2 >> 2;
    uint32_t prev = seed;
    for (size_t i = 0; i < nd; i++) {
        uint32_t d = rd_u32(dec + i * 4);
        uint32_t o = d ^ prev;
        pt[i * 4]     = (uint8_t)o;
        pt[i * 4 + 1] = (uint8_t)(o >> 8);
        pt[i * 4 + 2] = (uint8_t)(o >> 16);
        pt[i * 4 + 3] = (uint8_t)(o >> 24);
        prev = d;
    }
    size_t tail = len2 & 3u;
    for (size_t i = 0; i < tail; i++)
        pt[nd * 4 + i] = dec[nd * 4 + i];

    free(dec);
    *out = pt;
    *out_len = len2;
    return HIPA_OK;
}

hipa_status hipa_decrypt(const char *raw_text, size_t raw_len,
                         uint8_t **out, size_t *out_len)
{
    long need = hipa_base64_decode(raw_text, raw_len, NULL, 0);
    if (need < 0) return (hipa_status)need;

    uint8_t *blob = (uint8_t *)malloc((size_t)need ? (size_t)need : 1);
    if (!blob) return HIPA_ERR_NOMEM;

    long n = hipa_base64_decode(raw_text, raw_len, blob, (size_t)need);
    if (n < 0) { free(blob); return (hipa_status)n; }

    hipa_status st = hipa_decrypt_container(blob, (size_t)n, out, out_len);
    free(blob);
    return st;
}

uint32_t hipa_key_hash(const char *name, uint32_t channel_key)
{
    uint32_t hash = 0, a = 63689u;
    const uint32_t b = 378551u;
    for (const unsigned char *p = (const unsigned char *)name; *p; p++) {
        hash = channel_key ^ (a * hash + *p);
        a *= b;
    }
    return hash;
}

const char *hipa_strerror(hipa_status s)
{
    switch (s) {
        case HIPA_OK:          return "ok";
        case HIPA_ERR_BASE64:  return "invalid base64";
        case HIPA_ERR_MAGIC:   return "unrecognized container magic";
        case HIPA_ERR_FORMAT:  return "malformed container";
        case HIPA_ERR_NOMEM:   return "out of memory";
    }
    return "unknown error";
}
