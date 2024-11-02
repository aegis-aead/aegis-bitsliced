#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"
#include "include/aegis.h"
#include "include/aegis256.h"

#include "aes-bs8.h"

#define RATE      16
#define ALIGNMENT 16

static void
aegis_round(AesBlocks st)
{
    AesBlocks st1;
    size_t    i;

    memcpy(st1, st, sizeof(AesBlocks));
    pack(st1);
    aes_round(st);
    unpack(st1);

    for (i = 0; i < 6; i++) {
        st[word_idx(i, 0)] ^= st1[word_idx((i - 1) % 6, 0)];
        st[word_idx(i, 1)] ^= st1[word_idx((i - 1) % 6, 1)];
        st[word_idx(i, 2)] ^= st1[word_idx((i - 1) % 6, 2)];
        st[word_idx(i, 3)] ^= st1[word_idx((i - 1) % 6, 3)];
    }

#if defined(ALT_REGISTER_ALLOCATION) && defined(KEEP_STATE_BITSLICED)
    (void) pack2;
    (void) unpack2;
    (void) aes_round2;
#endif
}

static inline void
aegis_absorb_rate(AesBlocks st, const AesBlock m)
{
    st[word_idx(0, 0)] ^= m[0];
    st[word_idx(0, 1)] ^= m[1];
    st[word_idx(0, 2)] ^= m[2];
    st[word_idx(0, 3)] ^= m[3];
}

static inline void
aegis_update(AesBlocks st, const AesBlock m)
{
    aegis_round(st);
    aegis_absorb_rate(st, m);
}

static void
aegis256_init(const uint8_t *key, const uint8_t *nonce, AesBlocks st)
{
    const AesBlock c0 = { 0x02010100, 0x0d080503, 0x59372215, 0x6279e990 };
    const AesBlock c1 = { 0x55183ddb, 0xf12fc26d, 0x42311120, 0xdd28b573 };
    AesBlock       k0, k1, n0, n1, k0n0, k1n1, k0c0, k1c1;
    int            i;

    block_from_bytes(k0, key);
    block_from_bytes(k1, key + 16);
    block_from_bytes(n0, nonce);
    block_from_bytes(n1, nonce + 16);
    block_xor(k0n0, k0, n0);
    block_xor(k1n1, k1, n1);
    block_xor(k0c0, k0, c0);
    block_xor(k1c1, k1, c1);

    memset(st, 0, sizeof(AesBlocks));
    blocks_put(st, k0n0, 0);
    blocks_put(st, k1n1, 1);
    blocks_put(st, c1, 2);
    blocks_put(st, c0, 3);
    blocks_put(st, k0c0, 4);
    blocks_put(st, k1c1, 5);

    for (i = 0; i < 4; i++) {
        aegis_update(st, k0);
        aegis_update(st, k1);
        aegis_update(st, k0n0);
        aegis_update(st, k1n1);
    }
}

static void
aegis256_absorb(const uint8_t *const src, AesBlocks st)
{
    AesBlock msg;

    aegis_round(st);
    block_from_bytes(msg, src);
    aegis_absorb_rate(st, msg);
}

static void
aegis256_enc(uint8_t *const dst, const uint8_t *const src, AesBlocks st)
{
    AesBlock t, z;
    AesBlock out;
    size_t   i;

    for (i = 0; i < 4; i++) {
        z[i] = st[word_idx(4, i)] ^ st[word_idx(5, i)] ^ (st[word_idx(2, i)] & st[word_idx(3, i)]);
    }
    aegis_round(st);
    block_from_bytes(t, src);
    aegis_absorb_rate(st, t);
    block_xor(out, t, z);
    block_to_bytes(dst, out);
}

static void
aegis256_dec(uint8_t *const dst, const uint8_t *const src, AesBlocks st)
{
    AesBlock msg;
    size_t   i;

    block_from_bytes(msg, src);
    for (i = 0; i < 4; i++) {
        msg[i] ^=
            st[word_idx(4, i)] ^ st[word_idx(5, i)] ^ (st[word_idx(2, i)] & st[word_idx(3, i)]);
    }
    block_to_bytes(dst, msg);
    aegis_update(st, msg);
}

static void
aegis256_declast(uint8_t *const dst, const uint8_t *const src, size_t len, AesBlocks st)
{
    uint8_t  pad[RATE];
    AesBlock msg;
    size_t   i;

    memset(pad, 0, sizeof pad);
    memcpy(pad, src, len);

    block_from_bytes(msg, pad);
    for (i = 0; i < 4; i++) {
        msg[i] ^=
            st[word_idx(4, i)] ^ st[word_idx(5, i)] ^ (st[word_idx(2, i)] & st[word_idx(3, i)]);
    }
    aegis_round(st);
    block_to_bytes(pad, msg);
    memset(pad + len, 0, sizeof pad - len);
    memcpy(dst, pad, len);
    block_from_bytes(msg, pad);
    aegis_absorb_rate(st, msg);
}

static void
aegis256_mac(uint8_t *mac, size_t maclen, size_t adlen, size_t mlen, AesBlocks st)
{
    AesBlock tmp;
    size_t   i;

    tmp[0] = (uint32_t) (adlen << 3);
    tmp[1] = (uint32_t) (adlen >> (32 - 3));
    tmp[2] = (uint32_t) (mlen << 3);
    tmp[3] = (uint32_t) (mlen >> (32 - 3));

    tmp[0] ^= st[word_idx(3, 0)];
    tmp[1] ^= st[word_idx(3, 1)];
    tmp[2] ^= st[word_idx(3, 2)];
    tmp[3] ^= st[word_idx(3, 3)];

    for (i = 0; i < 7; i++) {
        aegis_update(st, tmp);
    }

    if (maclen == 16) {
        for (i = 0; i < 4; i++) {
            tmp[i] = st[word_idx(0, i)] ^ st[word_idx(1, i)] ^ st[word_idx(2, i)] ^
                     st[word_idx(3, i)] ^ st[word_idx(4, i)] ^ st[word_idx(5, i)];
        }
        block_to_bytes(mac, tmp);
    } else if (maclen == 32) {
        for (i = 0; i < 4; i++) {
            tmp[i] = st[word_idx(0, i)] ^ st[word_idx(1, i)] ^ st[word_idx(2, i)];
        }
        block_to_bytes(mac, tmp);
        for (i = 0; i < 4; i++) {
            tmp[i] = st[word_idx(3, i)] ^ st[word_idx(4, i)] ^ st[word_idx(5, i)];
        }
        block_to_bytes(mac + 16, tmp);
    } else {
        memset(mac, 0, maclen);
    }
}

size_t
aegis256_keybytes(void)
{
    return aegis256_KEYBYTES;
}

size_t
aegis256_npubbytes(void)
{
    return aegis256_NPUBBYTES;
}

size_t
aegis256_abytes_min(void)
{
    return aegis256_ABYTES_MIN;
}

size_t
aegis256_abytes_max(void)
{
    return aegis256_ABYTES_MAX;
}

int
aegis256_encrypt_detached(uint8_t *c, uint8_t *mac, size_t maclen, const uint8_t *m, size_t mlen,
                          const uint8_t *ad, size_t adlen, const uint8_t *npub, const uint8_t *k)
{
    AesBlocks                       state;
    CRYPTO_ALIGN(ALIGNMENT) uint8_t src[RATE];
    CRYPTO_ALIGN(ALIGNMENT) uint8_t dst[RATE];
    size_t                          i;

    aegis256_init(k, npub, state);

    for (i = 0; i + RATE <= adlen; i += RATE) {
        aegis256_absorb(ad + i, state);
    }
    if (adlen % RATE) {
        memset(src, 0, RATE);
        memcpy(src, ad + i, adlen % RATE);
        aegis256_absorb(src, state);
    }
    for (i = 0; i + RATE <= mlen; i += RATE) {
        aegis256_enc(c + i, m + i, state);
    }
    if (mlen % RATE) {
        memset(src, 0, RATE);
        memcpy(src, m + i, mlen % RATE);
        aegis256_enc(dst, src, state);
        memcpy(c + i, dst, mlen % RATE);
    }
    aegis256_mac(mac, maclen, adlen, mlen, state);

    return 0;
}

int
aegis256_encrypt(uint8_t *c, size_t maclen, const uint8_t *m, size_t mlen, const uint8_t *ad,
                 size_t adlen, const uint8_t *npub, const uint8_t *k)
{
    return aegis256_encrypt_detached(c, c + mlen, maclen, m, mlen, ad, adlen, npub, k);
}

int
aegis256_decrypt_detached(uint8_t *m, const uint8_t *c, size_t clen, const uint8_t *mac,
                          size_t maclen, const uint8_t *ad, size_t adlen, const uint8_t *npub,
                          const uint8_t *k)
{
    AesBlocks                       state;
    CRYPTO_ALIGN(ALIGNMENT) uint8_t src[RATE];
    CRYPTO_ALIGN(ALIGNMENT) uint8_t dst[RATE];
    CRYPTO_ALIGN(16) uint8_t        computed_mac[32];
    const size_t                    mlen = clen;
    size_t                          i;
    int                             ret;

    aegis256_init(k, npub, state);

    for (i = 0; i + RATE <= adlen; i += RATE) {
        aegis256_absorb(ad + i, state);
    }
    if (adlen % RATE) {
        memset(src, 0, RATE);
        memcpy(src, ad + i, adlen % RATE);
        aegis256_absorb(src, state);
    }
    if (m != NULL) {
        for (i = 0; i + RATE <= mlen; i += RATE) {
            aegis256_dec(m + i, c + i, state);
        }
    } else {
        for (i = 0; i + RATE <= mlen; i += RATE) {
            aegis256_dec(dst, c + i, state);
        }
    }
    if (mlen % RATE) {
        if (m != NULL) {
            aegis256_declast(m + i, c + i, mlen % RATE, state);
        } else {
            aegis256_declast(dst, c + i, mlen % RATE, state);
        }
    }
    COMPILER_ASSERT(sizeof computed_mac >= 32);
    aegis256_mac(computed_mac, maclen, adlen, mlen, state);
    ret = -1;
    if (maclen == 16) {
        ret = aegis_verify_16(computed_mac, mac);
    } else if (maclen == 32) {
        ret = aegis_verify_32(computed_mac, mac);
    }
    if (ret != 0 && m != NULL) {
        memset(m, 0, mlen);
    }
    return ret;
}

int
aegis256_decrypt(uint8_t *m, const uint8_t *c, size_t clen, size_t maclen, const uint8_t *ad,
                 size_t adlen, const uint8_t *npub, const uint8_t *k)
{
    int ret = -1;

    if (clen >= maclen) {
        ret = aegis256_decrypt_detached(m, c, clen - maclen, c + clen - maclen, maclen, ad, adlen,
                                        npub, k);
    }
    return ret;
}
