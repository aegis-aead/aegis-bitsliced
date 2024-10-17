#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"
#include "include/aegis.h"
#include "include/aegis128l.h"

#include "aes-bs8.h"

#define RATE      32
#define ALIGNMENT 32

static void
aegis_round(AesBlocks st)
{
    AesBlocks st1;
    size_t    i;

    memcpy(st1, st, sizeof(AesBlocks));
    pack(st1);
    sboxes(st1);
    shiftrows(st1);
    mixcolumns(st1);
    unpack(st1);

    for (i = 0; i < 8; i++) {
        st[word_idx(i, 0)] ^= st1[word_idx((i - 1) % 8, 0)];
        st[word_idx(i, 1)] ^= st1[word_idx((i - 1) % 8, 1)];
        st[word_idx(i, 2)] ^= st1[word_idx((i - 1) % 8, 2)];
        st[word_idx(i, 3)] ^= st1[word_idx((i - 1) % 8, 3)];
    }
}

static inline void
aegis_absorb_rate(AesBlocks st, const AesBlock m0, const AesBlock m1)
{
    st[word_idx(0, 0)] ^= m0[0];
    st[word_idx(0, 1)] ^= m0[1];
    st[word_idx(0, 2)] ^= m0[2];
    st[word_idx(0, 3)] ^= m0[3];

    st[word_idx(4, 0)] ^= m1[0];
    st[word_idx(4, 1)] ^= m1[1];
    st[word_idx(4, 2)] ^= m1[2];
    st[word_idx(4, 3)] ^= m1[3];
}

static inline void
aegis_update(AesBlocks st, const AesBlock m0, const AesBlock m1)
{
    aegis_round(st);
    aegis_absorb_rate(st, m0, m1);
}

static void
aegis128l_init(const uint8_t *key, const uint8_t *nonce, AesBlocks st)
{
    const AesBlock c0 = { 0x02010100, 0x0d080503, 0x59372215, 0x6279e990 };
    const AesBlock c1 = { 0x55183ddb, 0xf12fc26d, 0x42311120, 0xdd28b573 };
    AesBlock       k, n, kn, kc0, kc1;
    int            i;

    block_from_bytes(k, key);
    block_from_bytes(n, nonce);
    block_xor(kn, k, n);
    block_xor(kc0, k, c0);
    block_xor(kc1, k, c1);

    blocks_put(st, kn, 0);
    blocks_put(st, c1, 1);
    blocks_put(st, c0, 2);
    blocks_put(st, c1, 3);
    blocks_put(st, kn, 4);
    blocks_put(st, kc0, 5);
    blocks_put(st, kc1, 6);
    blocks_put(st, kc0, 7);

    for (i = 0; i < 10; i++) {
        aegis_update(st, n, k);
    }
}

static void
aegis128l_absorb(const uint8_t *const src, AesBlocks st)
{
    AesBlock msg0, msg1;

    aegis_round(st);
    block_from_bytes(msg0, src);
    block_from_bytes(msg1, src + AES_BLOCK_LENGTH);
    aegis_absorb_rate(st, msg0, msg1);
}

static void
aegis128l_enc(uint8_t *const dst, const uint8_t *const src, AesBlocks st)
{
    AesBlock t0, t1;
    AesBlock z0, z1;
    AesBlock out0, out1;
    size_t   i;

    for (i = 0; i < 4; i++) {
        z0[i] = st[word_idx(6, i)] ^ st[word_idx(1, i)] ^ (st[word_idx(2, i)] & st[word_idx(3, i)]);
    }
    for (i = 0; i < 4; i++) {
        z1[i] = st[word_idx(2, i)] ^ st[word_idx(5, i)] ^ (st[word_idx(6, i)] & st[word_idx(7, i)]);
    }
    aegis_round(st);
    block_from_bytes(t0, src);
    block_from_bytes(t1, src + AES_BLOCK_LENGTH);
    aegis_absorb_rate(st, t0, t1);
    block_xor(out0, t0, z0);
    block_xor(out1, t1, z1);
    block_to_bytes(dst, out0);
    block_to_bytes(dst + AES_BLOCK_LENGTH, out1);
}

static void
aegis128l_dec(uint8_t *const dst, const uint8_t *const src, AesBlocks st)
{
    AesBlock msg0, msg1;
    size_t   i;

    block_from_bytes(msg0, src);
    block_from_bytes(msg1, src + AES_BLOCK_LENGTH);
    for (i = 0; i < 4; i++) {
        msg0[i] ^=
            st[word_idx(6, i)] ^ st[word_idx(1, i)] ^ (st[word_idx(2, i)] & st[word_idx(3, i)]);
    }
    for (i = 0; i < 4; i++) {
        msg1[i] ^=
            st[word_idx(2, i)] ^ st[word_idx(5, i)] ^ (st[word_idx(6, i)] & st[word_idx(7, i)]);
    }
    block_to_bytes(dst, msg0);
    block_to_bytes(dst + AES_BLOCK_LENGTH, msg1);
    aegis_update(st, msg0, msg1);
}

static void
aegis128l_declast(uint8_t *const dst, const uint8_t *const src, size_t len, AesBlocks st)
{
    uint8_t  pad[RATE];
    AesBlock msg0, msg1;
    size_t   i;

    memset(pad, 0, sizeof pad);
    memcpy(pad, src, len);

    block_from_bytes(msg0, pad);
    block_from_bytes(msg1, pad + AES_BLOCK_LENGTH);
    for (i = 0; i < 4; i++) {
        msg0[i] ^=
            st[word_idx(6, i)] ^ st[word_idx(1, i)] ^ (st[word_idx(2, i)] & st[word_idx(3, i)]);
    }
    for (i = 0; i < 4; i++) {
        msg1[i] ^=
            st[word_idx(2, i)] ^ st[word_idx(5, i)] ^ (st[word_idx(6, i)] & st[word_idx(7, i)]);
    }
    aegis_round(st);
    block_to_bytes(pad, msg0);
    block_to_bytes(pad + AES_BLOCK_LENGTH, msg1);
    memset(pad + len, 0, sizeof pad - len);
    memcpy(dst, pad, len);
    block_from_bytes(msg0, pad);
    block_from_bytes(msg1, pad + AES_BLOCK_LENGTH);
    aegis_absorb_rate(st, msg0, msg1);
}

static void
aegis128l_mac(uint8_t *mac, size_t maclen, size_t adlen, size_t mlen, AesBlocks st)
{
    AesBlock tmp;
    size_t   i;

    tmp[0] = (uint32_t) (mlen << 3);
    tmp[1] = (uint32_t) (mlen >> (32 - 3));
    tmp[2] = (uint32_t) (adlen << 3);
    tmp[3] = (uint32_t) (adlen >> (32 - 3));

    tmp[0] ^= st[word_idx(2, 0)];
    tmp[1] ^= st[word_idx(2, 1)];
    tmp[2] ^= st[word_idx(2, 2)];
    tmp[3] ^= st[word_idx(2, 3)];

    for (i = 0; i < 7; i++) {
        aegis_update(st, tmp, tmp);
    }

    if (maclen == 16) {
        for (i = 0; i < 4; i++) {
            tmp[i] = st[word_idx(0, i)] ^ st[word_idx(1, i)] ^ st[word_idx(2, i)] ^
                     st[word_idx(3, i)] ^ st[word_idx(4, i)] ^ st[word_idx(5, i)] ^
                     st[word_idx(6, i)];
        }
        block_to_bytes(mac, tmp);
    } else if (maclen == 32) {
        for (i = 0; i < 4; i++) {
            tmp[i] =
                st[word_idx(0, i)] ^ st[word_idx(1, i)] ^ st[word_idx(2, i)] ^ st[word_idx(3, i)];
        }
        block_to_bytes(mac, tmp);
        for (i = 0; i < 4; i++) {
            tmp[i] =
                st[word_idx(4, i)] ^ st[word_idx(5, i)] ^ st[word_idx(6, i)] ^ st[word_idx(7, i)];
        }
        block_to_bytes(mac + 16, tmp);
    } else {
        memset(mac, 0, maclen);
    }
}

size_t
aegis128l_keybytes(void)
{
    return aegis128l_KEYBYTES;
}

size_t
aegis128l_npubbytes(void)
{
    return aegis128l_NPUBBYTES;
}

size_t
aegis128l_abytes_min(void)
{
    return aegis128l_ABYTES_MIN;
}

size_t
aegis128l_abytes_max(void)
{
    return aegis128l_ABYTES_MAX;
}

int
aegis128l_encrypt_detached(uint8_t *c, uint8_t *mac, size_t maclen, const uint8_t *m, size_t mlen,
                           const uint8_t *ad, size_t adlen, const uint8_t *npub, const uint8_t *k)
{
    AesBlocks                       state;
    CRYPTO_ALIGN(ALIGNMENT) uint8_t src[RATE];
    CRYPTO_ALIGN(ALIGNMENT) uint8_t dst[RATE];
    size_t                          i;

    aegis128l_init(k, npub, state);

    for (i = 0; i + RATE <= adlen; i += RATE) {
        aegis128l_absorb(ad + i, state);
    }
    if (adlen % RATE) {
        memset(src, 0, RATE);
        memcpy(src, ad + i, adlen % RATE);
        aegis128l_absorb(src, state);
    }
    for (i = 0; i + RATE <= mlen; i += RATE) {
        aegis128l_enc(c + i, m + i, state);
    }
    if (mlen % RATE) {
        memset(src, 0, RATE);
        memcpy(src, m + i, mlen % RATE);
        aegis128l_enc(dst, src, state);
        memcpy(c + i, dst, mlen % RATE);
    }
    aegis128l_mac(mac, maclen, adlen, mlen, state);

    return 0;
}

int
aegis128l_encrypt(uint8_t *c, size_t maclen, const uint8_t *m, size_t mlen, const uint8_t *ad,
                  size_t adlen, const uint8_t *npub, const uint8_t *k)
{
    return aegis128l_encrypt_detached(c, c + mlen, maclen, m, mlen, ad, adlen, npub, k);
}

int
aegis128l_decrypt_detached(uint8_t *m, const uint8_t *c, size_t clen, const uint8_t *mac,
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

    aegis128l_init(k, npub, state);

    for (i = 0; i + RATE <= adlen; i += RATE) {
        aegis128l_absorb(ad + i, state);
    }
    if (adlen % RATE) {
        memset(src, 0, RATE);
        memcpy(src, ad + i, adlen % RATE);
        aegis128l_absorb(src, state);
    }
    if (m != NULL) {
        for (i = 0; i + RATE <= mlen; i += RATE) {
            aegis128l_dec(m + i, c + i, state);
        }
    } else {
        for (i = 0; i + RATE <= mlen; i += RATE) {
            aegis128l_dec(dst, c + i, state);
        }
    }
    if (mlen % RATE) {
        if (m != NULL) {
            aegis128l_declast(m + i, c + i, mlen % RATE, state);
        } else {
            aegis128l_declast(dst, c + i, mlen % RATE, state);
        }
    }
    COMPILER_ASSERT(sizeof computed_mac >= 32);
    aegis128l_mac(computed_mac, maclen, adlen, mlen, state);
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
aegis128l_decrypt(uint8_t *m, const uint8_t *c, size_t clen, size_t maclen, const uint8_t *ad,
                  size_t adlen, const uint8_t *npub, const uint8_t *k)
{
    int ret = -1;

    if (clen >= maclen) {
        ret = aegis128l_decrypt_detached(m, c, clen - maclen, c + clen - maclen, maclen, ad, adlen,
                                         npub, k);
    }
    return ret;
}
