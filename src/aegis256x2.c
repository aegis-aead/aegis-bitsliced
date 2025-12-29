#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"

#if BITSLICE_WORD_SIZE == 32

#    include "include/aegis.h"
#    include "include/aegis256x2.h"

#    include "aes-bs8x2.h"

#    undef KEEP_STATE_BITSLICED

#    define RATE      32
#    define ALIGNMENT 32

static void
aegis_round(AesBlocks st)
{
    AesBlocks st1;
    size_t    i;

    memcpy(st1, st, sizeof(AesBlocks));
    pack(st1);
    aes_round(st1);
    unpack(st1);

    for (i = 0; i < 6; i++) {
        size_t j;

        for (j = 0; j < 4 * 2; j++) {
            st[word_idx(i, j)] ^= st1[word_idx((i + 5) % 6, j)];
        }
    }
}

static void
aegis_round_packed(AesBlocks st, const AesBlocks constant_input)
{
    AesBlocks st1;

    memcpy(st1, st, sizeof(AesBlocks));
    aes_round(st1);
    blocks_rotr6(st1);
    blocks_xor(st, st1);
    blocks_xor(st, constant_input);
}

static void
aegis_pack_constant_input(AesBlocks st, const AesBlock m)
{
    size_t i;

    memset(st, 0, sizeof(AesBlocks));
    for (i = 0; i < 4 * 2; i++) {
        st[word_idx(0, i)] = m[i];
    }
    pack04_6(st);
}

static inline void
aegis_absorb_rate(AesBlocks st, const AesBlock m)
{
    size_t i;

    for (i = 0; i < 4 * 2; i++) {
        st[word_idx(0, i)] ^= m[i];
    }
}

static inline void
aegis_update(AesBlocks st, const AesBlock m)
{
    aegis_round(st);
    aegis_absorb_rate(st, m);
}

static void
aegis256x2_init(const uint8_t *key, const uint8_t *nonce, AesBlocks st)
{
    const AesBlock c0 = { 0x02010100, 0x0d080503, 0x59372215, 0x6279e990,
                          0x02010100, 0x0d080503, 0x59372215, 0x6279e990 };
    const AesBlock c1 = { 0x55183ddb, 0xf12fc26d, 0x42311120, 0xdd28b573,
                          0x55183ddb, 0xf12fc26d, 0x42311120, 0xdd28b573 };
    AesBlock       k0, k1, n0, n1, k0n0, k1n1, k0c0, k1c1;
    int            i;

    block_from_broadcast(k0, key);
    block_from_broadcast(k1, key + 16);
    block_from_broadcast(n0, nonce);
    block_from_broadcast(n1, nonce + 16);
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

#    ifdef KEEP_STATE_BITSLICED
    {
        const AesBlocks constant_ctx_mask = {
            0, 0, 0, 0, 0, 0, 0, 0,  0, 0, 0, 0, 0, 0, 0, 17, 0, 0,  0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,  0, 0, 0, 0, 0, 0, 0, 0,  0, 17, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 17, 0, 0, 0, 0, 0, 0, 0, 0,  0, 0,  0, 0,
        };
        AesBlocks constant_input_k0, constant_input_k1, constant_input_k0n0, constant_input_k1n1;

        aegis_pack_constant_input(constant_input_k0, k0);
        aegis_pack_constant_input(constant_input_k1, k1);
        aegis_pack_constant_input(constant_input_k0n0, k0n0);
        aegis_pack_constant_input(constant_input_k1n1, k1n1);
        pack_6(st);
        for (i = 0; i < 4; i++) {
            blocks_xor(st, constant_ctx_mask);
            aegis_round_packed(st, constant_input_k0);
            blocks_xor(st, constant_ctx_mask);
            aegis_round_packed(st, constant_input_k1);
            blocks_xor(st, constant_ctx_mask);
            aegis_round_packed(st, constant_input_k0n0);
            blocks_xor(st, constant_ctx_mask);
            aegis_round_packed(st, constant_input_k1n1);
        }
        unpack_6(st);
    }
#    else
    {
        const AesBlock ctx = { 0x00000100, 0x00000000, 0x00000000, 0x00000000,
                               0x00000101, 0x00000000, 0x00000000, 0x00000000 };

        for (i = 0; i < 4; i++) {
            size_t j;

            for (j = 0; j < 4 * 2; j++) {
                st[word_idx(3, j)] ^= ctx[j];
                st[word_idx(5, j)] ^= ctx[j];
            }
            aegis_update(st, k0);
            for (j = 0; j < 4 * 2; j++) {
                st[word_idx(3, j)] ^= ctx[j];
                st[word_idx(5, j)] ^= ctx[j];
            }
            aegis_update(st, k1);
            for (j = 0; j < 4 * 2; j++) {
                st[word_idx(3, j)] ^= ctx[j];
                st[word_idx(5, j)] ^= ctx[j];
            }
            aegis_update(st, k0n0);
            for (j = 0; j < 4 * 2; j++) {
                st[word_idx(3, j)] ^= ctx[j];
                st[word_idx(5, j)] ^= ctx[j];
            }
            aegis_update(st, k1n1);
        }
    }
#    endif
}

static void
aegis256x2_absorb(const uint8_t *const src, AesBlocks st)
{
    AesBlock msg;

    aegis_round(st);
    block_from_bytes(msg, src);
    aegis_absorb_rate(st, msg);
}

static void
aegis256x2_absorb_packed(const uint8_t *const src, AesBlocks st)
{
    AesBlocks constant_input;
    AesBlock  msg;

    block_from_bytes(msg, src);
    aegis_pack_constant_input(constant_input, msg);
    aegis_round_packed(st, constant_input);
}

static void
aegis256x2_enc(uint8_t *const dst, const uint8_t *const src, AesBlocks st)
{
    AesBlock t;
    AesBlock z;
    AesBlock out;
    size_t   i;

    for (i = 0; i < 4 * 2; i++) {
        z[i] = st[word_idx(1, i)] ^ st[word_idx(4, i)] ^ st[word_idx(5, i)] ^
               (st[word_idx(2, i)] & st[word_idx(3, i)]);
    }
    aegis_round(st);
    block_from_bytes(t, src);
    aegis_absorb_rate(st, t);
    block_xor(out, t, z);
    block_to_bytes(dst, out);
}

static void
aegis256x2_dec(uint8_t *const dst, const uint8_t *const src, AesBlocks st)
{
    AesBlock msg;
    size_t   i;

    block_from_bytes(msg, src);
    for (i = 0; i < 4 * 2; i++) {
        msg[i] ^= st[word_idx(1, i)] ^ st[word_idx(4, i)] ^ st[word_idx(5, i)] ^
                  (st[word_idx(2, i)] & st[word_idx(3, i)]);
    }
    aegis_update(st, msg);
    block_to_bytes(dst, msg);
}

static void
aegis256x2_declast(uint8_t *const dst, const uint8_t *const src, size_t len, AesBlocks st)
{
    uint8_t  pad[RATE];
    AesBlock msg;
    size_t   i;

    memset(pad, 0, sizeof pad);
    memcpy(pad, src, len);

    block_from_bytes(msg, pad);
    for (i = 0; i < 4 * 2; i++) {
        msg[i] ^= st[word_idx(1, i)] ^ st[word_idx(4, i)] ^ st[word_idx(5, i)] ^
                  (st[word_idx(2, i)] & st[word_idx(3, i)]);
    }
    aegis_round(st);
    block_to_bytes(pad, msg);
    memset(pad + len, 0, sizeof pad - len);
    memcpy(dst, pad, len);
    block_from_bytes(msg, pad);
    aegis_absorb_rate(st, msg);
}

static void
aegis256x2_mac(uint8_t *mac, size_t maclen, size_t adlen, size_t mlen, AesBlocks st)
{
    AesBlock tmp;
    size_t   i;

    tmp[0] = (uint32_t) (adlen << 3);
    tmp[1] = (uint32_t) (adlen >> (32 - 3));
    tmp[2] = (uint32_t) (mlen << 3);
    tmp[3] = (uint32_t) (mlen >> (32 - 3));
    memcpy(tmp + 4, tmp, 4 * sizeof(uint32_t));
    for (i = 0; i < 4 * 2; i++) {
        tmp[i] ^= st[word_idx(3, i)];
    }

#    ifdef KEEP_STATE_BITSLICED
    {
        AesBlocks constant_input;

        aegis_pack_constant_input(constant_input, tmp);
        pack_6(st);
        for (i = 0; i < 7; i++) {
            aegis_round_packed(st, constant_input);
        }
        unpack_6(st);
    }
#    else
    for (i = 0; i < 7; i++) {
        aegis_update(st, tmp);
    }
#    endif

    if (maclen == 16) {
        for (i = 0; i < 4; i++) {
            tmp[i] = st[word_idx(0, i)] ^ st[word_idx(1, i)] ^ st[word_idx(2, i)] ^
                     st[word_idx(3, i)] ^ st[word_idx(4, i)] ^ st[word_idx(5, i)] ^
                     st[word_idx(0, 4 + i)] ^ st[word_idx(1, 4 + i)] ^ st[word_idx(2, 4 + i)] ^
                     st[word_idx(3, 4 + i)] ^ st[word_idx(4, 4 + i)] ^ st[word_idx(5, 4 + i)];
        }
        base_block_to_bytes(mac, tmp);
    } else if (maclen == 32) {
        for (i = 0; i < 4; i++) {
            tmp[i] = st[word_idx(0, i)] ^ st[word_idx(1, i)] ^ st[word_idx(2, i)] ^
                     st[word_idx(0, 4 + i)] ^ st[word_idx(1, 4 + i)] ^ st[word_idx(2, 4 + i)];
        }
        base_block_to_bytes(mac, tmp);
        for (i = 0; i < 4; i++) {
            tmp[i] = st[word_idx(3, i)] ^ st[word_idx(4, i)] ^ st[word_idx(5, i)] ^
                     st[word_idx(3, 4 + i)] ^ st[word_idx(4, 4 + i)] ^ st[word_idx(5, 4 + i)];
        }
        base_block_to_bytes(mac + 16, tmp);
    } else {
        memset(mac, 0, maclen);
    }
}

static void
aegis256x2_absorb_ad(AesBlocks st, uint8_t tmp[RATE], const uint8_t *ad, const size_t adlen)
{
    size_t i;

    if (adlen > 2 * RATE) {
        pack_6(st);
        for (i = 0; i + RATE <= adlen; i += RATE) {
            aegis256x2_absorb_packed(ad + i, st);
        }
        if (adlen % RATE) {
            memset(tmp, 0, RATE);
            memcpy(tmp, ad + i, adlen % RATE);
            aegis256x2_absorb_packed(tmp, st);
        }
        unpack_6(st);
        return;
    }
    for (i = 0; i + RATE <= adlen; i += RATE) {
        aegis256x2_absorb(ad + i, st);
    }
    if (adlen % RATE) {
        memset(tmp, 0, RATE);
        memcpy(tmp, ad + i, adlen % RATE);
        aegis256x2_absorb(tmp, st);
    }
}

size_t
aegis256x2_keybytes(void)
{
    return aegis256x2_KEYBYTES;
}

size_t
aegis256x2_npubbytes(void)
{
    return aegis256x2_NPUBBYTES;
}

size_t
aegis256x2_abytes_min(void)
{
    return aegis256x2_ABYTES_MIN;
}

size_t
aegis256x2_abytes_max(void)
{
    return aegis256x2_ABYTES_MAX;
}

int
aegis256x2_encrypt_detached(uint8_t *c, uint8_t *mac, size_t maclen, const uint8_t *m, size_t mlen,
                            const uint8_t *ad, size_t adlen, const uint8_t *npub, const uint8_t *k)
{
    AesBlocks                       state;
    CRYPTO_ALIGN(ALIGNMENT) uint8_t src[RATE];
    CRYPTO_ALIGN(ALIGNMENT) uint8_t dst[RATE];
    size_t                          i;

    aegis256x2_init(k, npub, state);

    if (adlen > 0) {
        aegis256x2_absorb_ad(state, src, ad, adlen);
    }
    for (i = 0; i + RATE <= mlen; i += RATE) {
        aegis256x2_enc(c + i, m + i, state);
    }
    if (mlen % RATE) {
        memset(src, 0, RATE);
        memcpy(src, m + i, mlen % RATE);
        aegis256x2_enc(dst, src, state);
        memcpy(c + i, dst, mlen % RATE);
    }
    aegis256x2_mac(mac, maclen, adlen, mlen, state);

    return 0;
}

int
aegis256x2_encrypt(uint8_t *c, size_t maclen, const uint8_t *m, size_t mlen, const uint8_t *ad,
                   size_t adlen, const uint8_t *npub, const uint8_t *k)
{
    return aegis256x2_encrypt_detached(c, c + mlen, maclen, m, mlen, ad, adlen, npub, k);
}

int
aegis256x2_decrypt_detached(uint8_t *m, const uint8_t *c, size_t clen, const uint8_t *mac,
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

    aegis256x2_init(k, npub, state);

    if (adlen > 0) {
        aegis256x2_absorb_ad(state, src, ad, adlen);
    }
    if (m != NULL) {
        for (i = 0; i + RATE <= mlen; i += RATE) {
            aegis256x2_dec(m + i, c + i, state);
        }
    } else {
        for (i = 0; i + RATE <= mlen; i += RATE) {
            aegis256x2_dec(dst, c + i, state);
        }
    }
    if (mlen % RATE) {
        if (m != NULL) {
            aegis256x2_declast(m + i, c + i, mlen % RATE, state);
        } else {
            aegis256x2_declast(dst, c + i, mlen % RATE, state);
        }
    }
    COMPILER_ASSERT(sizeof computed_mac >= 32);
    aegis256x2_mac(computed_mac, maclen, adlen, mlen, state);
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
aegis256x2_decrypt(uint8_t *m, const uint8_t *c, size_t clen, size_t maclen, const uint8_t *ad,
                   size_t adlen, const uint8_t *npub, const uint8_t *k)
{
    int ret = -1;

    if (clen >= maclen) {
        ret = aegis256x2_decrypt_detached(m, c, clen - maclen, c + clen - maclen, maclen, ad, adlen,
                                          npub, k);
    }
    return ret;
}

#endif
