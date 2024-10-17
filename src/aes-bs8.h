#ifndef aes_bs8_H
#define aes_bs8_H

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"

#define AES_BLOCK_LENGTH 16

#define SWAPMOVE(a, b, mask, n)                     \
    do {                                            \
        const uint32_t tmp = (b ^ (a >> n)) & mask; \
        b ^= tmp;                                   \
        a ^= (tmp << n);                            \
    } while (0)

typedef CRYPTO_ALIGN(16) uint32_t AesBlock[4];
typedef CRYPTO_ALIGN(64) uint32_t AesBlocks[32];
typedef uint8_t AesBlocksBytes[1024];

static void
sbox(AesBlocks st)
{
    uint32_t t0, t1, t2, t3, t4, t5, t6, t7, t8, t9, t10, t11, t12, t13, t14, t15, t16, t17;

    t0    = st[3] ^ st[5];
    t1    = st[0] ^ st[6];
    t2    = t1 ^ t0;
    t3    = st[4] ^ t2;
    t4    = t3 ^ st[5];
    t5    = t2 & t4;
    t6    = t4 ^ st[7];
    t7    = t3 ^ st[1];
    t8    = st[0] ^ st[3];
    t9    = t7 ^ t8;
    t10   = t8 & t9;
    t11   = st[7] ^ t9;
    t12   = st[0] ^ st[5];
    t13   = st[1] ^ st[2];
    t14   = t4 ^ t13;
    t15   = t14 ^ t9;
    t16   = t0 & t15;
    t17   = t16 ^ t10;
    st[1] = t14 ^ t12;
    st[2] = t12 & t14;
    st[2] ^= t10;
    st[4] = t13 ^ t9;
    st[5] = t1 ^ st[4];
    t3    = t1 & st[4];
    t10   = st[0] ^ st[4];
    t13 ^= st[7];
    st[3] ^= t13;
    t16 = st[3] & st[7];
    t16 ^= t5;
    t16 ^= st[2];
    st[1] ^= t16;
    st[0] ^= t13;
    t16 = st[0] & t11;
    t16 ^= t3;
    st[2] ^= t16;
    st[2] ^= t10;
    st[6] ^= t13;
    t10 = st[6] & t13;
    t3 ^= t10;
    t3 ^= t17;
    st[5] ^= t3;
    t3  = st[6] ^ t12;
    t10 = t3 & t6;
    t5 ^= t10;
    t5 ^= t7;
    t5 ^= t17;
    t7  = t5 & st[5];
    t10 = st[2] ^ t7;
    t7 ^= st[1];
    t5 ^= st[1];
    t16 = t5 & t10;
    st[1] ^= t16;
    t17 = st[1] & st[0];
    t11 = st[1] & t11;
    t16 = st[5] ^ st[2];
    t7 &= t16;
    t7 ^= st[2];
    t16 = t10 ^ t7;
    st[2] &= t16;
    t10 ^= st[2];
    t10 &= st[1];
    t5 ^= t10;
    t10 = st[1] ^ t5;
    st[4] &= t10;
    t11 ^= st[4];
    t1 &= t10;
    st[6] &= t5;
    t10 = t5 & t13;
    st[4] ^= t10;
    st[5] ^= t7;
    st[2] ^= st[5];
    st[5] = t5 ^ st[2];
    t5    = st[5] & t14;
    t10   = st[5] & t12;
    t12   = t7 ^ st[2];
    t4 &= t12;
    t2 &= t12;
    t3 &= st[2];
    st[2] &= t6;
    st[2] ^= t4;
    t13 = st[4] ^ st[2];
    st[3] &= t7;
    st[1] ^= t7;
    st[5] ^= st[1];
    t6 = st[5] & t15;
    st[4] ^= t6;
    t0 &= st[5];
    st[5] = st[1] & t9;
    st[5] ^= st[4];
    st[1] &= t8;
    t6 = st[1] ^ st[5];
    t0 ^= st[1];
    st[1] = t3 ^ t0;
    t15   = st[1] ^ st[3];
    t2 ^= st[1];
    st[0] = t2 ^ st[5];
    st[3] = t2 ^ t13;
    st[1] = st[3] ^ st[5];
    t0 ^= st[6];
    st[5] = t7 & st[7];
    t14   = t4 ^ st[5];
    st[6] = t1 ^ t14;
    st[6] ^= t5;
    st[6] ^= st[4];
    st[2] = t17 ^ st[6];
    st[5] = t15 ^ st[2];
    st[2] ^= t6;
    st[2] ^= t10;
    t14 ^= t11;
    t0 ^= t14;
    st[6] ^= t0;
    st[7] = t1 ^ t0;
    st[4] = t14 ^ st[3];
    st[1] ^= 0xffffffff;
    st[2] ^= 0xffffffff;
    st[6] ^= 0xffffffff;
    st[7] ^= 0xffffffff;
}

static void
shiftrows(AesBlocks st)
{
    for (int i = 8; i < 16; i++) {
        st[i] = ROTL32(st[i], 24);
    }
    for (int i = 16; i < 24; i++) {
        st[i] = ROTL32(st[i], 16);
    }
    for (int i = 24; i < 32; i++) {
        st[i] = ROTL32(st[i], 8);
    }
}

static void
mixcolumns(AesBlocks st)
{
    uint32_t t2_0, t2_1, t2_2, t2_3;
    uint32_t t, t_bis, t0_0, t0_1, t0_2, t0_3;
    uint32_t t1_0, t1_1, t1_2, t1_3;

    t2_0   = st[0] ^ st[8];
    t2_1   = st[8] ^ st[16];
    t2_2   = st[16] ^ st[24];
    t2_3   = st[24] ^ st[0];
    t0_0   = st[7] ^ st[15];
    t0_1   = st[15] ^ st[23];
    t0_2   = st[23] ^ st[31];
    t0_3   = st[31] ^ st[7];
    t      = st[7];
    st[7]  = t2_0 ^ t0_2 ^ st[15];
    st[15] = t2_1 ^ t0_2 ^ t;
    t      = st[23];
    st[23] = t2_2 ^ t0_0 ^ st[31];
    st[31] = t2_3 ^ t0_0 ^ t;
    t1_0   = st[6] ^ st[14];
    t1_1   = st[14] ^ st[22];
    t1_2   = st[22] ^ st[30];
    t1_3   = st[30] ^ st[6];
    t      = st[6];
    st[6]  = t0_0 ^ t2_0 ^ st[14] ^ t1_2;
    t_bis  = st[14];
    st[14] = t0_1 ^ t2_1 ^ t1_2 ^ t;
    t      = st[22];
    st[22] = t0_2 ^ t2_2 ^ t1_3 ^ t_bis;
    st[30] = t0_3 ^ t2_3 ^ t1_0 ^ t;
    t0_0   = st[5] ^ st[13];
    t0_1   = st[13] ^ st[21];
    t0_2   = st[21] ^ st[29];
    t0_3   = st[29] ^ st[5];
    t      = st[5];
    st[5]  = t1_0 ^ t0_1 ^ st[29];
    t_bis  = st[13];
    st[13] = t1_1 ^ t0_2 ^ t;
    t      = st[21];
    st[21] = t1_2 ^ t0_3 ^ t_bis;
    st[29] = t1_3 ^ t0_0 ^ t;
    t1_0   = st[4] ^ st[12];
    t1_1   = st[12] ^ st[20];
    t1_2   = st[20] ^ st[28];
    t1_3   = st[28] ^ st[4];
    t      = st[4];
    st[4]  = t0_0 ^ t2_0 ^ t1_1 ^ st[28];
    t_bis  = st[12];
    st[12] = t0_1 ^ t2_1 ^ t1_2 ^ t;
    t      = st[20];
    st[20] = t0_2 ^ t2_2 ^ t1_3 ^ t_bis;
    st[28] = t0_3 ^ t2_3 ^ t1_0 ^ t;
    t0_0   = st[3] ^ st[11];
    t0_1   = st[11] ^ st[19];
    t0_2   = st[19] ^ st[27];
    t0_3   = st[27] ^ st[3];
    t      = st[3];
    st[3]  = t1_0 ^ t2_0 ^ t0_1 ^ st[27];
    t_bis  = st[11];
    st[11] = t1_1 ^ t2_1 ^ t0_2 ^ t;
    t      = st[19];
    st[19] = t1_2 ^ t2_2 ^ t0_3 ^ t_bis;
    st[27] = t1_3 ^ t2_3 ^ t0_0 ^ t;
    t1_0   = st[2] ^ st[10];
    t1_1   = st[10] ^ st[18];
    t1_2   = st[18] ^ st[26];
    t1_3   = st[26] ^ st[2];
    t      = st[2];
    st[2]  = t0_0 ^ t1_1 ^ st[26];
    t_bis  = st[10];
    st[10] = t0_1 ^ t1_2 ^ t;
    t      = st[18];
    st[18] = t0_2 ^ t1_3 ^ t_bis;
    st[26] = t0_3 ^ t1_0 ^ t;
    t0_0   = st[1] ^ st[9];
    t0_1   = st[9] ^ st[17];
    t0_2   = st[17] ^ st[25];
    t0_3   = st[25] ^ st[1];
    t      = st[1];
    st[1]  = t1_0 ^ t0_1 ^ st[25];
    t_bis  = st[9];
    st[9]  = t1_1 ^ t0_2 ^ t;
    t      = st[17];
    st[17] = t1_2 ^ t0_3 ^ t_bis;
    st[25] = t1_3 ^ t0_0 ^ t;
    t      = st[0];
    st[0]  = t0_0 ^ t2_1 ^ st[24];
    t_bis  = st[8];
    st[8]  = t0_1 ^ t2_2 ^ t;
    t      = st[16];
    st[16] = t0_2 ^ t2_3 ^ t_bis;
    st[24] = t0_3 ^ t2_0 ^ t;
}

static void
pack(AesBlocks st)
{
    size_t i;

    for (i = 0; i < 8; i++) {
        SWAPMOVE(st[i], st[i + 8], 0x00ff00ff, 8);
        SWAPMOVE(st[i + 16], st[i + 24], 0x00ff00ff, 8);
    }
    for (i = 0; i < 16; i++) {
        SWAPMOVE(st[i], st[i + 16], 0x0000ffff, 16);
    }
    for (i = 0; i < 32; i += 8) {
        SWAPMOVE(st[i + 1], st[i], 0x55555555, 1);
        SWAPMOVE(st[i + 3], st[i + 2], 0x55555555, 1);
        SWAPMOVE(st[i + 5], st[i + 4], 0x55555555, 1);
        SWAPMOVE(st[i + 7], st[i + 6], 0x55555555, 1);
        SWAPMOVE(st[i + 2], st[i], 0x33333333, 2);
        SWAPMOVE(st[i + 3], st[i + 1], 0x33333333, 2);
        SWAPMOVE(st[i + 6], st[i + 4], 0x33333333, 2);
        SWAPMOVE(st[i + 7], st[i + 5], 0x33333333, 2);
        SWAPMOVE(st[i + 4], st[i], 0x0f0f0f0f, 4);
        SWAPMOVE(st[i + 5], st[i + 1], 0x0f0f0f0f, 4);
        SWAPMOVE(st[i + 6], st[i + 2], 0x0f0f0f0f, 4);
        SWAPMOVE(st[i + 7], st[i + 3], 0x0f0f0f0f, 4);
    }
}

static void
unpack(AesBlocks st)
{
    size_t i;

    for (i = 0; i < 32; i += 8) {
        SWAPMOVE(st[i + 1], st[i], 0x55555555, 1);
        SWAPMOVE(st[i + 3], st[i + 2], 0x55555555, 1);
        SWAPMOVE(st[i + 5], st[i + 4], 0x55555555, 1);
        SWAPMOVE(st[i + 7], st[i + 6], 0x55555555, 1);
        SWAPMOVE(st[i + 2], st[i], 0x33333333, 2);
        SWAPMOVE(st[i + 3], st[i + 1], 0x33333333, 2);
        SWAPMOVE(st[i + 6], st[i + 4], 0x33333333, 2);
        SWAPMOVE(st[i + 7], st[i + 5], 0x33333333, 2);
        SWAPMOVE(st[i + 4], st[i], 0x0f0f0f0f, 4);
        SWAPMOVE(st[i + 5], st[i + 1], 0x0f0f0f0f, 4);
        SWAPMOVE(st[i + 6], st[i + 2], 0x0f0f0f0f, 4);
        SWAPMOVE(st[i + 7], st[i + 3], 0x0f0f0f0f, 4);
    }
    for (i = 0; i < 16; i++) {
        SWAPMOVE(st[i], st[i + 16], 0x0000ffff, 16);
    }
    for (i = 0; i < 8; i++) {
        SWAPMOVE(st[i], st[i + 8], 0x00ff00ff, 8);
        SWAPMOVE(st[i + 16], st[i + 24], 0x00ff00ff, 8);
    }
}

static inline size_t
word_idx(const size_t block, const size_t word)
{
    return block + word * 8;
}

static inline void
blocks_put(AesBlocks st, const AesBlock s, const size_t block)
{
    st[word_idx(block, 0)] = s[0];
    st[word_idx(block, 1)] = s[1];
    st[word_idx(block, 2)] = s[2];
    st[word_idx(block, 3)] = s[3];
}

static inline void
blocks_get(AesBlock s, const AesBlocks st, const size_t block)
{
    s[0] = st[word_idx(block, 0)];
    s[1] = st[word_idx(block, 1)];
    s[2] = st[word_idx(block, 2)];
    s[3] = st[word_idx(block, 3)];
}

static inline void
block_from_bytes(AesBlock out, const AesBlocksBytes in)
{
#ifdef NAIIVE_LITTLE_ENDIAN
    memcpy(out, in, 16);
#else
    out[0] = LOAD32_LE(in + 4 * 0);
    out[1] = LOAD32_LE(in + 4 * 1);
    out[2] = LOAD32_LE(in + 4 * 2);
    out[3] = LOAD32_LE(in + 4 * 3);
#endif
}

static inline void
block_to_bytes(AesBlocksBytes out, const AesBlock in)
{
#ifdef NATIVE_LITTLE_ENDIAN
    memcpy(out, in, 16);
#else
    STORE32_LE(out + 4 * 0, in[0]);
    STORE32_LE(out + 4 * 1, in[1]);
    STORE32_LE(out + 4 * 2, in[2]);
    STORE32_LE(out + 4 * 3, in[3]);
#endif
}

static inline void
block_xor(AesBlock out, const AesBlock a, const AesBlock b)
{
    out[0] = a[0] ^ b[0];
    out[1] = a[1] ^ b[1];
    out[2] = a[2] ^ b[2];
    out[3] = a[3] ^ b[3];
}

#endif