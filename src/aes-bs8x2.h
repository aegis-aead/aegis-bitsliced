#ifndef aes_bs8x2_H
#define aes_bs8x2_H

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"

#define AES_BLOCK_LENGTH 32

#define SWAPMOVE(a, b, mask, n)                     \
    do {                                            \
        const uint32_t tmp = (b ^ (a >> n)) & mask; \
        b ^= tmp;                                   \
        a ^= (tmp << n);                            \
    } while (0)

typedef CRYPTO_ALIGN(16) uint32_t AesBlockBase[4];
typedef CRYPTO_ALIGN(32) uint32_t AesBlock[8];
typedef CRYPTO_ALIGN(32) uint32_t AesBlocksBases[32];
typedef CRYPTO_ALIGN(64) uint32_t AesBlocks[64];
typedef uint32_t Sbox[8];
typedef uint8_t  AesBlocksBytes[2048];
typedef uint8_t  AesBlockBytesBase[16];
typedef uint8_t  AesBlockBytes[32];

static void
sbox(Sbox b)
{
    uint32_t t0, t1, t2, t3, t4, t5, t6, t7, t8, t9, t10, t11, t12, t13, t14, t15, t16, t17;

    t0   = b[3] ^ b[5];
    t1   = b[0] ^ b[6];
    t2   = t1 ^ t0;
    t3   = b[4] ^ t2;
    t4   = t3 ^ b[5];
    t5   = t2 & t4;
    t6   = t4 ^ b[7];
    t7   = t3 ^ b[1];
    t8   = b[0] ^ b[3];
    t9   = t7 ^ t8;
    t10  = t8 & t9;
    t11  = b[7] ^ t9;
    t12  = b[0] ^ b[5];
    t13  = b[1] ^ b[2];
    t14  = t4 ^ t13;
    t15  = t14 ^ t9;
    t16  = t0 & t15;
    t17  = t16 ^ t10;
    b[1] = t14 ^ t12;
    b[2] = t12 & t14;
    b[2] ^= t10;
    b[4] = t13 ^ t9;
    b[5] = t1 ^ b[4];
    t3   = t1 & b[4];
    t10  = b[0] ^ b[4];
    t13 ^= b[7];
    b[3] ^= t13;
    t16 = b[3] & b[7];
    t16 ^= t5;
    t16 ^= b[2];
    b[1] ^= t16;
    b[0] ^= t13;
    t16 = b[0] & t11;
    t16 ^= t3;
    b[2] ^= t16;
    b[2] ^= t10;
    b[6] ^= t13;
    t10 = b[6] & t13;
    t3 ^= t10;
    t3 ^= t17;
    b[5] ^= t3;
    t3  = b[6] ^ t12;
    t10 = t3 & t6;
    t5 ^= t10;
    t5 ^= t7;
    t5 ^= t17;
    t7  = t5 & b[5];
    t10 = b[2] ^ t7;
    t7 ^= b[1];
    t5 ^= b[1];
    t16 = t5 & t10;
    b[1] ^= t16;
    t17 = b[1] & b[0];
    t11 = b[1] & t11;
    t16 = b[5] ^ b[2];
    t7 &= t16;
    t7 ^= b[2];
    t16 = t10 ^ t7;
    b[2] &= t16;
    t10 ^= b[2];
    t10 &= b[1];
    t5 ^= t10;
    t10 = b[1] ^ t5;
    b[4] &= t10;
    t11 ^= b[4];
    t1 &= t10;
    b[6] &= t5;
    t10 = t5 & t13;
    b[4] ^= t10;
    b[5] ^= t7;
    b[2] ^= b[5];
    b[5] = t5 ^ b[2];
    t5   = b[5] & t14;
    t10  = b[5] & t12;
    t12  = t7 ^ b[2];
    t4 &= t12;
    t2 &= t12;
    t3 &= b[2];
    b[2] &= t6;
    b[2] ^= t4;
    t13 = b[4] ^ b[2];
    b[3] &= t7;
    b[1] ^= t7;
    b[5] ^= b[1];
    t6 = b[5] & t15;
    b[4] ^= t6;
    t0 &= b[5];
    b[5] = b[1] & t9;
    b[5] ^= b[4];
    b[1] &= t8;
    t6 = b[1] ^ b[5];
    t0 ^= b[1];
    b[1] = t3 ^ t0;
    t15  = b[1] ^ b[3];
    t2 ^= b[1];
    b[0] = t2 ^ b[5];
    b[3] = t2 ^ t13;
    b[1] = b[3] ^ b[5];
    b[1] ^= 0xffffffff;
    t0 ^= b[6];
    b[5] = t7 & b[7];
    t14  = t4 ^ b[5];
    b[6] = t1 ^ t14;
    b[6] ^= t5;
    b[6] ^= b[4];
    b[2] = t17 ^ b[6];
    b[5] = t15 ^ b[2];
    b[2] ^= t6;
    b[2] ^= t10;
    b[2] ^= 0xffffffff;
    t14 ^= t11;
    t0 ^= t14;
    b[6] ^= t0;
    b[6] ^= 0xffffffff;
    b[7] = t1 ^ t0;
    b[7] ^= 0xffffffff;
    b[4] = t14 ^ b[3];
}

static void
sboxes(AesBlocks st)
{
    size_t i;

    for (i = 0; i < 4 * 2; i++) {
        sbox(st + 8 * i);
    }
}

static void
shiftrows(AesBlocks st)
{
    size_t i;

    for (i = 8; i < 16; i++) {
        st[i] = ROTL32(st[i], 24);
    }
    for (i = 16; i < 24; i++) {
        st[i] = ROTL32(st[i], 16);
    }
    for (i = 24; i < 32; i++) {
        st[i] = ROTL32(st[i], 8);
    }
    for (i = 32 + 8; i < 32 + 16; i++) {
        st[i] = ROTL32(st[i], 24);
    }
    for (i = 32 + 16; i < 32 + 24; i++) {
        st[i] = ROTL32(st[i], 16);
    }
    for (i = 32 + 24; i < 32 + 32; i++) {
        st[i] = ROTL32(st[i], 8);
    }
}

static void
mixcolumns_(AesBlocksBases st)
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
mixcolumns(AesBlocks st)
{
    mixcolumns_(st + 32 * 0);
    mixcolumns_(st + 32 * 1);
}

static void
aes_round(AesBlocks st)
{
    sboxes(st);
    shiftrows(st);
    mixcolumns(st);
}

static void
pack_(AesBlocksBases st)
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
pack(AesBlocks st)
{
    pack_(st + 32 * 0);
    pack_(st + 32 * 1);
}

static void
unpack_(AesBlocksBases st)
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

static void
unpack(AesBlocks st)
{
    unpack_(st + 32 * 0);
    unpack_(st + 32 * 1);
}

static inline size_t
word_idx(const size_t block, const size_t word)
{
    return block + (word % 4) * 8 + (word / 4) * 32;
}

static inline void
blocks_rotr(AesBlocks st)
{
    size_t i;

    for (i = 0; i < 32 * 2; i++) {
        st[i] = (st[i] & 0xfefefefe) >> 1 | (st[i] & 0x01010101) << 7;
    }
}

static inline void
blocks_put(AesBlocks st, const AesBlock s, const size_t block)
{
    size_t i;

    for (i = 0; i < 4 * 2; i++) {
        st[word_idx(block, i)] = s[i];
    }
}

static inline void
block_from_broadcast(AesBlock out, const AesBlockBytesBase in)
{
#ifdef NATIVE_LITTLE_ENDIAN
    memcpy(out, in, 16);
    memcpy(out + 4, in, 16);
#else
    size_t i;

    for (i = 0; i < 4; i++) {
        out[i] = LOAD32_LE(in + 4 * i);
    }
    memcpy(out + 4, in, 16);
#endif
}

static inline void
block_from_bytes(AesBlock out, const AesBlockBytes in)
{
#ifdef NATIVE_LITTLE_ENDIAN
    memcpy(out, in, 16 * 2);
#else
    size_t i;

    for (i = 0; i < 4 * 2; i++) {
        out[i] = LOAD32_LE(in + 4 * i);
    }
#endif
}

static inline void
block_to_bytes(AesBlockBytes out, const AesBlock in)
{
#ifdef NATIVE_LITTLE_ENDIAN
    memcpy(out, in, 16 * 2);
#else
    size_t i;

    for (i = 0; i < 4 * 2; i++) {
        STORE32_LE(out + 4 * i, in[i]);
    }
#endif
}

static inline void
base_block_to_bytes(AesBlockBytesBase out, const AesBlockBase in)
{
#ifdef NATIVE_LITTLE_ENDIAN
    memcpy(out, in, 16);
#else
    size_t i;

    for (i = 0; i < 4; i++) {
        STORE32_LE(out + 4 * i, in[i]);
    }
#endif
}

static inline void
block_xor(AesBlock out, const AesBlock a, const AesBlock b)
{
    size_t i;

    for (i = 0; i < 4 * 2; i++) {
        out[i] = a[i] ^ b[i];
    }
}

static inline void
blocks_xor(AesBlocks a, const AesBlocks b)
{
    size_t i;

    for (i = 0; i < 32 * 2; i++) {
        a[i] ^= b[i];
    }
}

#endif