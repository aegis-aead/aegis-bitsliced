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
sbox(Sbox u)
{
    const uint32_t s0  = u[1] ^ u[4];
    const uint32_t s1  = u[5] ^ u[7];
    const uint32_t s2  = u[3] ^ s0;
    const uint32_t s3  = u[0] ^ u[2];
    const uint32_t q0  = s1 ^ s2;
    const uint32_t s4  = u[0] ^ u[6];
    const uint32_t s5  = u[2] ^ u[6];
    const uint32_t s6  = u[3] ^ s1;
    const uint32_t s7  = u[5] ^ s3;
    const uint32_t q1  = s1 ^ s5;
    const uint32_t q2  = u[2] ^ q0;
    const uint32_t q3  = s4 ^ s2;
    const uint32_t q4  = s3 ^ q0;
    const uint32_t s8  = u[4] ^ s3;
    const uint32_t q5  = s6 ^ s8;
    const uint32_t q6  = u[2] ^ u[3];
    const uint32_t q7  = u[6] ^ s2;
    const uint32_t s9  = u[6] ^ s0;
    const uint32_t q8  = s3 ^ s9;
    const uint32_t q9  = s4 ^ s6;
    const uint32_t q10 = s0 ^ s5;
    const uint32_t q12 = u[7] ^ s2;
    const uint32_t q13 = u[1] ^ s7;
    const uint32_t q14 = u[7] ^ s3;
    const uint32_t q15 = s2 ^ s7;
    const uint32_t q16 = u[1] ^ s1;
    const uint32_t q17 = u[1] ^ u[7];
    const uint32_t q11 = u[5];

    const uint32_t t20 = q6 & q12;
    const uint32_t t21 = q3 & q14;
    const uint32_t t22 = q1 & q16;
    const uint32_t t23 = q2 & q17;
    const uint32_t x0  = ((q3 | q14) ^ (q0 & q7))    ^ (t20 ^ t22);
    const uint32_t x1  = ((q4 | q13) ^ (q10 & q11))  ^ (t21 ^ t20);
    const uint32_t x2  = ((q2 | q17) ^ (q5 & q9))    ^ (t21 ^ t22);
    const uint32_t x3  = ((q8 | q15) ^ t23)          ^ (t21 ^ (q4 & q13));

    const uint32_t a   = x1 & ~x3;
    const uint32_t b   = x0 & ~x3;
    const uint32_t c   = x3 & ~x1;
    const uint32_t d   = x2 & ~x1;
    const uint32_t e   = x0 ^ a;
    const uint32_t y0  = x3 ^ (x2 & ~e);
    const uint32_t f   = x1 ^ b;
    const uint32_t y1  = c ^ (x2 & f);
    const uint32_t g   = x2 ^ c;
    const uint32_t y2  = x1 ^ (x0 & ~g);
    const uint32_t h   = x3 ^ d;
    const uint32_t y3  = a ^ (x0 & h);
    const uint32_t y02 = y2 ^ y0;
    const uint32_t y13 = y3 ^ y1;
    const uint32_t y23 = y3 ^ y2;
    const uint32_t y01 = y1 ^ y0;
    const uint32_t y00 = y02 ^ y13;

    const uint32_t a0  = y01 & q11;
    const uint32_t a1  = y0  & q12;
    const uint32_t a2  = y1  & q0;
    const uint32_t a3  = y23 & q17;
    const uint32_t a4  = y2  & q5;
    const uint32_t a5  = y3  & q15;
    const uint32_t a6  = y13 & q14;
    const uint32_t a7  = y00 & q16;
    const uint32_t a8  = y02 & q13;
    const uint32_t a9  = y01 & q7;
    const uint32_t a10 = y0  & q10;
    const uint32_t a11 = y1  & q6;
    const uint32_t a12 = y23 & q2;
    const uint32_t a13 = y2  & q9;
    const uint32_t a14 = y3  & q8;
    const uint32_t a15 = y13 & q3;
    const uint32_t a16 = y00 & q1;
    const uint32_t a17 = y02 & q4;

    const uint32_t r0  = a1 ^ a5;
    const uint32_t r1  = a9 ^ a15;
    const uint32_t r2  = a4 ^ r0;
    const uint32_t r3  = a2 ^ a10;
    const uint32_t r4  = a11 ^ a17;
    const uint32_t r5  = a8 ^ r1;
    const uint32_t r6  = a0 ^ a16;
    const uint32_t r7  = a7 ^ a13;
    const uint32_t r8  = a11 ^ a14;
    const uint32_t r9  = r3 ^ r4;
    const uint32_t r10 = r5 ^ r6;
    const uint32_t r11 = r2 ^ r9;
    const uint32_t r12 = a3 ^ r0;
    const uint32_t r13 = r7 ^ r8;
    const uint32_t r14 = r12 ^ r13;
    u[0]               = r10 ^ r14;
    const uint32_t r15 = a6 ^ a10;
    const uint32_t r16 = r15 ^ r2;
    u[1]               = ~(r10 ^ r16);
    u[2]               = ~(a2 ^ r2);
    const uint32_t r17 = a12 ^ a13;
    const uint32_t r18 = a15 ^ r17;
    u[3]               = r18 ^ r11;
    const uint32_t r19 = a1 ^ a14;
    const uint32_t r20 = a17 ^ r3;
    const uint32_t r21 = r7 ^ r19;
    const uint32_t r22 = r5 ^ r20;
    u[4]               = r21 ^ r22;
    const uint32_t r23 = a9 ^ a12;
    u[5]               = r8 ^ r23;
    u[6]               = ~(r1 ^ r4);
    u[7]               = ~(a16 ^ r11);
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
pack04_(AesBlocksBases st)
{
    size_t i;

    SWAPMOVE(st[0], st[0 + 8], 0x00ff00ff, 8);
    SWAPMOVE(st[0 + 16], st[0 + 24], 0x00ff00ff, 8);
    SWAPMOVE(st[4], st[4 + 8], 0x00ff00ff, 8);
    SWAPMOVE(st[4 + 16], st[4 + 24], 0x00ff00ff, 8);

    SWAPMOVE(st[0], st[0 + 16], 0x0000ffff, 16);
    SWAPMOVE(st[4], st[4 + 16], 0x0000ffff, 16);
    SWAPMOVE(st[8], st[8 + 16], 0x0000ffff, 16);
    SWAPMOVE(st[12], st[12 + 16], 0x0000ffff, 16);

    for (i = 0; i < 32; i += 8) {
        SWAPMOVE(st[i + 1], st[i], 0x55555555, 1);
        SWAPMOVE(st[i + 5], st[i + 4], 0x55555555, 1);
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
unpack04_(AesBlocksBases st)
{
    size_t i;

    for (i = 0; i < 32; i += 8) {
        SWAPMOVE(st[i + 7], st[i + 3], 0x0f0f0f0f, 4);
        SWAPMOVE(st[i + 6], st[i + 2], 0x0f0f0f0f, 4);
        SWAPMOVE(st[i + 5], st[i + 1], 0x0f0f0f0f, 4);
        SWAPMOVE(st[i + 4], st[i], 0x0f0f0f0f, 4);
        SWAPMOVE(st[i + 7], st[i + 5], 0x33333333, 2);
        SWAPMOVE(st[i + 6], st[i + 4], 0x33333333, 2);
        SWAPMOVE(st[i + 3], st[i + 1], 0x33333333, 2);
        SWAPMOVE(st[i + 2], st[i], 0x33333333, 2);
        SWAPMOVE(st[i + 5], st[i + 4], 0x55555555, 1);
        SWAPMOVE(st[i + 1], st[i], 0x55555555, 1);
    }

    SWAPMOVE(st[12], st[12 + 16], 0x0000ffff, 16);
    SWAPMOVE(st[8], st[8 + 16], 0x0000ffff, 16);
    SWAPMOVE(st[4], st[4 + 16], 0x0000ffff, 16);
    SWAPMOVE(st[0], st[0 + 16], 0x0000ffff, 16);

    SWAPMOVE(st[4 + 16], st[4 + 24], 0x00ff00ff, 8);
    SWAPMOVE(st[4], st[4 + 8], 0x00ff00ff, 8);
    SWAPMOVE(st[0 + 16], st[0 + 24], 0x00ff00ff, 8);
    SWAPMOVE(st[0], st[0 + 8], 0x00ff00ff, 8);
}

static void
pack04(AesBlocks st)
{
    pack04_(st + 32 * 0);
    pack04_(st + 32 * 1);
}

static void
unpack04(AesBlocks st)
{
    unpack04_(st + 32 * 0);
    unpack04_(st + 32 * 1);
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

static inline void
blocks_rotr6(AesBlocks st)
{
    size_t i;

    for (i = 0; i < 32 * 2; i++) {
        st[i] = ((st[i] & 0xf8f8f8f8) >> 1) | ((st[i] & 0x04040404) << 5);
    }
}

static void
pack04_6_(AesBlocksBases st)
{
    size_t i;

    SWAPMOVE(st[0], st[0 + 8], 0x00ff00ff, 8);
    SWAPMOVE(st[0 + 16], st[0 + 24], 0x00ff00ff, 8);

    SWAPMOVE(st[0], st[0 + 16], 0x0000ffff, 16);
    SWAPMOVE(st[8], st[8 + 16], 0x0000ffff, 16);

    for (i = 0; i < 32; i += 8) {
        SWAPMOVE(st[i + 1], st[i], 0x55555555, 1);
        SWAPMOVE(st[i + 2], st[i], 0x33333333, 2);
        SWAPMOVE(st[i + 3], st[i + 1], 0x33333333, 2);
        SWAPMOVE(st[i + 4], st[i], 0x0f0f0f0f, 4);
        SWAPMOVE(st[i + 5], st[i + 1], 0x0f0f0f0f, 4);
        SWAPMOVE(st[i + 6], st[i + 2], 0x0f0f0f0f, 4);
        SWAPMOVE(st[i + 7], st[i + 3], 0x0f0f0f0f, 4);
    }
}

static void
unpack04_6_(AesBlocksBases st)
{
    size_t i;

    for (i = 0; i < 32; i += 8) {
        SWAPMOVE(st[i + 7], st[i + 3], 0x0f0f0f0f, 4);
        SWAPMOVE(st[i + 6], st[i + 2], 0x0f0f0f0f, 4);
        SWAPMOVE(st[i + 5], st[i + 1], 0x0f0f0f0f, 4);
        SWAPMOVE(st[i + 4], st[i], 0x0f0f0f0f, 4);
        SWAPMOVE(st[i + 3], st[i + 1], 0x33333333, 2);
        SWAPMOVE(st[i + 2], st[i], 0x33333333, 2);
        SWAPMOVE(st[i + 1], st[i], 0x55555555, 1);
    }

    SWAPMOVE(st[8], st[8 + 16], 0x0000ffff, 16);
    SWAPMOVE(st[0], st[0 + 16], 0x0000ffff, 16);

    SWAPMOVE(st[0 + 16], st[0 + 24], 0x00ff00ff, 8);
    SWAPMOVE(st[0], st[0 + 8], 0x00ff00ff, 8);
}

static void
pack04_6(AesBlocks st)
{
    pack04_6_(st + 32 * 0);
    pack04_6_(st + 32 * 1);
}

static void
unpack04_6(AesBlocks st)
{
    unpack04_6_(st + 32 * 0);
    unpack04_6_(st + 32 * 1);
}

static void
pack_6_(AesBlocksBases st)
{
    size_t i;

    for (i = 0; i < 6; i++) {
        SWAPMOVE(st[i], st[i + 8], 0x00ff00ff, 8);
        SWAPMOVE(st[i + 16], st[i + 24], 0x00ff00ff, 8);
    }
    for (i = 0; i < 6; i++) {
        SWAPMOVE(st[i], st[i + 16], 0x0000ffff, 16);
    }
    for (i = 8; i < 14; i++) {
        SWAPMOVE(st[i], st[i + 16], 0x0000ffff, 16);
    }
    for (i = 0; i < 32; i += 8) {
        SWAPMOVE(st[i + 1], st[i], 0x55555555, 1);
        SWAPMOVE(st[i + 3], st[i + 2], 0x55555555, 1);
        SWAPMOVE(st[i + 5], st[i + 4], 0x55555555, 1);
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
pack_6(AesBlocks st)
{
    pack_6_(st + 32 * 0);
    pack_6_(st + 32 * 1);
}

static void
unpack_6_(AesBlocksBases st)
{
    size_t i;

    for (i = 0; i < 32; i += 8) {
        SWAPMOVE(st[i + 1], st[i], 0x55555555, 1);
        SWAPMOVE(st[i + 3], st[i + 2], 0x55555555, 1);
        SWAPMOVE(st[i + 5], st[i + 4], 0x55555555, 1);
        SWAPMOVE(st[i + 2], st[i], 0x33333333, 2);
        SWAPMOVE(st[i + 3], st[i + 1], 0x33333333, 2);
        SWAPMOVE(st[i + 6], st[i + 4], 0x33333333, 2);
        SWAPMOVE(st[i + 7], st[i + 5], 0x33333333, 2);
        SWAPMOVE(st[i + 4], st[i], 0x0f0f0f0f, 4);
        SWAPMOVE(st[i + 5], st[i + 1], 0x0f0f0f0f, 4);
        SWAPMOVE(st[i + 6], st[i + 2], 0x0f0f0f0f, 4);
        SWAPMOVE(st[i + 7], st[i + 3], 0x0f0f0f0f, 4);
    }
    for (i = 0; i < 6; i++) {
        SWAPMOVE(st[i], st[i + 16], 0x0000ffff, 16);
    }
    for (i = 8; i < 14; i++) {
        SWAPMOVE(st[i], st[i + 16], 0x0000ffff, 16);
    }
    for (i = 0; i < 6; i++) {
        SWAPMOVE(st[i], st[i + 8], 0x00ff00ff, 8);
        SWAPMOVE(st[i + 16], st[i + 24], 0x00ff00ff, 8);
    }
}

static void
unpack_6(AesBlocks st)
{
    unpack_6_(st + 32 * 0);
    unpack_6_(st + 32 * 1);
}

#endif
