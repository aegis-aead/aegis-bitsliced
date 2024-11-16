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
    // ftop
    const uint32_t Z18  = u[1] ^ u[4];
    const uint32_t L28  = Z18 ^ u[6];
    const uint32_t Q0   = u[2] ^ L28;
    const uint32_t Z96  = u[5] ^ u[6];
    const uint32_t Q1   = u[0] ^ Z96;
    const uint32_t Z160 = u[5] ^ u[7];
    const uint32_t Q2   = u[6] ^ Z160;
    const uint32_t Q11  = u[2] ^ u[3];
    const uint32_t L6   = u[4] ^ Z96;
    const uint32_t Q3   = Q11 ^ L6;
    const uint32_t Q16  = u[0] ^ Q11;
    const uint32_t Q4   = Q16 ^ u[4];
    const uint32_t Q5   = Z18 ^ Z160;
    const uint32_t Z10  = u[1] ^ u[3];
    const uint32_t Q6   = Z10 ^ Q2;
    const uint32_t Q7   = u[0] ^ u[7];
    const uint32_t Z36  = u[2] ^ u[5];
    const uint32_t Q8   = Z36 ^ Q5;
    const uint32_t L19  = u[2] ^ Z96;
    const uint32_t Q9   = Z18 ^ L19;
    const uint32_t Q10  = Z10 ^ Q1;
    const uint32_t Q12  = u[3] ^ L28;
    const uint32_t Q13  = u[3] ^ Q2;
    const uint32_t L10  = Z36 ^ Q7;
    const uint32_t Q14  = u[6] ^ L10;
    const uint32_t Q15  = u[0] ^ Q5;
    const uint32_t L8   = u[3] ^ Q5;
    const uint32_t L12  = Q16 ^ Q2;
    const uint32_t L16  = u[2] ^ Q4;
    const uint32_t L15  = u[1] ^ Z96;
    const uint32_t L31  = Q16 ^ L15;
    const uint32_t L5   = Q12 ^ L31;
    const uint32_t L13  = u[3] ^ Q8;
    const uint32_t L17  = u[4] ^ L10;
    const uint32_t L29  = Z96 ^ L10;
    const uint32_t L14  = Q11 ^ L10;
    const uint32_t L26  = Q11 ^ Q5;
    const uint32_t L30  = Q11 ^ u[6];
    const uint32_t L7   = Q12 ^ Q1;
    const uint32_t L11  = Q12 ^ L15;
    const uint32_t L27  = L30 ^ L10;
    const uint32_t Q17  = u[0];
    const uint32_t L0   = Q10;
    const uint32_t L4   = u[6];
    const uint32_t L20  = Q0;
    const uint32_t L24  = Q16;
    const uint32_t L1   = Q6;
    const uint32_t L9   = u[5];
    const uint32_t L21  = Q11;
    const uint32_t L25  = Q13;
    const uint32_t L2   = Q9;
    const uint32_t L18  = u[1];
    const uint32_t L22  = Q15;
    const uint32_t L3   = Q8;
    const uint32_t L23  = u[0];

    // mulx.a
    const uint32_t T20 = NAND(Q6, Q12);
    const uint32_t T21 = NAND(Q3, Q14);
    const uint32_t T22 = NAND(Q1, Q16);
    const uint32_t T10 = (NOR(Q3, Q14) ^ NAND(Q0, Q7));
    const uint32_t T11 = (NOR(Q4, Q13) ^ NAND(Q10, Q11));
    const uint32_t T12 = (NOR(Q2, Q17) ^ NAND(Q5, Q9));
    const uint32_t T13 = (NOR(Q8, Q15) ^ NAND(Q2, Q17));
    const uint32_t X0  = T10 ^ (T20 ^ T22);
    const uint32_t X1  = T11 ^ (T21 ^ T20);
    const uint32_t X2  = T12 ^ (T21 ^ T22);
    const uint32_t X3  = T13 ^ (T21 ^ NAND(Q4, Q13));

    // inv.a
    const uint32_t T0 = NAND(X0, X2);
    const uint32_t T1 = NOR(X1, X3);
    const uint32_t T2 = XNOR(T0, T1);
    const uint32_t Y0 = MUX(X2, T2, X3);
    const uint32_t Y2 = MUX(X0, T2, X1);
    const uint32_t T3 = MUX(X1, X2, ~0);
    const uint32_t Y1 = MUX(T2, X3, T3);
    const uint32_t T4 = MUX(X3, X0, ~0);
    const uint32_t Y3 = MUX(T2, X1, T4);

    // mull.f
    const uint32_t K4  = AND(Y0, L4);
    const uint32_t K8  = AND(Y0, L8);
    const uint32_t K24 = AND(Y0, L24);
    const uint32_t K28 = AND(Y0, L28);

    // mull.d
    const uint32_t K0  = NAND(Y0, L0);
    const uint32_t K12 = NAND(Y0, L12);
    const uint32_t K16 = NAND(Y0, L16);
    const uint32_t K20 = NAND(Y0, L20);
    const uint32_t K1  = NAND(Y1, L1);
    const uint32_t K5  = NAND(Y1, L5);
    const uint32_t K9  = NAND(Y1, L9);
    const uint32_t K13 = NAND(Y1, L13);
    const uint32_t K17 = NAND(Y1, L17);
    const uint32_t K21 = NAND(Y1, L21);
    const uint32_t K25 = NAND(Y1, L25);
    const uint32_t K29 = NAND(Y1, L29);
    const uint32_t K2  = NAND(Y2, L2);
    const uint32_t K6  = NAND(Y2, L6);
    const uint32_t K10 = NAND(Y2, L10);
    const uint32_t K14 = NAND(Y2, L14);
    const uint32_t K18 = NAND(Y2, L18);
    const uint32_t K22 = NAND(Y2, L22);
    const uint32_t K26 = NAND(Y2, L26);
    const uint32_t K30 = NAND(Y2, L30);
    const uint32_t K3  = NAND(Y3, L3);
    const uint32_t K7  = NAND(Y3, L7);
    const uint32_t K11 = NAND(Y3, L11);
    const uint32_t K15 = NAND(Y3, L15);
    const uint32_t K19 = NAND(Y3, L19);
    const uint32_t K23 = NAND(Y3, L23);
    const uint32_t K27 = NAND(Y3, L27);
    const uint32_t K31 = NAND(Y3, L31);

    // 8xor4.d
    u[0] = (K0 ^ K1) ^ (K2 ^ K3);
    u[1] = (K4 ^ K5) ^ (K6 ^ K7);
    u[2] = (K8 ^ K9) ^ (K10 ^ K11);
    u[3] = (K12 ^ K13) ^ (K14 ^ K15);
    u[4] = (K16 ^ K17) ^ (K18 ^ K19);
    u[5] = (K20 ^ K21) ^ (K22 ^ K23);
    u[6] = (K24 ^ K25) ^ (K26 ^ K27);
    u[7] = (K28 ^ K29) ^ (K30 ^ K31);
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
pack04_(AesBlocks st)
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
pack04(AesBlocks st)
{
    pack04_(st + 32 * 0);
    pack04_(st + 32 * 1);
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