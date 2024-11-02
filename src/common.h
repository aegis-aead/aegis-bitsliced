#ifndef common_H
#define common_H

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "include/aegis.h"

/* Keep the state in bitsliced representation during initialization and finalization */
#define KEEP_STATE_BITSLICED
/* Force the compiler to emit different versions of functions that aren't always inlined (ex: pack)
 in order to avoid performance regressions when KEEP_STATE_BITSLICED is set */
#define ALT_REGISTER_ALLOCATION

#if defined(__i386__) || defined(_M_IX86) || defined(__x86_64__) || defined(_M_AMD64)
#    define NATIVE_LITTLE_ENDIAN
#endif
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#    ifndef NATIVE_LITTLE_ENDIAN
#        define NATIVE_LITTLE_ENDIAN
#    endif
#endif

#if defined(__INTEL_COMPILER) || defined(_MSC_VER)
#    define CRYPTO_ALIGN(x) __declspec(align(x))
#else
#    define CRYPTO_ALIGN(x) __attribute__((aligned(x)))
#endif

#define LOAD32_LE(SRC) load32_le(SRC)
static inline uint32_t
load32_le(const uint8_t src[4])
{
#ifdef NATIVE_LITTLE_ENDIAN
    uint32_t w;
    memcpy(&w, src, sizeof w);
    return w;
#else
    uint32_t w = (uint32_t) src[0];
    w |= (uint32_t) src[1] << 8;
    w |= (uint32_t) src[2] << 16;
    w |= (uint32_t) src[3] << 24;
    return w;
#endif
}

#define STORE32_LE(DST, W) store32_le((DST), (W))
static inline void
store32_le(uint8_t dst[4], uint32_t w)
{
#ifdef NATIVE_LITTLE_ENDIAN
    memcpy(dst, &w, sizeof w);
#else
    dst[0] = (uint8_t) w;
    w >>= 8;
    dst[1] = (uint8_t) w;
    w >>= 8;
    dst[2] = (uint8_t) w;
    w >>= 8;
    dst[3] = (uint8_t) w;
#endif
}

#define STORE64_LE(DST, W) store64_le((DST), (W))
static inline void
store64_le(uint8_t dst[8], uint64_t w)
{
#ifdef NATIVE_LITTLE_ENDIAN
    memcpy(dst, &w, sizeof w);
#else
    dst[0] = (uint8_t) w;
    w >>= 8;
    dst[1] = (uint8_t) w;
    w >>= 8;
    dst[2] = (uint8_t) w;
    w >>= 8;
    dst[3] = (uint8_t) w;
    w >>= 8;
    dst[4] = (uint8_t) w;
    w >>= 8;
    dst[5] = (uint8_t) w;
    w >>= 8;
    dst[6] = (uint8_t) w;
    w >>= 8;
    dst[7] = (uint8_t) w;
#endif
}

#define ROTL32(X, B) rotl32((X), (B))
static inline uint32_t
rotl32(const uint32_t x, const int b)
{
    return (x << b) | (x >> (32 - b));
}

#define ROTL32_64(x, b)                                         \
    ((x << b) & ((~(uint64_t) 0xffffffff << b) | 0xffffffff)) | \
        ((x >> (32 - b)) &                                      \
         ((0xffffffff >> (32 - b)) | (((uint64_t) 0xffffffff >> (32 - b)) << 32)))

#define COMPILER_ASSERT(X) (void) sizeof(char[(X) ? 1 : -1])

#endif
