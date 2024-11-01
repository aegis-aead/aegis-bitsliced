#include <stddef.h>
#include <stdint.h>

#include "common.h"

static volatile uint16_t optblocker_u16;

static inline int
aegis_verify_n(const uint8_t *x_, const uint8_t *y_, const int n)
{
    const volatile uint8_t *volatile x = (const volatile uint8_t *volatile) x_;
    const volatile uint8_t *volatile y = (const volatile uint8_t *volatile) y_;
    volatile uint16_t d                = 0U;
    int               i;

    for (i = 0; i < n; i++) {
        d |= x[i] ^ y[i];
    }
#if defined(__GNUC__) || defined(__clang__)
    __asm__("" : "+r"(d) :);
#endif
    d--;
    d = ((d >> 13) ^ optblocker_u16) >> 2;

    return (int) d - 1;
}

int
aegis_verify_16(const uint8_t *x, const uint8_t *y)
{
    return aegis_verify_n(x, y, 16);
}

int
aegis_verify_32(const uint8_t *x, const uint8_t *y)
{
    return aegis_verify_n(x, y, 32);
}
