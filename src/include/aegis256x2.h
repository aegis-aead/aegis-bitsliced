#ifndef aegis256x2_H
#define aegis256x2_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* The length of an AEGIS key, in bytes */
#define aegis256x2_KEYBYTES 32

/* The length of an AEGIS nonce, in bytes */
#define aegis256x2_NPUBBYTES 32

/* The minimum length of an AEGIS authentication tag, in bytes */
#define aegis256x2_ABYTES_MIN 16

/* The maximum length of an AEGIS authentication tag, in bytes */
#define aegis256x2_ABYTES_MAX 32

/* The length of an AEGIS key, in bytes */
size_t aegis256x2_keybytes(void);

/* The length of an AEGIS nonce, in bytes */
size_t aegis256x2_npubbytes(void);

/* The minimum length of an AEGIS authentication tag, in bytes */
size_t aegis256x2_abytes_min(void);

/* The maximum length of an AEGIS authentication tag, in bytes */
size_t aegis256x2_abytes_max(void);

/*
 * Encrypt a message with AEGIS in one shot mode, returning the tag and the ciphertext separately.
 *
 * c: ciphertext output buffer
 * mac: authentication tag output buffer
 * maclen: length of the authentication tag to generate (16 or 32)
 * m: plaintext input buffer
 * mlen: length of the plaintext
 * ad: additional data input buffer
 * adlen: length of the additional data
 * npub: nonce input buffer (32 bytes)
 * k: key input buffer (32 bytes)
 */
int aegis256x2_encrypt_detached(uint8_t *c, uint8_t *mac, size_t maclen, const uint8_t *m,
                                size_t mlen, const uint8_t *ad, size_t adlen, const uint8_t *npub,
                                const uint8_t *k);

/*
 * Decrypt a message with AEGIS in one shot mode, returning the tag and the ciphertext separately.
 *
 * m: plaintext output buffer
 * c: ciphertext input buffer
 * clen: length of the ciphertext
 * mac: authentication tag input buffer
 * maclen: length of the authentication tag (16 or 32)
 * ad: additional data input buffer
 * adlen: length of the additional data
 * npub: nonce input buffer (32 bytes)
 * k: key input buffer (32 bytes)
 *
 * Returns 0 if the ciphertext is authentic, -1 otherwise.
 */
int aegis256x2_decrypt_detached(uint8_t *m, const uint8_t *c, size_t clen, const uint8_t *mac,
                                size_t maclen, const uint8_t *ad, size_t adlen, const uint8_t *npub,
                                const uint8_t *k) __attribute__((warn_unused_result));

/*
 * Encrypt a message with AEGIS in one shot mode, returning the tag and the ciphertext together.
 *
 * c: ciphertext output buffer
 * maclen: length of the authentication tag to generate (16 or 32)
 * m: plaintext input buffer
 * mlen: length of the plaintext
 * ad: additional data input buffer
 * adlen: length of the additional data
 * npub: nonce input buffer (32 bytes)
 * k: key input buffer (32 bytes)
 */
int aegis256x2_encrypt(uint8_t *c, size_t maclen, const uint8_t *m, size_t mlen, const uint8_t *ad,
                       size_t adlen, const uint8_t *npub, const uint8_t *k);

/*
 * Decrypt a message with AEGIS in one shot mode, returning the tag and the ciphertext together.
 *
 * m: plaintext output buffer
 * c: ciphertext input buffer
 * clen: length of the ciphertext
 * maclen: length of the authentication tag (16 or 32)
 * ad: additional data input buffer
 * adlen: length of the additional data
 * npub: nonce input buffer (32 bytes)
 * k: key input buffer (32 bytes)
 *
 * Returns 0 if the ciphertext is authentic, -1 otherwise.
 */
int aegis256x2_decrypt(uint8_t *m, const uint8_t *c, size_t clen, size_t maclen, const uint8_t *ad,
                       size_t adlen, const uint8_t *npub, const uint8_t *k)
    __attribute__((warn_unused_result));

#ifdef __cplusplus
}
#endif

#endif
