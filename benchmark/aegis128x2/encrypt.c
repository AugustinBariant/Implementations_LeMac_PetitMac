#include <limits.h>
#include <stdint.h>
#include <string.h>

// common.h

#include <stdint.h>
#include <string.h>

#if !defined(__cplusplus) && (!defined(__STDC_VERSION__) || __STDC_VERSION__ < 199901L)
#    ifdef _MSC_VER
#        define inline __inline
#    endif
#endif

#if !defined(__clang__) && !defined(__GNUC__)
#    ifdef __attribute__
#        undef __attribute__
#    endif
#    define __attribute__(a)
#endif

#ifndef CRYPTO_ALIGN
#    if defined(__INTEL_COMPILER) || defined(_MSC_VER)
#        define CRYPTO_ALIGN(x) __declspec(align(x))
#    else
#        define CRYPTO_ALIGN(x) __attribute__((aligned(x)))
#    endif
#endif

#define LOAD32_LE(SRC) load32_le(SRC)
static inline uint32_t
load32_le(const uint8_t src[4])
{
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
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
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
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

#define ROTL32(X, B) rotl32((X), (B))
static inline uint32_t
rotl32(const uint32_t x, const int b)
{
    return (x << b) | (x >> (32 - b));
}

// encrypt.c

#include <immintrin.h>
#include <wmmintrin.h>

#ifdef __clang__
#    pragma clang attribute push(__attribute__((target("aes,avx"))), apply_to = function)
#elif defined(__GNUC__)
#    pragma GCC target("aes,avx")
#endif

#define AES_BLOCK_LENGTH 32

typedef struct {
    __m128i b0;
    __m128i b1;
} aes_block_t;

static inline aes_block_t
AES_BLOCK_XOR(const aes_block_t a, const aes_block_t b)
{
    return (aes_block_t) { _mm_xor_si128(a.b0, b.b0), _mm_xor_si128(a.b1, b.b1) };
}

static inline aes_block_t
AES_BLOCK_AND(const aes_block_t a, const aes_block_t b)
{
    return (aes_block_t) { _mm_and_si128(a.b0, b.b0), _mm_and_si128(a.b1, b.b1) };
}

static inline aes_block_t
AES_BLOCK_LOAD(const uint8_t *a)
{
    return (aes_block_t) { _mm_loadu_si128((const __m128i *) (const void *) a),
                           _mm_loadu_si128((const __m128i *) (const void *) (a + 16)) };
}

static inline aes_block_t
AES_BLOCK_LOAD_64x2(uint64_t a, uint64_t b)
{
    const __m128i t = _mm_set_epi64x((long long) a, (long long) b);
    return (aes_block_t) { t, t };
}

static inline void
AES_BLOCK_STORE(uint8_t *a, const aes_block_t b)
{
    _mm_storeu_si128((__m128i *) (void *) a, b.b0);
    _mm_storeu_si128((__m128i *) (void *) (a + 16), b.b1);
}

static inline aes_block_t
AES_ENC(const aes_block_t a, const aes_block_t b)
{
    return (aes_block_t) { _mm_aesenc_si128(a.b0, b.b0), _mm_aesenc_si128(a.b1, b.b1) };
}

static inline void
aegis128x2_update(aes_block_t *const state, const aes_block_t d1, const aes_block_t d2)
{
    aes_block_t tmp;

    tmp      = state[7];
    state[7] = AES_ENC(state[6], state[7]);
    state[6] = AES_ENC(state[5], state[6]);
    state[5] = AES_ENC(state[4], state[5]);
    state[4] = AES_ENC(state[3], state[4]);
    state[3] = AES_ENC(state[2], state[3]);
    state[2] = AES_ENC(state[1], state[2]);
    state[1] = AES_ENC(state[0], state[1]);
    state[0] = AES_ENC(tmp, state[0]);

    state[0] = AES_BLOCK_XOR(state[0], d1);
    state[4] = AES_BLOCK_XOR(state[4], d2);
}

// 128x2-common.h

#define RATE 64

static void
aegis128x2_init(const uint8_t *key, const uint8_t *nonce, aes_block_t *const state)
{
    static CRYPTO_ALIGN(AES_BLOCK_LENGTH) const uint8_t c0_[AES_BLOCK_LENGTH] = {
        0x00, 0x01, 0x01, 0x02, 0x03, 0x05, 0x08, 0x0d, 0x15, 0x22, 0x37,
        0x59, 0x90, 0xe9, 0x79, 0x62, 0x00, 0x01, 0x01, 0x02, 0x03, 0x05,
        0x08, 0x0d, 0x15, 0x22, 0x37, 0x59, 0x90, 0xe9, 0x79, 0x62,
    };
    static CRYPTO_ALIGN(AES_BLOCK_LENGTH) const uint8_t c1_[AES_BLOCK_LENGTH] = {
        0xdb, 0x3d, 0x18, 0x55, 0x6d, 0xc2, 0x2f, 0xf1, 0x20, 0x11, 0x31,
        0x42, 0x73, 0xb5, 0x28, 0xdd, 0xdb, 0x3d, 0x18, 0x55, 0x6d, 0xc2,
        0x2f, 0xf1, 0x20, 0x11, 0x31, 0x42, 0x73, 0xb5, 0x28, 0xdd,
    };

    const aes_block_t c0 = AES_BLOCK_LOAD(c0_);
    const aes_block_t c1 = AES_BLOCK_LOAD(c1_);
    uint8_t           tmp[2 * 16];
    uint8_t           context_bytes[AES_BLOCK_LENGTH];
    aes_block_t       context;
    aes_block_t       k;
    aes_block_t       n;
    int               i;

    memcpy(tmp, key, 16);
    memcpy(tmp + 16, key, 16);
    k = AES_BLOCK_LOAD(tmp);

    memcpy(tmp, nonce, 16);
    memcpy(tmp + 16, nonce, 16);
    n = AES_BLOCK_LOAD(tmp);

    memset(context_bytes, 0, sizeof context_bytes);
    context_bytes[0 * 16]     = 0x00;
    context_bytes[0 * 16 + 1] = 0x01;
    context_bytes[1 * 16]     = 0x01;
    context_bytes[1 * 16 + 1] = 0x01;
    context                   = AES_BLOCK_LOAD(context_bytes);

    state[0] = AES_BLOCK_XOR(k, n);
    state[1] = c1;
    state[2] = c0;
    state[3] = c1;
    state[4] = AES_BLOCK_XOR(k, n);
    state[5] = AES_BLOCK_XOR(k, c0);
    state[6] = AES_BLOCK_XOR(k, c1);
    state[7] = AES_BLOCK_XOR(k, c0);
    for (i = 0; i < 10; i++) {
        state[3] = AES_BLOCK_XOR(state[3], context);
        state[7] = AES_BLOCK_XOR(state[7], context);
        aegis128x2_update(state, n, k);
    }
}

static void
aegis128x2_mac(uint8_t *mac, size_t adlen, size_t mlen, aes_block_t *const state)
{
    uint8_t     mac_multi_0[AES_BLOCK_LENGTH];
    uint8_t     mac_multi_1[AES_BLOCK_LENGTH];
    aes_block_t tmp;
    int         i;

    tmp = AES_BLOCK_LOAD_64x2(((uint64_t) mlen) << 3, ((uint64_t) adlen) << 3);
    tmp = AES_BLOCK_XOR(tmp, state[2]);

    for (i = 0; i < 7; i++) {
        aegis128x2_update(state, tmp, tmp);
    }

    tmp = AES_BLOCK_XOR(state[6], AES_BLOCK_XOR(state[5], state[4]));
    tmp = AES_BLOCK_XOR(tmp, AES_BLOCK_XOR(state[3], state[2]));
    tmp = AES_BLOCK_XOR(tmp, AES_BLOCK_XOR(state[1], state[0]));
    AES_BLOCK_STORE(mac_multi_0, tmp);
    for (i = 0; i < 16; i++) {
        mac[i] = mac_multi_0[i] ^ mac_multi_0[1 * 16 + i];
    }
}

static inline void
aegis128x2_absorb(const uint8_t *const src, aes_block_t *const state)
{
    aes_block_t msg0, msg1;

    msg0 = AES_BLOCK_LOAD(src);
    msg1 = AES_BLOCK_LOAD(src + AES_BLOCK_LENGTH);
    aegis128x2_update(state, msg0, msg1);
}

static inline void
aegis128x2_absorb2(const uint8_t *const src, aes_block_t *const state)
{
    aes_block_t msg0, msg1, msg2, msg3;

    msg0 = AES_BLOCK_LOAD(src + 0 * AES_BLOCK_LENGTH);
    msg1 = AES_BLOCK_LOAD(src + 1 * AES_BLOCK_LENGTH);
    msg2 = AES_BLOCK_LOAD(src + 2 * AES_BLOCK_LENGTH);
    msg3 = AES_BLOCK_LOAD(src + 3 * AES_BLOCK_LENGTH);
    aegis128x2_update(state, msg0, msg1);
    aegis128x2_update(state, msg2, msg3);
}

static int
encrypt_detached(uint8_t *c, uint8_t *mac, size_t maclen, const uint8_t *m, size_t mlen,
                 const uint8_t *ad, size_t adlen, const uint8_t *npub, const uint8_t *k)
{
    aes_block_t                state[8];
    CRYPTO_ALIGN(RATE) uint8_t src[RATE];
    size_t                     i;

    (void) c;
    (void) m;
    (void) mlen;

    aegis128x2_init(k, npub, state);

    for (i = 0; i + RATE * 2 <= adlen; i += RATE * 2) {
        aegis128x2_absorb2(ad + i, state);
    }
    for (; i + RATE <= adlen; i += RATE) {
        aegis128x2_absorb(ad + i, state);
    }
    if (adlen % RATE) {
        memset(src, 0, RATE);
        memcpy(src, ad + i, adlen % RATE);
        aegis128x2_absorb(src, state);
    }
    aegis128x2_mac(mac, adlen, mlen, state);

    return 0;
}

int
crypto_aead_encrypt(unsigned char *c, unsigned long long *clen, const unsigned char *m,
                    unsigned long long mlen, const unsigned char *ad, unsigned long long adlen,
                    const unsigned char *nsec, const unsigned char *npub, const unsigned char *k)
{
    (void) nsec;
    (void) m;
    (void) mlen;

    if (encrypt_detached(NULL, c, 16, NULL, 0U,
                         (const uint8_t *) ad, (size_t) adlen,
                         (const uint8_t *) npub, (const uint8_t *) k) != 0) {
        return -1;
    }
    *clen = 16;

    return 0;
}

#ifdef __clang__
#    pragma clang attribute pop
#endif
