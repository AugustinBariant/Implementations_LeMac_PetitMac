#include <stdint.h>
#include <string.h>

#define UNROLL_BLOCK_SIZE 256 // NUM of STATES * BLOCK_SIZE
#define BLOCK_SIZE        16 // 128bits = 16 Bytes
#define UNROLL_ROUND      16 // = NUM of STATES
#define STATE             16 // NUM of STATES

#if defined(__AES__) && defined(__x86_64__)
#    include <immintrin.h>
#    include <wmmintrin.h>
typedef __m128i DATA128b;
#elif defined(__ARM_FEATURE_CRYPTO) && defined(__ARM_NEON)
#    include <arm_neon.h>
typedef uint8x16_t DATA128b;
#else
#    error arch_not_supported_yet
#endif

#define P_0 0
#define P_1 1
#define P_4 13
#define P_7 9
#define i_1 3
#define i_2 13

static const uint8_t CONST0[16] = { 0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
                                    0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34 };
static const uint8_t CONST1[16] = { 0x4a, 0x40, 0x93, 0x82, 0x22, 0x99, 0xf3, 0x1d,
                                    0x00, 0x82, 0xef, 0xa9, 0x8e, 0xc4, 0xe6, 0xc8 };

#if defined(__AES__) && defined(__x86_64__)
#    include <immintrin.h>
#    include <wmmintrin.h>

#    define SIMD_LOAD(x)     _mm_loadu_si128((const __m128i *) (x))
#    define SIMD_STORE(x, y) _mm_storeu_si128((__m128i *) (x), y)
#    define SIMD_XOR(x, y)   _mm_xor_si128(x, y)
#    define SIMD_ZERO_128()  _mm_setzero_si128()
#    define AESEMC(x, y)     _mm_aesenc_si128(SIMD_XOR(x, y), SIMD_ZERO_128())
#    define AESL(x)          _mm_aesenc_si128(x, SIMD_ZERO_128())
#    define AESENC(x, y)     _mm_aesenc_si128(x, y)

#elif defined(__ARM_FEATURE_CRYPTO) && defined(__ARM_NEON)
#    include <arm_neon.h>

#    define SIMD_LOAD(x)       vld1q_u8(x)
#    define SIMD_STORE(dst, x) vst1q_u8(dst, x)
#    define SIMD_XOR(a, b)     veorq_u8(a, b)
#    define SIMD_ZERO_128()    vmovq_n_u8(0)
#    define AESEMC(x, y)       vaesmcq_u8(vaeseq_u8(x, y))
#    define AESL(x)            AESEMC(x, SIMD_ZERO_128())
#    define AESENC(x, y)       SIMD_XOR(AESEMC(x, SIMD_ZERO_128()), y)

#else
#    error This_Arch_do_not_Supported_yet_!!!
#endif

/*
 * Avoid cost of extra XOR operation cross platform
 */
#if defined(__AES__) && defined(__x86_64__)

#    define UPDATE_STATE_offset(M, offset)                                                    \
        tmp[offset] = SIMD_XOR(state[(P_0 + offset) % STATE], state[(P_1 + offset) % STATE]); \
        tmp[offset] = AESENC(tmp[offset], M);                                                 \
        state[(0 + offset) % STATE]   = AESENC(state[(P_4 + offset) % STATE], tmp[offset]);   \
        state[(i_1 + offset) % STATE] = SIMD_XOR(state[(i_1 + offset) % STATE], M);           \
        state[(i_2 + offset) % STATE] = SIMD_XOR(state[(i_2 + offset) % STATE], M);

#    define ENC_offset(M, C, offset)                                                \
        C = SIMD_XOR(state[(P_0 + offset) % STATE], state[(P_1 + offset) % STATE]); \
        C = AESENC(C, M);                                                           \
        state[(0 + offset) % STATE]   = AESENC(state[(P_4 + offset) % STATE], C);   \
        C                             = SIMD_XOR(C, state[(P_7 + offset) % STATE]); \
        state[(i_1 + offset) % STATE] = SIMD_XOR(state[(i_1 + offset) % STATE], M); \
        state[(i_2 + offset) % STATE] = SIMD_XOR(state[(i_2 + offset) % STATE], M);

#    define DEC_offset(M, C, offset)                                                          \
        tmp[offset] = SIMD_XOR(state[(P_0 + offset) % STATE], state[(P_1 + offset) % STATE]); \
        M           = SIMD_XOR(state[(P_7 + offset) % STATE], C);                             \
        state[(0 + offset) % STATE]   = AESENC(state[(P_4 + offset) % STATE], M);             \
        M                             = AESENC(tmp[offset], M);                               \
        state[(i_1 + offset) % STATE] = SIMD_XOR(state[(i_1 + offset) % STATE], M);           \
        state[(i_2 + offset) % STATE] = SIMD_XOR(state[(i_2 + offset) % STATE], M);

#elif defined(__ARM_FEATURE_CRYPTO) && defined(__ARM_NEON)

#    define UPDATE_STATE_offset(M, offset)                                                          \
        tmp[offset] = AESEMC(state[(P_0 + offset) % STATE], state[(P_1 + offset) % STATE]);         \
        tmp[offset] = SIMD_XOR(tmp[offset], M);                                                     \
        state[(0 + offset) % STATE]   = SIMD_XOR(tmp[offset], AESL(state[(P_4 + offset) % STATE])); \
        state[(i_1 + offset) % STATE] = SIMD_XOR(state[(i_1 + offset) % STATE], M);                 \
        state[(i_2 + offset) % STATE] = SIMD_XOR(state[(i_2 + offset) % STATE], M);

#    define ENC_offset(M, C, offset)                                                        \
        tmp[offset] = AESEMC(state[(P_0 + offset) % STATE], state[(P_1 + offset) % STATE]); \
        C           = SIMD_XOR(tmp[offset], M);                                             \
        state[(0 + offset) % STATE]   = SIMD_XOR(C, AESL(state[(P_4 + offset) % STATE]));   \
        C                             = SIMD_XOR(C, state[(P_7 + offset) % STATE]);         \
        state[(i_1 + offset) % STATE] = SIMD_XOR(state[(i_1 + offset) % STATE], M);         \
        state[(i_2 + offset) % STATE] = SIMD_XOR(state[(i_2 + offset) % STATE], M);

#    define DEC_offset(M, C, offset)                                                        \
        tmp[offset] = AESEMC(state[(P_0 + offset) % STATE], state[(P_1 + offset) % STATE]); \
        M           = SIMD_XOR(state[(P_7 + offset) % STATE], C);                           \
        state[(0 + offset) % STATE]   = SIMD_XOR(M, AESL(state[(P_4 + offset) % STATE]));   \
        M                             = SIMD_XOR(M, tmp[offset]);                           \
        state[(i_1 + offset) % STATE] = SIMD_XOR(state[(i_1 + offset) % STATE], M);         \
        state[(i_2 + offset) % STATE] = SIMD_XOR(state[(i_2 + offset) % STATE], M);

#else

#    error This_Arch_do_not_Supported_yet_!!!

#endif

/*
 * load 4 128bit block from src
 */
#define LOAD_1BLOCK_offset(M, offset)                   \
    (M) = SIMD_LOAD(src + i + 0 + BLOCK_SIZE * offset); \
/*                                                      \
 * store 4 128bit block to dst                          \
 */
#define STORE_1BLOCK_offset(C, offset) SIMD_STORE(dst + i + 0 + BLOCK_SIZE * offset, (C));

#define encode_little_endian(bytes, v)           \
    bytes[0]  = ((uint64_t) (v) << (3));         \
    bytes[1]  = ((uint64_t) (v) >> (1 * 8 - 3)); \
    bytes[2]  = ((uint64_t) (v) >> (2 * 8 - 3)); \
    bytes[3]  = ((uint64_t) (v) >> (3 * 8 - 3)); \
    bytes[4]  = ((uint64_t) (v) >> (4 * 8 - 3)); \
    bytes[5]  = ((uint64_t) (v) >> (5 * 8 - 3)); \
    bytes[6]  = ((uint64_t) (v) >> (6 * 8 - 3)); \
    bytes[7]  = ((uint64_t) (v) >> (7 * 8 - 3)); \
    bytes[8]  = ((uint64_t) (v) >> (8 * 8 - 3)); \
    bytes[9]  = 0;                               \
    bytes[10] = 0;                               \
    bytes[11] = 0;                               \
    bytes[12] = 0;                               \
    bytes[13] = 0;                               \
    bytes[14] = 0;                               \
    bytes[15] = 0;

#define STATE_SHIFT        \
    tmp[0]    = state[0];  \
    state[0]  = state[1];  \
    state[1]  = state[2];  \
    state[2]  = state[3];  \
    state[3]  = state[4];  \
    state[4]  = state[5];  \
    state[5]  = state[6];  \
    state[6]  = state[7];  \
    state[7]  = state[8];  \
    state[8]  = state[9];  \
    state[9]  = state[10]; \
    state[10] = state[11]; \
    state[11] = state[12]; \
    state[12] = state[13]; \
    state[13] = state[14]; \
    state[14] = state[15]; \
    state[15] = tmp[0]

#define INIT_UPDATE(c0)          \
    UPDATE_STATE_offset(c0, 0);  \
    UPDATE_STATE_offset(c0, 1);  \
    UPDATE_STATE_offset(c0, 2);  \
    UPDATE_STATE_offset(c0, 3);  \
    UPDATE_STATE_offset(c0, 4);  \
    UPDATE_STATE_offset(c0, 5);  \
    UPDATE_STATE_offset(c0, 6);  \
    UPDATE_STATE_offset(c0, 7);  \
    UPDATE_STATE_offset(c0, 8);  \
    UPDATE_STATE_offset(c0, 9);  \
    UPDATE_STATE_offset(c0, 10); \
    UPDATE_STATE_offset(c0, 11); \
    UPDATE_STATE_offset(c0, 12); \
    UPDATE_STATE_offset(c0, 13); \
    UPDATE_STATE_offset(c0, 14); \
    UPDATE_STATE_offset(c0, 15);

#define AD_UPDATE                   \
    LOAD_1BLOCK_offset(M[0], 0);    \
    LOAD_1BLOCK_offset(M[1], 1);    \
    LOAD_1BLOCK_offset(M[2], 2);    \
    LOAD_1BLOCK_offset(M[3], 3);    \
    LOAD_1BLOCK_offset(M[4], 4);    \
    LOAD_1BLOCK_offset(M[5], 5);    \
    LOAD_1BLOCK_offset(M[6], 6);    \
    LOAD_1BLOCK_offset(M[7], 7);    \
    LOAD_1BLOCK_offset(M[8], 8);    \
    LOAD_1BLOCK_offset(M[9], 9);    \
    LOAD_1BLOCK_offset(M[10], 10);  \
    LOAD_1BLOCK_offset(M[11], 11);  \
    LOAD_1BLOCK_offset(M[12], 12);  \
    LOAD_1BLOCK_offset(M[13], 13);  \
    LOAD_1BLOCK_offset(M[14], 14);  \
    LOAD_1BLOCK_offset(M[15], 15);  \
    UPDATE_STATE_offset(M[0], 0);   \
    UPDATE_STATE_offset(M[1], 1);   \
    UPDATE_STATE_offset(M[2], 2);   \
    UPDATE_STATE_offset(M[3], 3);   \
    UPDATE_STATE_offset(M[4], 4);   \
    UPDATE_STATE_offset(M[5], 5);   \
    UPDATE_STATE_offset(M[6], 6);   \
    UPDATE_STATE_offset(M[7], 7);   \
    UPDATE_STATE_offset(M[8], 8);   \
    UPDATE_STATE_offset(M[9], 9);   \
    UPDATE_STATE_offset(M[10], 10); \
    UPDATE_STATE_offset(M[11], 11); \
    UPDATE_STATE_offset(M[12], 12); \
    UPDATE_STATE_offset(M[13], 13); \
    UPDATE_STATE_offset(M[14], 14); \
    UPDATE_STATE_offset(M[15], 15);

#define ENCRYPT                     \
    LOAD_1BLOCK_offset(M[0], 0);    \
    LOAD_1BLOCK_offset(M[1], 1);    \
    LOAD_1BLOCK_offset(M[2], 2);    \
    LOAD_1BLOCK_offset(M[3], 3);    \
    LOAD_1BLOCK_offset(M[4], 4);    \
    LOAD_1BLOCK_offset(M[5], 5);    \
    LOAD_1BLOCK_offset(M[6], 6);    \
    LOAD_1BLOCK_offset(M[7], 7);    \
    LOAD_1BLOCK_offset(M[8], 8);    \
    LOAD_1BLOCK_offset(M[9], 9);    \
    LOAD_1BLOCK_offset(M[10], 10);  \
    LOAD_1BLOCK_offset(M[11], 11);  \
    LOAD_1BLOCK_offset(M[12], 12);  \
    LOAD_1BLOCK_offset(M[13], 13);  \
    LOAD_1BLOCK_offset(M[14], 14);  \
    LOAD_1BLOCK_offset(M[15], 15);  \
    ENC_offset(M[0], C[0], 0);      \
    ENC_offset(M[1], C[1], 1);      \
    ENC_offset(M[2], C[2], 2);      \
    ENC_offset(M[3], C[3], 3);      \
    ENC_offset(M[4], C[4], 4);      \
    ENC_offset(M[5], C[5], 5);      \
    ENC_offset(M[6], C[6], 6);      \
    ENC_offset(M[7], C[7], 7);      \
    ENC_offset(M[8], C[8], 8);      \
    ENC_offset(M[9], C[9], 9);      \
    ENC_offset(M[10], C[10], 10);   \
    ENC_offset(M[11], C[11], 11);   \
    ENC_offset(M[12], C[12], 12);   \
    ENC_offset(M[13], C[13], 13);   \
    ENC_offset(M[14], C[14], 14);   \
    ENC_offset(M[15], C[15], 15);   \
    STORE_1BLOCK_offset(C[0], 0);   \
    STORE_1BLOCK_offset(C[1], 1);   \
    STORE_1BLOCK_offset(C[2], 2);   \
    STORE_1BLOCK_offset(C[3], 3);   \
    STORE_1BLOCK_offset(C[4], 4);   \
    STORE_1BLOCK_offset(C[5], 5);   \
    STORE_1BLOCK_offset(C[6], 6);   \
    STORE_1BLOCK_offset(C[7], 7);   \
    STORE_1BLOCK_offset(C[8], 8);   \
    STORE_1BLOCK_offset(C[9], 9);   \
    STORE_1BLOCK_offset(C[10], 10); \
    STORE_1BLOCK_offset(C[11], 11); \
    STORE_1BLOCK_offset(C[12], 12); \
    STORE_1BLOCK_offset(C[13], 13); \
    STORE_1BLOCK_offset(C[14], 14); \
    STORE_1BLOCK_offset(C[15], 15);

#define DECRYPT                     \
    LOAD_1BLOCK_offset(C[0], 0);    \
    LOAD_1BLOCK_offset(C[1], 1);    \
    LOAD_1BLOCK_offset(C[2], 2);    \
    LOAD_1BLOCK_offset(C[3], 3);    \
    LOAD_1BLOCK_offset(C[4], 4);    \
    LOAD_1BLOCK_offset(C[5], 5);    \
    LOAD_1BLOCK_offset(C[6], 6);    \
    LOAD_1BLOCK_offset(C[7], 7);    \
    LOAD_1BLOCK_offset(C[8], 8);    \
    LOAD_1BLOCK_offset(C[9], 9);    \
    LOAD_1BLOCK_offset(C[10], 10);  \
    LOAD_1BLOCK_offset(C[11], 11);  \
    LOAD_1BLOCK_offset(C[12], 12);  \
    LOAD_1BLOCK_offset(C[13], 13);  \
    LOAD_1BLOCK_offset(C[14], 14);  \
    LOAD_1BLOCK_offset(C[15], 15);  \
    DEC_offset(M[0], C[0], 0);      \
    DEC_offset(M[1], C[1], 1);      \
    DEC_offset(M[2], C[2], 2);      \
    DEC_offset(M[3], C[3], 3);      \
    DEC_offset(M[4], C[4], 4);      \
    DEC_offset(M[5], C[5], 5);      \
    DEC_offset(M[6], C[6], 6);      \
    DEC_offset(M[7], C[7], 7);      \
    DEC_offset(M[8], C[8], 8);      \
    DEC_offset(M[9], C[9], 9);      \
    DEC_offset(M[10], C[10], 10);   \
    DEC_offset(M[11], C[11], 11);   \
    DEC_offset(M[12], C[12], 12);   \
    DEC_offset(M[13], C[13], 13);   \
    DEC_offset(M[14], C[14], 14);   \
    DEC_offset(M[15], C[15], 15);   \
    STORE_1BLOCK_offset(M[0], 0);   \
    STORE_1BLOCK_offset(M[1], 1);   \
    STORE_1BLOCK_offset(M[2], 2);   \
    STORE_1BLOCK_offset(M[3], 3);   \
    STORE_1BLOCK_offset(M[4], 4);   \
    STORE_1BLOCK_offset(M[5], 5);   \
    STORE_1BLOCK_offset(M[6], 6);   \
    STORE_1BLOCK_offset(M[7], 7);   \
    STORE_1BLOCK_offset(M[8], 8);   \
    STORE_1BLOCK_offset(M[9], 9);   \
    STORE_1BLOCK_offset(M[10], 10); \
    STORE_1BLOCK_offset(M[11], 11); \
    STORE_1BLOCK_offset(M[12], 12); \
    STORE_1BLOCK_offset(M[13], 13); \
    STORE_1BLOCK_offset(M[14], 14); \
    STORE_1BLOCK_offset(M[15], 15);

static void
HiAE_stream_init(DATA128b *state, const uint8_t *key, const uint8_t *iv)
{
    DATA128b c0 = SIMD_LOAD(CONST0);
    DATA128b c1 = SIMD_LOAD(CONST1);
    DATA128b k0 = SIMD_LOAD(key);
    DATA128b k1 = SIMD_LOAD(key + 16);
    DATA128b N  = SIMD_LOAD(iv);

    DATA128b ze = SIMD_ZERO_128();
    state[0]    = c0;
    state[1]    = k1;
    state[2]    = N;
    state[3]    = c0;
    state[4]    = ze;
    state[5]    = SIMD_XOR(N, k0);
    state[6]    = ze;
    state[7]    = c1;
    state[8]    = SIMD_XOR(N, k1);
    state[9]    = ze;
    state[10]   = k1;
    state[11]   = c0;
    state[12]   = c1;
    state[13]   = k1;
    state[14]   = ze;
    state[15]   = SIMD_XOR(c0, c1);

    DATA128b tmp[STATE];
    INIT_UPDATE(c0);
    INIT_UPDATE(c0);
    state[9]  = SIMD_XOR(state[9], k0);
    state[13] = SIMD_XOR(state[13], k1);
}

static void
HiAE_stream_proc_ad(DATA128b *state, const uint8_t *ad, size_t len)
{
    size_t         i      = 0;
    size_t         rest   = len % UNROLL_BLOCK_SIZE;
    size_t         prefix = len - rest;
    const uint8_t *src    = ad;
    DATA128b       tmp[STATE], M[16];
    if (len == 0)
        return;
    for (; i < prefix; i += UNROLL_BLOCK_SIZE) {
        AD_UPDATE;
    }
    for (; i < len; i += BLOCK_SIZE) {
        M[0] = SIMD_LOAD(ad + i);
        UPDATE_STATE_offset(M[0], 0);
        STATE_SHIFT;
    }
    const size_t left = len & BLOCK_SIZE;
    if (left) {
        uint8_t padding[BLOCK_SIZE] = { 0 };
        memcpy(padding, ad + i, left);
        M[0] = SIMD_LOAD(padding);
        UPDATE_STATE_offset(M[0], 0);
        STATE_SHIFT;
    }
}

static void
HiAE_stream_finalize(DATA128b *state, uint64_t ad_len, uint64_t plain_len, uint8_t *tag)
{
    uint64_t lens[2];
    lens[0] = ad_len;
    lens[1] = plain_len;
    DATA128b temp, tmp[STATE];
    temp = SIMD_LOAD((uint8_t *) lens);
    INIT_UPDATE(temp);
    INIT_UPDATE(temp);
    temp = state[0];
    for (size_t i = 1; i < STATE; ++i) {
        temp = SIMD_XOR(temp, state[i]);
    }
    SIMD_STORE(tag, temp);
}

int
crypto_aead_encrypt(unsigned char *c, unsigned long long *clen, const unsigned char *m,
                    unsigned long long mlen, const unsigned char *ad, unsigned long long adlen,
                    const unsigned char *nsec, const unsigned char *npub, const unsigned char *k)
{
    (void) nsec;
    (void) m;
    (void) mlen;

    DATA128b state[STATE];
    HiAE_stream_init(state, k, npub);
    HiAE_stream_proc_ad(state, ad, adlen);
    HiAE_stream_finalize(state, adlen, 0, c);

    *clen = 16;

    return 0;
}
