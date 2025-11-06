/* LeMac-X4 AES-NI implementation
 *
 * This file implements a parallel variant of LeMAC for measuring
 * the performance impact of leveraging VAES instructions.
 */

#include <stdint.h>
#include <immintrin.h>
#include <string.h>

#define STATE_0 _mm512_set_epi64(0,0,0,0,0,0,0,0)

#define tabsize(T) (sizeof(T)/sizeof((T)[0]))

typedef struct {
  __m512i S[9];
} state;

typedef  struct {
  state init;
  __m512i keys[2][11];
  __m512i subkeys[18];
} context;


// AES key schedule from https://www.intel.com/content/dam/doc/white-paper/advanced-encryption-standard-new-instructions-set-paper.pdf

inline __m128i AES_128_ASSIST (__m128i temp1, __m128i temp2)     {
  __m128i temp3;
  temp2 = _mm_shuffle_epi32 (temp2 ,0xff);
  temp3 = _mm_slli_si128 (temp1, 0x4);
  temp1 = _mm_xor_si128 (temp1, temp3);
  temp3 = _mm_slli_si128 (temp3, 0x4);
  temp1 = _mm_xor_si128 (temp1, temp3);
  temp3 = _mm_slli_si128 (temp3, 0x4);
  temp1 = _mm_xor_si128 (temp1, temp3);
  temp1 = _mm_xor_si128 (temp1, temp2);
  return temp1;
}

void AES_KS (__m128i K, __m512i *Key_Schedule)     {
  __m128i temp1, temp2;
  temp1 = K;
  Key_Schedule[0] = _mm512_broadcast_i32x4(temp1);
  temp2 = _mm_aeskeygenassist_si128 (temp1 ,0x1);
  temp1 = AES_128_ASSIST(temp1, temp2);
  Key_Schedule[1] = _mm512_broadcast_i32x4(temp1);
  temp2 = _mm_aeskeygenassist_si128 (temp1,0x2);
  temp1 = AES_128_ASSIST(temp1, temp2);
  Key_Schedule[2] = _mm512_broadcast_i32x4(temp1);
  temp2 = _mm_aeskeygenassist_si128 (temp1,0x4);
  temp1 = AES_128_ASSIST(temp1, temp2);
  Key_Schedule[3] = _mm512_broadcast_i32x4(temp1);
  temp2 = _mm_aeskeygenassist_si128 (temp1,0x8);
  temp1 = AES_128_ASSIST(temp1, temp2);
  Key_Schedule[4] = _mm512_broadcast_i32x4(temp1);
  temp2 = _mm_aeskeygenassist_si128 (temp1,0x10);
  temp1 = AES_128_ASSIST(temp1, temp2);
  Key_Schedule[5] = _mm512_broadcast_i32x4(temp1);
  temp2 = _mm_aeskeygenassist_si128 (temp1,0x20);
  temp1 = AES_128_ASSIST(temp1, temp2);
  Key_Schedule[6] = _mm512_broadcast_i32x4(temp1);
  temp2 = _mm_aeskeygenassist_si128 (temp1,0x40);
  temp1 = AES_128_ASSIST(temp1, temp2);
  Key_Schedule[7] = _mm512_broadcast_i32x4(temp1);
  temp2 = _mm_aeskeygenassist_si128 (temp1,0x80);
  temp1 = AES_128_ASSIST(temp1, temp2);
  Key_Schedule[8] = _mm512_broadcast_i32x4(temp1);
  temp2 = _mm_aeskeygenassist_si128 (temp1,0x1b);
  temp1 = AES_128_ASSIST(temp1, temp2);
  Key_Schedule[9] = _mm512_broadcast_i32x4(temp1);
  temp2 = _mm_aeskeygenassist_si128 (temp1,0x36);
  temp1 = AES_128_ASSIST(temp1, temp2);
  Key_Schedule[10] = _mm512_broadcast_i32x4(temp1);
}

__m512i AES(const __m512i *Ki, __m512i x) {
  x ^= Ki[0];
  x = _mm512_aesenc_epi128(x, Ki[1]);
  x = _mm512_aesenc_epi128(x, Ki[2]);
  x = _mm512_aesenc_epi128(x, Ki[3]);
  x = _mm512_aesenc_epi128(x, Ki[4]);
  x = _mm512_aesenc_epi128(x, Ki[5]);
  x = _mm512_aesenc_epi128(x, Ki[6]);
  x = _mm512_aesenc_epi128(x, Ki[7]);
  x = _mm512_aesenc_epi128(x, Ki[8]);
  x = _mm512_aesenc_epi128(x, Ki[9]);
  x = _mm512_aesenclast_epi128(x, Ki[10]);
  return x;
}

__m512i AES_modified(const __m512i *Ki, __m512i x) {
  x ^= Ki[0];
  x = _mm512_aesenc_epi128(x, Ki[1]);
  x = _mm512_aesenc_epi128(x, Ki[2]);
  x = _mm512_aesenc_epi128(x, Ki[3]);
  x = _mm512_aesenc_epi128(x, Ki[4]);
  x = _mm512_aesenc_epi128(x, Ki[5]);
  x = _mm512_aesenc_epi128(x, Ki[6]);
  x = _mm512_aesenc_epi128(x, Ki[7]);
  x = _mm512_aesenc_epi128(x, Ki[8]);
  x = _mm512_aesenc_epi128(x, Ki[9]);
  x = _mm512_aesenc_epi128(x, _mm512_set_epi64(0,0,0,0,0,0,0,0));
  return x;
}

void lemac_x4_init(context *ctx, const uint8_t k[]) {
  const __m128i *K = (__m128i*)k;

  // Mask is <number of lanes - 1> || <lane id> || 0*
  const uint64_t mask0 = (0x03ULL << 56) | (0x00ULL << 48);
  const uint64_t mask1 = (0x03ULL << 56) | (0x01ULL << 48);
  const uint64_t mask2 = (0x03ULL << 56) | (0x02ULL << 48);
  const uint64_t mask3 = (0x03ULL << 56) | (0x03ULL << 48);
  __m512i Ki[11];
  AES_KS(*K, Ki);

  // Kinit 0 --> 8
  for (unsigned i=0; i<tabsize(ctx->init.S); i++)
    ctx->init.S[i] = AES(Ki, _mm512_set_epi64(mask0,i,mask1,i,mask2,i,mask3,i));

  // Kinit 9 --> 26
  for (unsigned i=0; i<tabsize(ctx->subkeys); i++)
    ctx->subkeys[i] = AES(Ki, _mm512_set_epi64(mask0,i+tabsize(ctx->init.S),
                                               mask1,i+tabsize(ctx->init.S),
                                               mask2,i+tabsize(ctx->init.S),
                                               mask3,i+tabsize(ctx->init.S)));

  // k2 27
  AES_KS(_mm512_castsi512_si128(AES(Ki, _mm512_set_epi64(mask0,tabsize(ctx->init.S)+tabsize(ctx->subkeys),
                                                         mask1,tabsize(ctx->init.S)+tabsize(ctx->subkeys),
                                                         mask2,tabsize(ctx->init.S)+tabsize(ctx->subkeys),
                                                         mask3,tabsize(ctx->init.S)+tabsize(ctx->subkeys)))), ctx->keys[0]);

  // k3 28
  AES_KS(_mm512_castsi512_si128(AES(Ki, _mm512_set_epi64(mask0,tabsize(ctx->init.S)+tabsize(ctx->subkeys)+1,
                                                         mask1,tabsize(ctx->init.S)+tabsize(ctx->subkeys)+1,
                                                         mask2,tabsize(ctx->init.S)+tabsize(ctx->subkeys)+1,
                                                         mask3,tabsize(ctx->init.S)+tabsize(ctx->subkeys)+1))), ctx->keys[1]);
}


#define ROUND(S, M0, M1, M2, M3, RR, R0, R1, R2) do {   \
    __m512i T = S.S[8];                                                     \
    S.S[8] = _mm512_aesenc_epi128(S.S[7],M3);                   \
    S.S[7] = _mm512_aesenc_epi128(S.S[6],M1);                   \
    S.S[6] = _mm512_aesenc_epi128(S.S[5],M1);                   \
    S.S[5] = _mm512_aesenc_epi128(S.S[4],M0);                   \
    S.S[4] = _mm512_aesenc_epi128(S.S[3],M0);                   \
    S.S[3] = _mm512_aesenc_epi128(S.S[2],R1 ^ R2);              \
    S.S[2] = _mm512_aesenc_epi128(S.S[1],M3);                   \
    S.S[1] = _mm512_aesenc_epi128(S.S[0],M3);                   \
    S.S[0] = S.S[0] ^ T ^ M2;                                           \
    R2 = R1;                                                    \
    R1 = R0;                                                    \
    R0 = RR ^ M1;                                               \
    RR = M2;                                                    \
  } while (0);

state lemac_x4_AU(context *ctx, const uint8_t *m, size_t mlen) {
  /* state S = ctx->init; */
  // Padding
  size_t m_padded_len = mlen - (mlen % 256) + 256;
  uint8_t m_padding[256];
  memcpy(m_padding, m + (mlen / 256) * 256, mlen % 256);
  m_padding[mlen % 256] = 1;
  __m512i *M_padding = (__m512i*) m_padding;
  for (size_t i = 1 + (mlen % 256); i < 256; ++i){
    m_padding[i] = 0;
  }

  const __m512i *M = (__m512i*)m;
  __m512i *Mfin = (__m512i*)(m + m_padded_len - 256);

  state S = ctx->init;

  __m512i RR = STATE_0;
  __m512i R0 = STATE_0;
  __m512i R1 = STATE_0;
  __m512i R2 = STATE_0;
  // Main rounds
  for (;M < Mfin; M+=4) {
    ROUND(S, M[0], M[1], M[2], M[3], RR, R0, R1, R2);
  }

  // Last round (padding)
  ROUND(S, M_padding[0], M_padding[1], M_padding[2], M_padding[3], RR, R0, R1, R2);

  // Four final rounds to absorb message state
  ROUND(S, STATE_0, STATE_0, STATE_0, STATE_0, RR, R0, R1, R2);
  ROUND(S, STATE_0, STATE_0, STATE_0, STATE_0, RR, R0, R1, R2);
  ROUND(S, STATE_0, STATE_0, STATE_0, STATE_0, RR, R0, R1, R2);
  ROUND(S, STATE_0, STATE_0, STATE_0, STATE_0, RR, R0, R1, R2);

  return S;
}

void lemac_x4_MAC(context *ctx, const uint8_t *nonce, const uint8_t *m, size_t mlen, uint8_t *tag) {
  state S = lemac_x4_AU(ctx, m, mlen);

  __m512i T;
  T  = AES_modified(ctx->subkeys  , S.S[0]);
  T ^= AES_modified(ctx->subkeys+1, S.S[1]);
  T ^= AES_modified(ctx->subkeys+2, S.S[2]);
  T ^= AES_modified(ctx->subkeys+3, S.S[3]);
  T ^= AES_modified(ctx->subkeys+4, S.S[4]);
  T ^= AES_modified(ctx->subkeys+5, S.S[5]);
  T ^= AES_modified(ctx->subkeys+6, S.S[6]);
  T ^= AES_modified(ctx->subkeys+7, S.S[7]);
  T ^= AES_modified(ctx->subkeys+8, S.S[8]);

  __m128i T_128 = _mm_xor_si128(_mm_xor_si128(_mm_xor_si128(
                    _mm512_extracti32x4_epi32(T, 0),  _mm512_extracti32x4_epi32(T, 1)),
                    _mm512_extracti32x4_epi32(T, 2)), _mm512_extracti32x4_epi32(T, 3));

  const __m128i N = *(const __m128i *) nonce;
  __m512i N_512 = _mm512_broadcast_i32x4(N);
  __m128i nonce_contrib = _mm512_castsi512_si128(AES(ctx->keys[0], N_512));
  T_128 ^= N ^ nonce_contrib;

  *(__m128i*)tag = _mm512_castsi512_si128(AES(ctx->keys[1], _mm512_broadcast_i32x4(T_128)));
}
