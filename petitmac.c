/* PetitMac AES-NI implementation

Written in 2024 by
  Augustin Bariant <augustin.bariant@ssi.gouv.fr>
  Gaëtan Leurent <gaetan.leurent@inria.fr>

To the extent possible under law, the author(s) have dedicated all
copyright and related and neighboring rights to this software to the
public domain worldwide. This software is distributed without any
warranty.

You should have received a copy of the CC0 Public Domain Dedication
along with this software. If not, see
<http://creativecommons.org/publicdomain/zero/1.0/>.
*/

/* NOTES 
 - Assumes that the message size is a multiple of 8bits
 - Assumes that endianness matches the hardware
 */

#include <stdint.h>
#include <immintrin.h>
#include <string.h>

#define STATE_0 _mm_set_epi64x(0,0)

#define tabsize(T) (sizeof(T)/sizeof((T)[0]))

typedef struct {
  __m128i S[6];
} state;

typedef  struct {
  state init;
  __m128i keys[2][11];
  __m128i subkeys[15];
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

void AES_KS (__m128i K, __m128i *Key_Schedule)     {
  __m128i temp1, temp2;
  temp1 = K;
  Key_Schedule[0] = temp1;
  temp2 = _mm_aeskeygenassist_si128 (temp1 ,0x1);
  temp1 = AES_128_ASSIST(temp1, temp2);
  Key_Schedule[1] = temp1;
  temp2 = _mm_aeskeygenassist_si128 (temp1,0x2);
  temp1 = AES_128_ASSIST(temp1, temp2);
  Key_Schedule[2] = temp1;
  temp2 = _mm_aeskeygenassist_si128 (temp1,0x4);
  temp1 = AES_128_ASSIST(temp1, temp2);
  Key_Schedule[3] = temp1;
  temp2 = _mm_aeskeygenassist_si128 (temp1,0x8);
  temp1 = AES_128_ASSIST(temp1, temp2);
  Key_Schedule[4] = temp1;
  temp2 = _mm_aeskeygenassist_si128 (temp1,0x10);
  temp1 = AES_128_ASSIST(temp1, temp2);
  Key_Schedule[5] = temp1;
  temp2 = _mm_aeskeygenassist_si128 (temp1,0x20);
  temp1 = AES_128_ASSIST(temp1, temp2);
  Key_Schedule[6] = temp1;
  temp2 = _mm_aeskeygenassist_si128 (temp1,0x40);
  temp1 = AES_128_ASSIST(temp1, temp2);
  Key_Schedule[7] = temp1;
  temp2 = _mm_aeskeygenassist_si128 (temp1,0x80);
  temp1 = AES_128_ASSIST(temp1, temp2);
  Key_Schedule[8] = temp1;
  temp2 = _mm_aeskeygenassist_si128 (temp1,0x1b);
  temp1 = AES_128_ASSIST(temp1, temp2);
  Key_Schedule[9] = temp1;
  temp2 = _mm_aeskeygenassist_si128 (temp1,0x36);
  temp1 = AES_128_ASSIST(temp1, temp2);
  Key_Schedule[10] = temp1;
} 

__m128i AES(const __m128i *Ki, __m128i x) {
  x ^= Ki[0];
  x = _mm_aesenc_si128(x, Ki[1]);
  x = _mm_aesenc_si128(x, Ki[2]);
  x = _mm_aesenc_si128(x, Ki[3]);
  x = _mm_aesenc_si128(x, Ki[4]);
  x = _mm_aesenc_si128(x, Ki[5]);
  x = _mm_aesenc_si128(x, Ki[6]);
  x = _mm_aesenc_si128(x, Ki[7]);
  x = _mm_aesenc_si128(x, Ki[8]);
  x = _mm_aesenc_si128(x, Ki[9]);
  x = _mm_aesenclast_si128(x, Ki[10]);
  return x;
}

__m128i AES_modified(const __m128i *Ki, __m128i x) {
  x ^= Ki[0];
  x = _mm_aesenc_si128(x, Ki[1]);
  x = _mm_aesenc_si128(x, Ki[2]);
  x = _mm_aesenc_si128(x, Ki[3]);
  x = _mm_aesenc_si128(x, Ki[4]);
  x = _mm_aesenc_si128(x, Ki[5]);
  x = _mm_aesenc_si128(x, Ki[6]);
  x = _mm_aesenc_si128(x, Ki[7]);
  x = _mm_aesenc_si128(x, Ki[8]);
  x = _mm_aesenc_si128(x, Ki[9]);
  x = _mm_aesenc_si128(x, _mm_set_epi64x(0,0));
  return x;
}

void petitmac_init(context *ctx, const uint8_t k[]) {
  const __m128i *K = (__m128i*)k;
  __m128i Ki[11];
  AES_KS(*K, Ki);

  ctx->init.S[0] = AES(Ki, _mm_set_epi64x(0,0));
  ctx->init.S[1] = STATE_0;
  ctx->init.S[2] = STATE_0;
  ctx->init.S[3] = STATE_0;
  ctx->init.S[4] = STATE_0;
  ctx->init.S[5] = STATE_0;

  for (unsigned i=1; i<16; i++)
    ctx->subkeys[i-1] = AES(Ki, _mm_set_epi64x(0,i));

  AES_KS(AES(Ki, _mm_set_epi64x(0,16)), ctx->keys[0]);
  AES_KS(AES(Ki, _mm_set_epi64x(0,17)), ctx->keys[1]);
}


#define ROUND(S,R0,R1,R2,R3,R4,M0) do {					\
    S = _mm_aesenc_si128(S,M0 ^ R4);			\
    __m128i t0 = R0; \
    __m128i t2 = R2; \
    R0 = M0 ^ R3; \
    R3 = R1 ; \
    R1 = R4 ^ R0; \
    R2 = R4 ^ t0; \
    R4 = t2; \
    S = _mm_aesenc_si128(S, R0);					\
  } while (0);

state petitmac_AU(context *ctx, const uint8_t *m, size_t mlen) {
  /* state S = ctx->init; */
    // Padding
  size_t m_padded_len = mlen - (mlen % 16) + 16;

  uint8_t m_padding[16];
  memcpy(m_padding, m + (mlen / 16) * 16, mlen % 16);
  m_padding[mlen % 16] = 1;
  __m128i *M_padding = (__m128i*) m_padding;
  for (size_t i = 1 + (mlen % 16); i < 16; ++i){
    m_padding[i] = 0;
  }

  const __m128i *M = (__m128i*)m;
  __m128i *Mfin = (__m128i*)(m + m_padded_len - 16);

  state S = ctx->init;

  // Main rounds
  for (;M < Mfin; M+=1) {
    ROUND(S.S[0],S.S[1],S.S[2],S.S[3],S.S[4],S.S[5],M[0])
  }

  // Last round (padding)
  ROUND(S.S[0],S.S[1],S.S[2],S.S[3],S.S[4],S.S[5],M_padding[0])
  return S;
}

void petitmac_MAC(context *ctx, const uint8_t *nonce, const uint8_t *m, size_t mlen, uint8_t *tag) {
  state S = petitmac_AU(ctx, m, mlen);
  const __m128i *N = (const __m128i*)nonce;

  __m128i T = *N ^ AES(ctx->keys[0], *N);
  T ^= AES_modified(ctx->subkeys  , S.S[0]);
  T ^= AES_modified(ctx->subkeys+1, S.S[1]);
  T ^= AES_modified(ctx->subkeys+2, S.S[2]);
  T ^= AES_modified(ctx->subkeys+3, S.S[3]);
  T ^= AES_modified(ctx->subkeys+4, S.S[4]);
  T ^= AES_modified(ctx->subkeys+5, S.S[5]);

  *(__m128i*)tag = AES(ctx->keys[1], T);
}
