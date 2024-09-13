/* LeMac AES-NI implementation

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
 - WARNING! This unrolled implementation is only valid for long messages!
 */

#include <stdint.h>
#include <immintrin.h>
#include <string.h>
#include <stdio.h>


#define STATE_0 _mm_set_epi64x(0,0)

#define tabsize(T) (sizeof(T)/sizeof((T)[0]))

typedef struct {
  __m128i S[9];
} state;

typedef  struct {
  state init;
  __m128i keys[2][11];
  __m128i subkeys[18];
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

void lemac_init(context *ctx, const uint8_t k[]) {
  const __m128i *K = (__m128i*)k;
  __m128i Ki[11];
  AES_KS(*K, Ki);

  // Kinit 0 --> 8
  for (unsigned i=0; i<tabsize(ctx->init.S); i++)
    ctx->init.S[i] = AES(Ki, _mm_set_epi64x(0,i));

  // Kinit 9 --> 26
  for (unsigned i=0; i<tabsize(ctx->subkeys); i++)
    ctx->subkeys[i] = AES(Ki, _mm_set_epi64x(0,i+tabsize(ctx->init.S)));

  // k2 27
  AES_KS(AES(Ki, _mm_set_epi64x(0,tabsize(ctx->init.S)+tabsize(ctx->subkeys))), ctx->keys[0]);

  // k3 28
  AES_KS(AES(Ki, _mm_set_epi64x(0,tabsize(ctx->init.S)+tabsize(ctx->subkeys)+1)), ctx->keys[1]);
}


#define ROUND(S0, S1, S2, S3, S4, S5, S6, S7, S8, M, MM) do {	\
    S8^= S0 ^ M[2];						\
    S0 = _mm_aesenc_si128(S0,M[3]);				\
    S1 = _mm_aesenc_si128(S1,M[3]);				\
    S2 = _mm_aesenc_si128(S2,MM);				\
    S3 = _mm_aesenc_si128(S3,M[0]);				\
    S4 = _mm_aesenc_si128(S4,M[0]);				\
    S5 = _mm_aesenc_si128(S5,M[1]);				\
    S6 = _mm_aesenc_si128(S6,M[1]);				\
    S7 = _mm_aesenc_si128(S7,M[3]);				\
  } while (0);

state lemac_AU(context *ctx, const uint8_t *m, size_t mlen) {
  /* state S = ctx->init; */
  // Padding
  size_t m_padded_len = mlen - (mlen % 64) + 64;
  uint8_t m_padding[64];
  memcpy(m_padding, m + (mlen / 64) * 64, mlen % 64);
  m_padding[mlen % 64] = 1;
  __m128i *M_padding = (__m128i*) m_padding;
  for (size_t i = 1 + (mlen % 64); i < 64; ++i){
    m_padding[i] = 0;
  }

  const __m128i *M = (__m128i*)m;
  __m128i *Mfin = (__m128i*)(m + m_padded_len - 64);

  __m128i S0 = ctx->init.S[0];
  __m128i S1 = ctx->init.S[1];
  __m128i S2 = ctx->init.S[2];
  __m128i S3 = ctx->init.S[3];
  __m128i S4 = ctx->init.S[4];
  __m128i S5 = ctx->init.S[5];
  __m128i S6 = ctx->init.S[6];
  __m128i S7 = ctx->init.S[7];
  __m128i S8 = ctx->init.S[8];

  if (mlen < 192) {
    fprintf (stderr, "Error: this implementation does not support short messages!\n");
    exit(-1);
  }
  
  // Unroll first three rounds because the initial message is empty
  ROUND(S0, S1, S2, S3, S4, S5, S6, S7, S8, M, STATE_0);
  M += 4;
  ROUND(S8, S0, S1, S2, S3, S4, S5, S6, S7, M, M[-3]);
  M += 4;
  ROUND(S7, S8, S0, S1, S2, S3, S4, S5, S6, M, M[-7]^M[-6]^M[-3]);
  M += 4;

  // Unroll blocks of 9 rounds
  for (;M+4*8 < Mfin;) {
    ROUND(S6, S7, S8, S0, S1, S2, S3, S4, S5, M, M[-10]^M[-7]^M[-6]^M[-3]);
    M+=4;
    ROUND(S5, S6, S7, S8, S0, S1, S2, S3, S4, M, M[-10]^M[-7]^M[-6]^M[-3]);
    M+=4;
    ROUND(S4, S5, S6, S7, S8, S0, S1, S2, S3, M, M[-10]^M[-7]^M[-6]^M[-3]);
    M+=4;
    ROUND(S3, S4, S5, S6, S7, S8, S0, S1, S2, M, M[-10]^M[-7]^M[-6]^M[-3]);
    M+=4;
    ROUND(S2, S3, S4, S5, S6, S7, S8, S0, S1, M, M[-10]^M[-7]^M[-6]^M[-3]);
    M+=4;
    ROUND(S1, S2, S3, S4, S5, S6, S7, S8, S0, M, M[-10]^M[-7]^M[-6]^M[-3]);
    M+=4;
    ROUND(S0, S1, S2, S3, S4, S5, S6, S7, S8, M, M[-10]^M[-7]^M[-6]^M[-3]);
    M+=4;
    ROUND(S8, S0, S1, S2, S3, S4, S5, S6, S7, M, M[-10]^M[-7]^M[-6]^M[-3]);
    M+=4;
    ROUND(S7, S8, S0, S1, S2, S3, S4, S5, S6, M, M[-10]^M[-7]^M[-6]^M[-3]);
    M+=4;
  }

  state S = {.S = {S6, S7, S8, S0, S1, S2, S3, S4, S5}};

  // Final rounds in-place
  for (; M<Mfin; M+=4) {
    state T;
    T.S[0] = S.S[0] ^ S.S[8] ^ M[2];
    T.S[1] = _mm_aesenc_si128(S.S[0],M[3]);
    T.S[2] = _mm_aesenc_si128(S.S[1],M[3]);
    T.S[3] = _mm_aesenc_si128(S.S[2],M[-10]^M[-7]^M[-6]^M[-3]);
    T.S[4] = _mm_aesenc_si128(S.S[3],M[0]);
    T.S[5] = _mm_aesenc_si128(S.S[4],M[0]);
    T.S[6] = _mm_aesenc_si128(S.S[5],M[1]);
    T.S[7] = _mm_aesenc_si128(S.S[6],M[1]);
    T.S[8] = _mm_aesenc_si128(S.S[7],M[3]);

    S = T;
  }

  // Last round (padding)
  {
    state T;
    T.S[0] = S.S[0] ^ S.S[8] ^ M_padding[2];
    T.S[1] = _mm_aesenc_si128(S.S[0],M_padding[3]);
    T.S[2] = _mm_aesenc_si128(S.S[1],M_padding[3]);
    T.S[3] = _mm_aesenc_si128(S.S[2],M[-10]^M[-7]^M[-6]^M[-3]);
    T.S[4] = _mm_aesenc_si128(S.S[3],M_padding[0]);
    T.S[5] = _mm_aesenc_si128(S.S[4],M_padding[0]);
    T.S[6] = _mm_aesenc_si128(S.S[5],M_padding[1]);
    T.S[7] = _mm_aesenc_si128(S.S[6],M_padding[1]);
    T.S[8] = _mm_aesenc_si128(S.S[7],M_padding[3]);

    S = T;
  }
  
  // Three final rounds to absorb message state
  {
    state T;
    T.S[0] = S.S[0] ^ S.S[8];
    T.S[1] = _mm_aesenc_si128(S.S[0],STATE_0);
    T.S[2] = _mm_aesenc_si128(S.S[1],STATE_0);
    T.S[3] = _mm_aesenc_si128(S.S[2],M[-6]^M[-3]^M[-2]^M_padding[1]);
    T.S[4] = _mm_aesenc_si128(S.S[3],STATE_0);
    T.S[5] = _mm_aesenc_si128(S.S[4],STATE_0);
    T.S[6] = _mm_aesenc_si128(S.S[5],STATE_0);
    T.S[7] = _mm_aesenc_si128(S.S[6],STATE_0);
    T.S[8] = _mm_aesenc_si128(S.S[7],STATE_0);

    S = T;
  }
  {
    state T;
    T.S[0] = S.S[0] ^ S.S[8];
    T.S[1] = _mm_aesenc_si128(S.S[0],STATE_0);
    T.S[2] = _mm_aesenc_si128(S.S[1],STATE_0);
    T.S[3] = _mm_aesenc_si128(S.S[2],M[-2]^M_padding[1]^M_padding[2]);
    T.S[4] = _mm_aesenc_si128(S.S[3],STATE_0);
    T.S[5] = _mm_aesenc_si128(S.S[4],STATE_0);
    T.S[6] = _mm_aesenc_si128(S.S[5],STATE_0);
    T.S[7] = _mm_aesenc_si128(S.S[6],STATE_0);
    T.S[8] = _mm_aesenc_si128(S.S[7],STATE_0);

    S = T;
  }
  {
    state T;
    T.S[0] = S.S[0] ^ S.S[8];
    T.S[1] = _mm_aesenc_si128(S.S[0],STATE_0);
    T.S[2] = _mm_aesenc_si128(S.S[1],STATE_0);
    T.S[3] = _mm_aesenc_si128(S.S[2],M_padding[2]);
    T.S[4] = _mm_aesenc_si128(S.S[3],STATE_0);
    T.S[5] = _mm_aesenc_si128(S.S[4],STATE_0);
    T.S[6] = _mm_aesenc_si128(S.S[5],STATE_0);
    T.S[7] = _mm_aesenc_si128(S.S[6],STATE_0);
    T.S[8] = _mm_aesenc_si128(S.S[7],STATE_0);

    S = T;
  }

  return S;
}

void lemac_MAC(context *ctx, const uint8_t *nonce, const uint8_t *m, size_t mlen, uint8_t *tag) {
  state S = lemac_AU(ctx, m, mlen);
  const __m128i *N = (const __m128i*)nonce;

  __m128i T = *N ^ AES(ctx->keys[0], *N);
  T ^= AES_modified(ctx->subkeys  , S.S[0]);
  T ^= AES_modified(ctx->subkeys+1, S.S[1]);
  T ^= AES_modified(ctx->subkeys+2, S.S[2]);
  T ^= AES_modified(ctx->subkeys+3, S.S[3]);
  T ^= AES_modified(ctx->subkeys+4, S.S[4]);
  T ^= AES_modified(ctx->subkeys+5, S.S[5]);
  T ^= AES_modified(ctx->subkeys+6, S.S[6]);
  T ^= AES_modified(ctx->subkeys+7, S.S[7]);
  T ^= AES_modified(ctx->subkeys+8, S.S[8]);

  *(__m128i*)tag = AES(ctx->keys[1], T);
}
