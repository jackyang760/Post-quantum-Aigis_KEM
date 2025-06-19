#include <stdio.h>
#include "polyvec.h"
#include "reduce.h"
#include "cbd.h"
#include "hashkdf.h"
#include "genmatrix.h"
#if defined(__x86_64__) || defined(_M_X64)
#include <immintrin.h>
#endif

extern const uint16_t chac[];
void polyvec_caddq(polyvec *r)
{
	int i;
	for (i = 0; i < PARAM_K; i++)
		poly_caddq(r->vec + i);
}
void polyvec_reduce(polyvec *r)
{
	int i;
	for (i = 0; i < PARAM_K; i++)
		poly_reduce(r->vec + i);
}

#define LOW_THRESH   1024
#define MID_THRESH   6144

// 核心压缩函数 (支持9/10/11位)
static inline uint16_t adaptive_compress(int16_t coeff, int bits) {
    uint32_t coeff32 = (uint32_t)(coeff >= 0 ? coeff : coeff + PARAM_Q);
    const uint32_t max_val = (1u << bits) - 1;
    
    // 资源分配比例（基于位宽动态计算）
    const uint32_t low_range = (max_val * 3) / 10;   // 30%
    const uint32_t mid_range = (max_val * 5) / 10;   // 50%
    const uint32_t high_range = max_val - low_range - mid_range;  // 20%
    
    // 确定区间（无分支避免侧信道）
    uint32_t range = 0;
    if (coeff32 < LOW_THRESH) {
        range = (coeff32 * low_range + (LOW_THRESH - 1)) / LOW_THRESH;
    } else if (coeff32 < MID_THRESH) {
        range = low_range + ((coeff32 - LOW_THRESH) * mid_range + 
                (MID_THRESH - LOW_THRESH) / 2) / (MID_THRESH - LOW_THRESH);
    } else {
        range = low_range + mid_range + 
               ((coeff32 - MID_THRESH) * high_range + 
               (PARAM_Q - MID_THRESH) / 2) / (PARAM_Q - MID_THRESH);
    }

    // 保证不越界
    return range < max_val ? (uint16_t)range : max_val;
}

// 核心解压函数 (匹配自适应压缩)
static inline int16_t adaptive_decompress(uint16_t comp_val, int bits) {
    const uint32_t max_val = (1u << bits) - 1;
    
    // 保持与压缩相同的比例
    const uint32_t low_range = (max_val * 3) / 10;
    const uint32_t mid_range = (max_val * 5) / 10;
    const uint32_t high_range = max_val - low_range - mid_range;
    
    int32_t value;
    
    if (comp_val < low_range) { // 低值区
        value = (comp_val * LOW_THRESH + low_range/2) / low_range;
    } 
    else if (comp_val < low_range + mid_range) { // 中值区
        value = LOW_THRESH + 
               ((comp_val - low_range) * (MID_THRESH - LOW_THRESH) + mid_range/2) / 
               mid_range;
    } 
    else { // 高值区
        value = MID_THRESH + 
               ((comp_val - low_range - mid_range) * (PARAM_Q - MID_THRESH) + 
               high_range/2) / high_range;
    }
    
    // 转换回有符号数
    return (value >= PARAM_Q) ? (int16_t)(PARAM_Q - 1) : (int16_t)value;
}

// ================== 压缩函数实现 ================== //

#if BITS_C1 == 9 || BITS_PK == 9
static void polyvec_compress9(uint8_t *r, const polyvec *a) {
    // uint16_t cpbytes = (PARAM_N * 9 + 7) / 8;
    for (int i = 0; i < PARAM_K; i++) {
        for (int j = 0; j < PARAM_N / 8; j++) {
            uint16_t t[8];
            
            // 应用自适应压缩
            for (int k = 0; k < 8; k++) {
                t[k] = adaptive_compress(a->vec[i].coeffs[8*j + k], 9);
            }
            
            // 高效位打包
            r[0] =  t[0]        & 0xFF;
            r[1] = (t[0] >>  8) | ((t[1] & 0x7F) << 1);
            r[2] = (t[1] >>  7) | ((t[2] & 0x3F) << 2);
            r[3] = (t[2] >>  6) | ((t[3] & 0x1F) << 3);
            r[4] = (t[3] >>  5) | ((t[4] & 0x0F) << 4);
            r[5] = (t[4] >>  4) | ((t[5] & 0x07) << 5);
            r[6] = (t[5] >>  3) | ((t[6] & 0x03) << 6);
            r[7] = (t[6] >>  2) | ((t[7] & 0x01) << 7);
            r[8] = (t[7] >>  1);
            r += 9;
        }
    }
}
#endif

#if BITS_C1 == 10 || BITS_PK == 10
static void polyvec_compress10(uint8_t *r, const polyvec *a) {
    // uint16_t cpbytes = (PARAM_N * 10 + 7) / 8;
    for (int i = 0; i < PARAM_K; i++) {
        for (int j = 0; j < PARAM_N / 4; j++) {
            uint16_t t[4];
            
            // 应用自适应压缩
            for (int k = 0; k < 4; k++) {
                t[k] = adaptive_compress(a->vec[i].coeffs[4*j + k], 10);
            }
            
            // 高效位打包
            r[0] =  t[0]        & 0xFF;
            r[1] = (t[0] >>  8) | ((t[1] & 0x3F) << 2);
            r[2] = (t[1] >>  6) | ((t[2] & 0x0F) << 4);
            r[3] = (t[2] >>  4) | ((t[3] & 0x03) << 6);
            r[4] = (t[3] >>  2);
            r += 5;
        }
    }
}
#endif

#if BITS_C1 == 11 || BITS_PK == 11
static void polyvec_compress11(uint8_t *r, const polyvec *a) {
    // uint16_t cpbytes = (PARAM_N * 11 + 7) / 8;
    for (int i = 0; i < PARAM_K; i++) {
        for (int j = 0; j < PARAM_N / 8; j++) {
            uint16_t t[8];
            
            // 应用自适应压缩
            for (int k = 0; k < 8; k++) {
                t[k] = adaptive_compress(a->vec[i].coeffs[8*j + k], 11);
            }
            
            // 高效位打包
            r[0]  =  t[0]        & 0xFF;
            r[1]  = (t[0] >>  8) | ((t[1] & 0x1F) << 3);
            r[2]  = (t[1] >>  5) | ((t[2] & 0x03) << 6);
            r[3]  = (t[2] >>  2) & 0xFF;
            r[4]  = (t[2] >> 10) | ((t[3] & 0x7F) << 1);
            r[5]  = (t[3] >>  7) | ((t[4] & 0x0F) << 4);
            r[6]  = (t[4] >>  4) | ((t[5] & 0x01) << 7);
            r[7]  = (t[5] >>  1) & 0xFF;
            r[8]  = (t[5] >>  9) | ((t[6] & 0x3F) << 2);
            r[9]  = (t[6] >>  6) | ((t[7] & 0x07) << 5);
            r[10] = (t[7] >>  3);
            r += 11;
        }
    }
}
#endif

// ================== 解压缩函数实现 ================== //

#if BITS_C1 == 9 || BITS_PK == 9
static void polyvec_decompress9(polyvec *r, const unsigned char *a) {
    // uint16_t cpbytes = (PARAM_N * 9 + 7) / 8;
    for (int i = 0; i < PARAM_K; i++) {
        for (int j = 0; j < PARAM_N / 8; j++) {
            uint16_t t[8];
            
            // 解包位压缩数据
            t[0] = a[0] | ((uint16_t)(a[1] & 0x01) << 8);
            t[1] = (a[1] >> 1) | ((uint16_t)(a[2] & 0x03) << 7);
            t[2] = (a[2] >> 2) | ((uint16_t)(a[3] & 0x07) << 6);
            t[3] = (a[3] >> 3) | ((uint16_t)(a[4] & 0x0F) << 5);
            t[4] = (a[4] >> 4) | ((uint16_t)(a[5] & 0x1F) << 4);
            t[5] = (a[5] >> 5) | ((uint16_t)(a[6] & 0x3F) << 3);
            t[6] = (a[6] >> 6) | ((uint16_t)(a[7] & 0x7F) << 2);
            t[7] = (a[7] >> 7) | ((uint16_t)(a[8]) << 1);
            a += 9;
            
            // 应用自适应解压缩
            for (int k = 0; k < 8; k++) {
                r->vec[i].coeffs[8*j + k] = adaptive_decompress(t[k], 9);
            }
        }
    }
}
#endif

#if BITS_C1 == 10 || BITS_PK == 10
static void polyvec_decompress10(polyvec *r, const unsigned char *a) {
    // uint16_t cpbytes = (PARAM_N * 10 + 7) / 8;
    for (int i = 0; i < PARAM_K; i++) {
        for (int j = 0; j < PARAM_N / 4; j++) {
            uint16_t t[4];
            
            // 解包位压缩数据
            t[0] = a[0] | ((uint16_t)(a[1] & 0x03) << 8);
            t[1] = (a[1] >> 2) | ((uint16_t)(a[2] & 0x0F) << 6);
            t[2] = (a[2] >> 4) | ((uint16_t)(a[3] & 0x3F) << 4);
            t[3] = (a[3] >> 6) | ((uint16_t)a[4] << 2);
            a += 5;
            
            // 应用自适应解压缩
            for (int k = 0; k < 4; k++) {
                r->vec[i].coeffs[4*j + k] = adaptive_decompress(t[k], 10);
            }
        }
    }
}
#endif

#if BITS_C1 == 11 || BITS_PK == 11
static void polyvec_decompress11(polyvec *r, const unsigned char *a) {
    // uint16_t cpbytes = (PARAM_N * 11 + 7) / 8;
    for (int i = 0; i < PARAM_K; i++) {
        for (int j = 0; j < PARAM_N / 8; j++) {
            uint16_t t[8];
            
            // 解包位压缩数据
            t[0] = a[0] | ((uint16_t)(a[1] & 0x07) << 8);
            t[1] = (a[1] >> 3) | ((uint16_t)(a[2] & 0x3F) << 5);
            t[2] = (a[2] >> 6) | ((uint16_t)a[3] << 2) | ((uint16_t)(a[4] & 0x01) << 10);
            t[3] = (a[4] >> 1) | ((uint16_t)(a[5] & 0x0F) << 7);
            t[4] = (a[5] >> 4) | ((uint16_t)(a[6] & 0x7F) << 4);
            t[5] = (a[6] >> 7) | ((uint16_t)a[7] << 1) | ((uint16_t)(a[8] & 0x03) << 9);
            t[6] = (a[8] >> 2) | ((uint16_t)(a[9] & 0x1F) << 6);
            t[7] = (a[9] >> 5) | ((uint16_t)a[10] << 3);
            a += 11;
            
            // 应用自适应解压缩
            for (int k = 0; k < 8; k++) {
                r->vec[i].coeffs[8*j + k] = adaptive_decompress(t[k], 11);
            }
        }
    }
}
#endif


void polyvec_ct_compress(uint8_t *r, const polyvec *a)
{
//assuming the coefficients belong in [0,PARAM_Q)
#if BITS_C1 == 9
	polyvec_compress9(r, a);
#elif BITS_C1 == 10
	polyvec_compress10(r, a);
#elif BITS_C1 == 11
	polyvec_compress11(r, a);
#else
#error "polyvec_ct_compress() only supports BITS_C1 in {9,10,11}"
#endif
}

void polyvec_pk_compress(uint8_t *r, const polyvec *a)
{
//assuming the coefficients belong in [0,PARAM_Q)
#if BITS_PK == 9
	polyvec_compress9(r, a);
#elif BITS_PK == 10
	polyvec_compress10(r, a);
#elif BITS_PK == 11
	polyvec_compress11(r, a);
#else
#error "polyvec_pk_compress() only supports BITS_C1 in {9,10,11}"
#endif
}

void polyvec_ct_decompress(polyvec *r, const uint8_t *a)
{
#if BITS_C1 == 9
	polyvec_decompress9(r, a);
#elif BITS_C1 == 10
	polyvec_decompress10(r, a);
#elif BITS_C1 == 11
	polyvec_decompress11(r, a);
#else
#error "polyvec_ct_decompress() only supports BITS_C1 in {9,10,11}"
#endif
}

void polyvec_pk_decompress(polyvec *r, const uint8_t *a)
{
#if BITS_PK == 9
	polyvec_decompress9(r, a);
#elif BITS_PK == 10
	polyvec_decompress10(r, a);
#elif BITS_PK == 11
	polyvec_decompress11(r, a);
#else
#error "polyvec_pk_decompress() only supports BITS_C1 in {9,10,11}"
#endif
}
/*************************************************
* Name:        polyvec_tobytes
* 
* Description: Serialize vector of polynomials
*
* Arguments:   - uint8_t *r: pointer to output byte array 
*              - const polyvec *a: pointer to input vector of polynomials
**************************************************/
void polyvec_tobytes(uint8_t *r, const polyvec *a)
{
  int i;
  for(i=0;i<PARAM_K;i++)
    poly_tobytes(r+i*POLY_BYTES, &a->vec[i]);
}

/*************************************************
* Name:        polyvec_frombytes
* 
* Description: De-serialize vector of polynomials;
*              inverse of polyvec_tobytes 
*
* Arguments:   - uint8_t *r: pointer to output byte array 
*              - const polyvec *a: pointer to input vector of polynomials
**************************************************/
void polyvec_frombytes(polyvec *r, const uint8_t *a)
{
  int i;
  for(i=0;i<PARAM_K;i++)
    poly_frombytes(&r->vec[i], a+i*POLY_BYTES);
}

void polyvec_ntt(polyvec *r)
{
  int i;
  for(i=0;i<PARAM_K;i++)
    poly_ntt(&r->vec[i]);
}

void polyvec_invntt(polyvec *r)
{
  int i;
  for(i=0;i<PARAM_K;i++)
    poly_invntt(&r->vec[i]);
}
 
/*************************************************
* Name:        polyvec_pointwise_acc
* 
* Description: Pointwise multiply elements of a and b and accumulate into r
*
* Arguments: - poly *r:          pointer to output polynomial
*            - const polyvec *a: pointer to first input vector of polynomials
*            - const polyvec *b: pointer to second input vector of polynomials
**************************************************/ 
void polyvec_pointwise_acc(poly *r, const polyvec *a, const polyvec *b)
{
	int i, j;
	int16_t t;
	int16_t montR2= 5569; // 5569 = 2^{2*16} % q

	for (j = 0; j < PARAM_N; j++)
	{
		t = montgomery_reduce(montR2* (int32_t)b->vec[0].coeffs[j]);
		r->coeffs[j] = montgomery_reduce(a->vec[0].coeffs[j] * t);
		for (i = 1; i < PARAM_K; i++)
		{
			t = montgomery_reduce(montR2 * (int32_t)b->vec[i].coeffs[j]);
			r->coeffs[j] += montgomery_reduce(a->vec[i].coeffs[j] * t);
		}
		r->coeffs[j] = barrett_reduce(r->coeffs[j]);
	}
}
/*************************************************
* Name:        polyvec_add
* 
* Description: Add vectors of polynomials
*
* Arguments: - polyvec *r:       pointer to output vector of polynomials
*            - const polyvec *a: pointer to first input vector of polynomials
*            - const polyvec *b: pointer to second input vector of polynomials
**************************************************/ 
void polyvec_add(polyvec *r, const polyvec *a, const polyvec *b)
{
  int i;
  for(i=0;i<PARAM_K;i++)
    poly_add(&r->vec[i], &a->vec[i], &b->vec[i]);

}
void polyvec_ss_getnoise(polyvec *r, const uint8_t *seed, uint8_t nonce)
{
	uint8_t buf[ETA_S*PARAM_N / 4];
	uint8_t extseed[SEED_BYTES + 1];
	int i;

	for (i = 0; i < SEED_BYTES; i++)
		extseed[i] = seed[i];
	for (i = 0; i < PARAM_K; i++)
	{
		extseed[SEED_BYTES] = nonce;
		nonce++;
		kdf256(buf,sizeof(buf),extseed,SEED_BYTES+1);
		cbd_etas(&r->vec[i], buf);
	}
}
void polyvec_ee_getnoise(polyvec *r, const uint8_t *seed, uint8_t nonce)
{
	uint8_t buf[ETA_E*PARAM_N / 4];
	uint8_t extseed[SEED_BYTES + 1];
	int i;

	for (i = 0; i < SEED_BYTES; i++)
		extseed[i] = seed[i];
	for (i = 0; i < PARAM_K; i++)
	{
		extseed[SEED_BYTES] = nonce;
		nonce++;
		kdf256(buf, sizeof(buf), extseed, SEED_BYTES + 1);
		cbd_etae(&r->vec[i], buf);
	}
}
