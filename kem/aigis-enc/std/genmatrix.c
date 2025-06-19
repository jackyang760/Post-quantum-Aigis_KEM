#include <string.h>
#include "genmatrix.h"
#include "polyvec.h"
#include "hashkdf.h"

#ifdef USE_SHAKE
static int rej_uniform(int16_t *r, int *cur, int n, const uint8_t *buf, int buflen)
{
	int ctr, pos;
	int16_t val[8];
	ctr = *cur;
	pos = 0;

	while (ctr + 8 <= n && pos + QBITS <= buflen)
	{
#if PARAM_Q == 7681
		val[0] = (buf[pos] | ((uint16_t)buf[pos + 1] << 8)) & 0x1fff;
		val[1] = ((buf[pos+1]>>5) | ((uint16_t)buf[pos + 2] << 3) | ((uint16_t)buf[pos + 3] << 11)) & 0x1fff;
		val[2] = ((buf[pos + 3] >> 2) | ((uint16_t)buf[pos + 4] << 6)) & 0x1fff;
		val[3] = ((buf[pos + 4] >> 7) | ((uint16_t)buf[pos + 5] << 1) | ((uint16_t)buf[pos + 6] << 9)) & 0x1fff;
		val[4] = ((buf[pos + 6] >> 4) | ((uint16_t)buf[pos + 7] << 4) | ((uint16_t)buf[pos + 8] << 12)) & 0x1fff;
		val[5] = ((buf[pos + 8] >> 1) | ((uint16_t)buf[pos + 9] << 7)) & 0x1fff;
		val[6] = ((buf[pos + 9] >> 6) | ((uint16_t)buf[pos + 10] << 2) | ((uint16_t)buf[pos + 11] << 10)) & 0x1fff;
		val[7] = ((buf[pos + 11] >> 3)| ((uint16_t)buf[pos + 12] << 5));
#elif PARAM_Q == 12289
		val[0] = (buf[pos] | ((uint16_t)buf[pos + 1] << 8)) & 0x3fff;
		val[1] = ((buf[pos + 1] >> 6) | ((uint16_t)buf[pos + 2] << 2) | ((uint16_t)buf[pos + 3] << 10)) & 0x3fff;
		val[2] = ((buf[pos + 3] >> 4) | ((uint16_t)buf[pos + 4] << 4) | ((uint16_t)buf[pos + 5] << 12)) & 0x3fff;
		val[3] = ((buf[pos + 5] >> 2) | ((uint16_t)buf[pos + 6] << 6));
		val[4] = (buf[pos + 7] | ((uint16_t)buf[pos + 8] << 8)) & 0x3fff;
		val[5] = ((buf[pos + 8] >> 6) | ((uint16_t)buf[pos + 9] << 2) | ((uint16_t)buf[pos + 10] << 10)) & 0x3fff;
		val[6] = ((buf[pos + 10] >> 4) | ((uint16_t)buf[pos + 11] << 4) | ((uint16_t)buf[pos + 12] << 12)) & 0x3fff;
		val[7] = ((buf[pos + 12] >> 2) | ((uint16_t)buf[pos + 13] << 6));
#endif

		if (val[0] < PARAM_Q)
			r[ctr++] = val[0];
		if (val[1] < PARAM_Q)
			r[ctr++] = val[1];
		if (val[2] < PARAM_Q)
			r[ctr++] = val[2];
		if (val[3] < PARAM_Q)
			r[ctr++] = val[3];
		if (val[4] < PARAM_Q)
			r[ctr++] = val[4];
		if (val[5] < PARAM_Q)
			r[ctr++] = val[5];
		if (val[6] < PARAM_Q)
			r[ctr++] = val[6];
		if (val[7] < PARAM_Q)
			r[ctr++] = val[7];
		pos += QBITS;
	}
	if (ctr + 8 <= n)//the random bits are enough, request more bits
	{
		*cur = ctr;
		return pos;
	}
	while (ctr < n && pos + 2 <= buflen)
	{
#if PARAM_Q == 7681
		val[0] = (buf[pos] | ((uint16_t)buf[pos + 1] << 8)) & 0x1fff;
		if (val[0] < PARAM_Q)
			r[ctr++] = val[0];
		if (ctr >= n || pos + 3 >= buflen)
		{
			pos += 2;
			break;
		}

		val[1] = ((buf[pos + 1] >> 5) | ((uint16_t)buf[pos + 2] << 3) | ((uint16_t)buf[pos + 3] << 11)) & 0x1fff;
		if (val[1] < PARAM_Q)
			r[ctr++] = val[1];
		if (ctr >= n || pos + 4 >= buflen)
		{
			pos += 4;
			break;
		}
		val[2] = ((buf[pos + 3] >> 2) | ((uint16_t)buf[pos + 4] << 6)) & 0x1fff;
		if (val[2] < PARAM_Q)
			r[ctr++] = val[2];

		if (ctr >= n || pos + 6 >= buflen)
		{
			pos += 5;
			break;
		}
		val[3] = ((buf[pos + 4] >> 7) | ((uint16_t)buf[pos + 5] << 1) | ((uint16_t)buf[pos + 6] << 9)) & 0x1fff;
		if (val[3] < PARAM_Q)
			r[ctr++] = val[3];

		if (ctr >= n || pos + 8 >= buflen)
		{
			pos += 7;
			break;
		}
		val[4] = ((buf[pos + 6] >> 4) | ((uint16_t)buf[pos + 7] << 4) | ((uint16_t)buf[pos + 8] << 12)) & 0x1fff;
		if (val[4] < PARAM_Q)
			r[ctr++] = val[4];

		if (ctr >= n || pos + 9 >= buflen)
		{
			pos += 9;
			break;
		}
		val[5] = ((buf[pos + 8] >> 1) | ((uint16_t)buf[pos + 9] << 7)) & 0x1fff;
		if (val[5] < PARAM_Q)
			r[ctr++] = val[5];

		if (ctr >= n || pos + 11 >= buflen)
		{
			pos += 10;
			break;
		}
		val[6] = ((buf[pos + 9] >> 6) | ((uint16_t)buf[pos + 10] << 2) | ((uint16_t)buf[pos + 11] << 10)) & 0x1fff;
		if (val[6] < PARAM_Q)
			r[ctr++] = val[6];

		if (ctr >= n || pos + 12 >= buflen)
		{
			pos += 12;
			break;
		}
		val[7] = ((buf[pos + 11] >> 3) | ((uint16_t)buf[pos + 12] << 5));
		if (val[7] < PARAM_Q)
			r[ctr++] = val[7];
		pos += 13;
#elif PARAM_Q == 12289
		val[0] = (buf[pos] | ((uint16_t)buf[pos + 1] << 8)) & 0x3fff;
		if (val[0] < PARAM_Q)
			r[ctr++] = val[0];
		if (ctr >= n || pos + 3 >= buflen)
		{
			pos += 2;
			break;
		}
		val[1] = ((buf[pos + 1] >> 6) | ((uint16_t)buf[pos + 2] << 2) | ((uint16_t)buf[pos + 3] << 10)) & 0x3fff;
		if (val[1] < PARAM_Q)
			r[ctr++] = val[1];
		if (ctr >= n || pos + 5 >= buflen)
		{
			pos += 4;
			break;
		}
		val[2] = ((buf[pos + 3] >> 4) | ((uint16_t)buf[pos + 4] << 4) | ((uint16_t)buf[pos + 5] << 12)) & 0x3fff;
		if (val[2] < PARAM_Q)
			r[ctr++] = val[2];
		if (ctr >= n || pos + 6 >= buflen)
		{
			pos += 6;
			break;
		}
		val[3] = ((buf[pos + 5] >> 2) | ((uint16_t)buf[pos + 6] << 6));
		if (val[3] < PARAM_Q)
			r[ctr++] = val[3];
		pos += 7;
#endif
	}
	*cur = ctr;
	return pos;
}
void poly_uniform_seed(poly *r, const uint8_t *seed, int seedbytes)
{
	int cur = 0, pos, step;
	uint8_t buf[REJ_UNIFORM_BYTES + KDF128RATE];
	int nblock = (REJ_UNIFORM_BYTES + KDF128RATE - 1) / KDF128RATE;

	int len;
	kdfstate state;
	kdf128_absorb(&state, seed, seedbytes);
	kdf128_squeezeblocks(buf, nblock, &state);
	len = nblock * KDF128RATE;
	pos = rej_uniform(r->coeffs, &cur, PARAM_N, buf, len);
	len -= pos;
	while (cur < PARAM_N)
	{
		pos -= KDF128RATE;
		len += KDF128RATE;
		kdf128_squeezeblocks(&buf[pos], 1, &state);
		step = rej_uniform(r->coeffs, &cur, PARAM_N, &buf[pos], len);
		pos += step;
		len -= step;
	}
}
void genmatrix(polyvec *a, const uint8_t *seed, int transposed)
{
	int i, j;
	uint8_t extseed[SEED_BYTES + 2];

	for (i = 0; i < SEED_BYTES; i++)
		extseed[i] = seed[i];

	for (i = 0; i < PARAM_K; i++)
		for (j = 0; j < PARAM_K; j++)
		{
			if (transposed)
			{
				extseed[SEED_BYTES] = j;
				extseed[SEED_BYTES + 1] = i;
			}
			else
			{
				extseed[SEED_BYTES] = i;
				extseed[SEED_BYTES + 1] = j;
			}
			poly_uniform_seed(&a[i].vec[j], extseed, SEED_BYTES + 2);
		}
}
#elif defined USE_SM3
static int rej_uniform(int16_t *r, int *cur, int n, const uint8_t *buf, int buflen)
{
	int ctr, pos;
	int16_t val[8];
	ctr = *cur;
	pos = 0;

	while (ctr + 8 <= n && pos + QBITS <= buflen)
	{
#if PARAM_Q == 7681
		val[0] = (buf[pos] | ((uint16_t)buf[pos + 1] << 8)) & 0x1fff;
		val[1] = ((buf[pos+1]>>5) | ((uint16_t)buf[pos + 2] << 3) | ((uint16_t)buf[pos + 3] << 11)) & 0x1fff;
		val[2] = ((buf[pos + 3] >> 2) | ((uint16_t)buf[pos + 4] << 6)) & 0x1fff;
		val[3] = ((buf[pos + 4] >> 7) | ((uint16_t)buf[pos + 5] << 1) | ((uint16_t)buf[pos + 6] << 9)) & 0x1fff;
		val[4] = ((buf[pos + 6] >> 4) | ((uint16_t)buf[pos + 7] << 4) | ((uint16_t)buf[pos + 8] << 12)) & 0x1fff;
		val[5] = ((buf[pos + 8] >> 1) | ((uint16_t)buf[pos + 9] << 7)) & 0x1fff;
		val[6] = ((buf[pos + 9] >> 6) | ((uint16_t)buf[pos + 10] << 2) | ((uint16_t)buf[pos + 11] << 10)) & 0x1fff;
		val[7] = ((buf[pos + 11] >> 3)| ((uint16_t)buf[pos + 12] << 5));
#elif PARAM_Q == 12289
		val[0] = (buf[pos] | ((uint16_t)buf[pos + 1] << 8)) & 0x3fff;
		val[1] = ((buf[pos + 1] >> 6) | ((uint16_t)buf[pos + 2] << 2) | ((uint16_t)buf[pos + 3] << 10)) & 0x3fff;
		val[2] = ((buf[pos + 3] >> 4) | ((uint16_t)buf[pos + 4] << 4) | ((uint16_t)buf[pos + 5] << 12)) & 0x3fff;
		val[3] = ((buf[pos + 5] >> 2) | ((uint16_t)buf[pos + 6] << 6));
		val[4] = (buf[pos + 7] | ((uint16_t)buf[pos + 8] << 8)) & 0x3fff;
		val[5] = ((buf[pos + 8] >> 6) | ((uint16_t)buf[pos + 9] << 2) | ((uint16_t)buf[pos + 10] << 10)) & 0x3fff;
		val[6] = ((buf[pos + 10] >> 4) | ((uint16_t)buf[pos + 11] << 4) | ((uint16_t)buf[pos + 12] << 12)) & 0x3fff;
		val[7] = ((buf[pos + 12] >> 2) | ((uint16_t)buf[pos + 13] << 6));
#endif

		if (val[0] < PARAM_Q)
			r[ctr++] = val[0];
		if (val[1] < PARAM_Q)
			r[ctr++] = val[1];
		if (val[2] < PARAM_Q)
			r[ctr++] = val[2];
		if (val[3] < PARAM_Q)
			r[ctr++] = val[3];
		if (val[4] < PARAM_Q)
			r[ctr++] = val[4];
		if (val[5] < PARAM_Q)
			r[ctr++] = val[5];
		if (val[6] < PARAM_Q)
			r[ctr++] = val[6];
		if (val[7] < PARAM_Q)
			r[ctr++] = val[7];
		pos += QBITS;
	}
	if (ctr + 8 <= n)//the random bits are enough, request more bits
	{
		*cur = ctr;
		return pos;
	}
	while (ctr < n && pos + 2 <= buflen)
	{
#if PARAM_Q == 7681
		val[0] = (buf[pos] | ((uint16_t)buf[pos + 1] << 8)) & 0x1fff;
		if (val[0] < PARAM_Q)
			r[ctr++] = val[0];
		if (ctr >= n || pos + 3 >= buflen)
		{
			pos += 2;
			break;
		}

		val[1] = ((buf[pos + 1] >> 5) | ((uint16_t)buf[pos + 2] << 3) | ((uint16_t)buf[pos + 3] << 11)) & 0x1fff;
		if (val[1] < PARAM_Q)
			r[ctr++] = val[1];
		if (ctr >= n || pos + 4 >= buflen)
		{
			pos += 4;
			break;
		}
		val[2] = ((buf[pos + 3] >> 2) | ((uint16_t)buf[pos + 4] << 6)) & 0x1fff;
		if (val[2] < PARAM_Q)
			r[ctr++] = val[2];

		if (ctr >= n || pos + 6 >= buflen)
		{
			pos += 5;
			break;
		}
		val[3] = ((buf[pos + 4] >> 7) | ((uint16_t)buf[pos + 5] << 1) | ((uint16_t)buf[pos + 6] << 9)) & 0x1fff;
		if (val[3] < PARAM_Q)
			r[ctr++] = val[3];

		if (ctr >= n || pos + 8 >= buflen)
		{
			pos += 7;
			break;
		}
		val[4] = ((buf[pos + 6] >> 4) | ((uint16_t)buf[pos + 7] << 4) | ((uint16_t)buf[pos + 8] << 12)) & 0x1fff;
		if (val[4] < PARAM_Q)
			r[ctr++] = val[4];

		if (ctr >= n || pos + 9 >= buflen)
		{
			pos += 9;
			break;
		}
		val[5] = ((buf[pos + 8] >> 1) | ((uint16_t)buf[pos + 9] << 7)) & 0x1fff;
		if (val[5] < PARAM_Q)
			r[ctr++] = val[5];

		if (ctr >= n || pos + 11 >= buflen)
		{
			pos += 10;
			break;
		}
		val[6] = ((buf[pos + 9] >> 6) | ((uint16_t)buf[pos + 10] << 2) | ((uint16_t)buf[pos + 11] << 10)) & 0x1fff;
		if (val[6] < PARAM_Q)
			r[ctr++] = val[6];

		if (ctr >= n || pos + 12 >= buflen)
		{
			pos += 12;
			break;
		}
		val[7] = ((buf[pos + 11] >> 3) | ((uint16_t)buf[pos + 12] << 5));
		if (val[7] < PARAM_Q)
			r[ctr++] = val[7];
		pos += 13;
#elif PARAM_Q == 12289
		val[0] = (buf[pos] | ((uint16_t)buf[pos + 1] << 8)) & 0x3fff;
		if (val[0] < PARAM_Q)
			r[ctr++] = val[0];
		if (ctr >= n || pos + 3 >= buflen)
		{
			pos += 2;
			break;
		}
		val[1] = ((buf[pos + 1] >> 6) | ((uint16_t)buf[pos + 2] << 2) | ((uint16_t)buf[pos + 3] << 10)) & 0x3fff;
		if (val[1] < PARAM_Q)
			r[ctr++] = val[1];
		if (ctr >= n || pos + 5 >= buflen)
		{
			pos += 4;
			break;
		}
		val[2] = ((buf[pos + 3] >> 4) | ((uint16_t)buf[pos + 4] << 4) | ((uint16_t)buf[pos + 5] << 12)) & 0x3fff;
		if (val[2] < PARAM_Q)
			r[ctr++] = val[2];
		if (ctr >= n || pos + 6 >= buflen)
		{
			pos += 6;
			break;
		}
		val[3] = ((buf[pos + 5] >> 2) | ((uint16_t)buf[pos + 6] << 6));
		if (val[3] < PARAM_Q)
			r[ctr++] = val[3];
		pos += 7;
#endif
	}
	*cur = ctr;
	return pos;
}
void poly_uniform_seed(poly *r, const uint8_t *seed, int seedbytes)
{
	int cur = 0, pos, step;
	uint8_t buf[REJ_UNIFORM_BYTES + KDF128RATE];
	int nblock = (REJ_UNIFORM_BYTES + KDF128RATE - 1) / KDF128RATE;

	int len;
	kdfstate state;
	kdf128_absorb(&state, seed, seedbytes);
	kdf128_squeezeblocks(buf, nblock, &state);
	len = nblock * KDF128RATE;
	pos = rej_uniform(r->coeffs, &cur, PARAM_N, buf, len);
	len -= pos;
	while (cur < PARAM_N)
	{
		pos -= KDF128RATE;
		len += KDF128RATE;
		kdf128_squeezeblocks(&buf[pos], 1, &state);
		step = rej_uniform(r->coeffs, &cur, PARAM_N, &buf[pos], len);
		pos += step;
		len -= step;
	}
}
void genmatrix(polyvec *a, const uint8_t *seed, int transposed)
{
	int i, j;
	uint8_t extseed[SEED_BYTES + 2];

	for (i = 0; i < SEED_BYTES; i++)
		extseed[i] = seed[i];

	for (i = 0; i < PARAM_K; i++)
		for (j = 0; j < PARAM_K; j++)
		{
			if (transposed)
			{
				extseed[SEED_BYTES] = j;
				extseed[SEED_BYTES + 1] = i;
			}
			else
			{
				extseed[SEED_BYTES] = i;
				extseed[SEED_BYTES + 1] = j;
			}
			poly_uniform_seed(&a[i].vec[j], extseed, SEED_BYTES + 2);
		}
}
#else
static unsigned int rej_uniform2(int16_t *r,
			unsigned int len,
			const uint8_t *buf,
			unsigned int buflen){
	unsigned int ctr = 0;
	unsigned int pos = 0;

#if PARAM_Q == 7681 // 模数 7681 (13位采样)
	const uint16_t bitmask = 0x1FFF; // 13位掩码

	// 批量处理：每次处理8个样本
	while (ctr + 8 <= len && pos + 13 <= buflen) {
		uint16_t val[8];

		// 从13字节中提取8个13位样本
		val[0] = (buf[pos] | ((uint16_t)buf[pos+1] << 8)) & bitmask;
		val[1] = ((buf[pos+1]>>5) | ((uint16_t)buf[pos+2]<<3) | ((uint16_t)buf[pos+3]<<11)) & bitmask;
		val[2] = ((buf[pos+3]>>2) | ((uint16_t)buf[pos+4]<<6)) & bitmask;
		val[3] = ((buf[pos+4]>>7) | ((uint16_t)buf[pos+5]<<1) | ((uint16_t)buf[pos+6]<<9)) & bitmask;
		val[4] = ((buf[pos+6]>>4) | ((uint16_t)buf[pos+7]<<4) | ((uint16_t)buf[pos+8]<<(12))) & bitmask;
		val[5] = ((buf[pos+8]>>1) | ((uint16_t)buf[pos+9]<<7)) & bitmask;
		val[6] = ((buf[pos+9]>>6) | ((uint16_t)buf[pos+10]<<2) | ((uint16_t)buf[pos+11]<<10)) & bitmask;
		val[7] = (buf[pos+11]>>3) | ((uint16_t)buf[pos+12]<<5);

		// 应用拒绝采样
		for (int i = 0; i < 8; i++) {
			if (val[i] < PARAM_Q ) {
			r[ctr++] = val[i];
			}
		}
		pos += 13;
	}

	// 单个样本处理
	while (ctr < len && pos + 2 <= buflen) {
		uint16_t val = (buf[pos] | ((uint16_t)buf[pos+1] << 8)) & bitmask;
		if (val < PARAM_Q ) {
			r[ctr++] = val;
		}
		pos += 2;
		if (ctr >= len) break;
	}

#elif PARAM_Q == 12289
	const uint16_t bitmask = 0x3FFF; // 14位掩码

	// 批量处理：每次处理8个样本
	while (ctr + 8 <= len && pos + 14 <= buflen) {
		uint16_t val[8];

		// 从14字节中提取8个14位样本
		val[0] = (buf[pos] | ((uint16_t)buf[pos+1] << 8)) & bitmask;
		val[1] = ((buf[pos+1]>>6) | ((uint16_t)buf[pos+2]<<2) | ((uint16_t)buf[pos+3]<<10)) & bitmask;
		val[2] = ((buf[pos+3]>>4) | ((uint16_t)buf[pos+4]<<4) | ((uint16_t)buf[pos+5]<<12)) & bitmask;
		val[3] = (buf[pos+5]>>2) | ((uint16_t)buf[pos+6]<<6);
		val[4] = (buf[pos+7] | ((uint16_t)buf[pos+8] << 8)) & bitmask;
		val[5] = ((buf[pos+8]>>6) | ((uint16_t)buf[pos+9]<<2) | ((uint16_t)buf[pos+10]<<10)) & bitmask;
		val[6] = ((buf[pos+10]>>4) | ((uint16_t)buf[pos+11]<<4) | ((uint16_t)buf[pos+12]<<12)) & bitmask;
		val[7] = (buf[pos+12]>>2) | ((uint16_t)buf[pos+13]<<6);

		// 应用拒绝采样
		for (int i = 0; i < 8; i++) {
			if (val[i] < PARAM_Q ) {
				r[ctr++] = val[i];
			}
		}
		pos += 14;
	}

	// 单个样本处理
	while (ctr < len && pos + 2 <= buflen) {
		uint16_t val = (buf[pos] | ((uint16_t)buf[pos+1] << 8)) & bitmask;
		if (val < PARAM_Q) {
			r[ctr++] = val;
		}
		pos += 2;
		if (ctr >= len) break;
	}

#else  // 默认：Kyber 原版模数 3329 (12位采样)
	const uint16_t bitmask = 0x0FFF; // 12位掩码

	// 批量处理：每次处理2个样本 (原版Kyber方式)
	while (ctr < len && pos + 3 <= buflen) {
		uint16_t val0 = (buf[pos] | ((uint16_t)buf[pos+1] << 8)) & bitmask;
		uint16_t val1 = (buf[pos+1] >> 4) | ((uint16_t)buf[pos+2] << 4);
		pos += 3;

		if (val0 < PARAM_Q)
			r[ctr++] = val0;
		if (ctr < len && val1 < PARAM_Q)
			r[ctr++] = val1;
	}

#endif
	return ctr; // 返回实际采样到的系数个数
}

// 动态计算每个多项式所需块数
#define UNIFORM_BITS 13          // 7681需要13位采样 (8192>7681)
#define UNIFORM_MAX 8191 
//#define XOF_BLOCKBYTES 168
#define XOF_BLOCKBYTES ASCON_HASH_RATE
#define BYTES_PER_POLY ((PARAM_N * UNIFORM_BITS + 7) / 8)  // 字节数量 = (系数个数×比特数 + 7) / 8
#define GEN_MATRIX_NBLOCKS ((BYTES_PER_POLY + XOF_BLOCKBYTES - 1) / XOF_BLOCKBYTES)

// 矩阵生成函数（支持多种模数）
void genmatrix(polyvec *a, const uint8_t *seed, int transposed)
{
    unsigned int ctr, i, j;
    size_t buflen;
    
    // 为每个多项式分配足够的缓冲区
    uint8_t buf[GEN_MATRIX_NBLOCKS * XOF_BLOCKBYTES];
    
    // 扩展种子结构：标准种子 + i坐标 + j坐标 + 计数器
    uint8_t extseed[SEED_BYTES + 3];
    memcpy(extseed, seed, SEED_BYTES);
    
    for(i = 0; i < PARAM_K; i++) {
        for(j = 0; j < PARAM_K; j++) {
            // 根据是否为转置矩阵设置索引
            extseed[SEED_BYTES] = transposed ? i : j;       // X坐标
            extseed[SEED_BYTES+1] = transposed ? j : i;     // Y坐标
            extseed[SEED_BYTES+2] = 0;                     // 计数器初始化为0
            
            // 生成随机字节流
            if (GEN_MATRIX_NBLOCKS * XOF_BLOCKBYTES > sizeof(buf)) {
                // 安全防护缓冲区溢出
                return;
            }
            ascon_xof(buf, GEN_MATRIX_NBLOCKS * XOF_BLOCKBYTES, extseed, SEED_BYTES + 3);
            buflen = GEN_MATRIX_NBLOCKS * XOF_BLOCKBYTES;
            
            // 使用模数特定的拒绝采样
            ctr = rej_uniform2(a[i].vec[j].coeffs, PARAM_N, buf, buflen);
            
            // 如果系数不足，继续生成
            while(ctr < PARAM_N) {
                extseed[SEED_BYTES+2]++;  // 递增计数器
                ascon_xof(buf, XOF_BLOCKBYTES, extseed, SEED_BYTES + 3);
                ctr += rej_uniform2(a[i].vec[j].coeffs + ctr, PARAM_N - ctr, buf, XOF_BLOCKBYTES);
            }
        }
    }
}
#endif

