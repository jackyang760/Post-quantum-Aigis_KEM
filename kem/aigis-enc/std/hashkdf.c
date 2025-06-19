#include "hashkdf.h"
#include "sm3kdf.h"

void kdf128(uint8_t *out, int outlen, const uint8_t *in, int inlen)
{
#ifdef USE_SHAKE
	shake128(out, outlen, in, inlen);
#elif defined USE_SM3 
	sm3kdf(out, outlen, in, inlen);
#else
	ascon_xof(out, outlen, in, inlen);
#endif
}

void kdf256(uint8_t *out, int outlen, const uint8_t *in, int inlen)
{
#ifdef USE_SHAKE
	shake256(out, outlen, in, inlen);
#elif defined USE_SM3 
	sm3kdf(out, outlen, in, inlen);
#else
	ascon_xof(out, outlen, in, inlen);
#endif
}

void hash256(uint8_t *out, const uint8_t *in, int inlen)
{
#ifdef USE_SHAKE
	sha3_256(out, in, inlen);
#elif defined USE_SM3
	sm3kdf(out, 32, in, inlen);
#else
	ascon_hash_32(out, in, inlen);
#endif
}

void hash512(uint8_t *out, const uint8_t *in, int inlen)
{
#ifdef USE_SHAKE
	sha3_512(out, in, inlen);
#elif defined USE_SM3
	sm3kdf(out, 64, in, inlen);
#else
	ascon_hash_64(out, in, inlen);
#endif
}

void hash1024(uint8_t *out, const uint8_t *in, int inlen)
{
#ifdef USE_SHAKE
	sha3_1024(out, in, inlen);
#elif defined USE_SM3
	sm3kdf(out, 128, in, inlen);
#else
	ascon_hash_128(out, in, inlen);
#endif
}
#ifdef USE_SHAKE
void kdf128_absorb(kdfstate * state, const uint8_t *input, int inlen)
{
	shake128_absorb_once(state, input, inlen);
}
#elif defined USE_SM3
void kdf128_absorb(kdfstate * state, const uint8_t *input, int inlen)
{
	sm3kdf_absorb(state, input, inlen);
}	
#else 

#endif

#ifdef USE_SHAKE
void kdf128_squeezeblocks(uint8_t *output, int nblocks, kdfstate * state)
{
	shake128_squeezeblocks(output, nblocks, state);
}
#elif defined USE_SM3
void kdf128_squeezeblocks(uint8_t *output, int nblocks, kdfstate * state)
{
	sm3kdf_squeezeblocks(output, nblocks, state);
}
#else

#endif

