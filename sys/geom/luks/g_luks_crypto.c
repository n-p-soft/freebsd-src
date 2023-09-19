/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2023 Nicolas Provost <dev@npsoft.fr>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <geom/luks/g_luks_crypto.h>

/**********
 * DIGEST *
 *********/
static const char *g_luks_hashes[] = {
	"sha1", "sha256", "sha512", "ripemd160", NULL
};

static const int g_luks_hashes_id[] = {
	G_LUKS_HASH_SHA1,
	G_LUKS_HASH_SHA256,
	G_LUKS_HASH_SHA512,
	G_LUKS_HASH_RMD160,
};

g_luks_hash
g_luks_digest_from_str(const char *s, size_t len)
{
	int i;

	for (i = 0; g_luks_hashes[i]; i++) {
		if (strncmp(s, g_luks_hashes[i], len) == 0)
			return g_luks_hashes_id[i];
	}
	return (G_LUKS_HASH_UNKNOWN);
}

int
g_luks_digest_output_len(int hash_alg)
{
	switch(hash_alg) {
	case CRYPTO_SHA1:
		return SHA1_HASH_LEN;
	case CRYPTO_SHA2_256:
		return SHA2_256_HASH_LEN;
	case CRYPTO_SHA2_512:
		return SHA2_512_HASH_LEN;
	case CRYPTO_RIPEMD160:
		return RIPEMD160_HASH_LEN;
	default:
		return 0;
	};
}

int
g_luks_digest_init(struct g_luks_digest_ctx *ctx, int hash_alg)
{
	ctx->alg = hash_alg;

	switch(hash_alg) {
	case CRYPTO_SHA1:
		SHA1Init(&ctx->ctx.sha1);
		ctx->block_len = SHA1_BLOCK_LEN;
		break;
	case CRYPTO_SHA2_256:
		SHA256_Init(&ctx->ctx.sha256);
		ctx->block_len = SHA2_256_BLOCK_LEN;
		break;
	case CRYPTO_SHA2_512:
		SHA512_Init(&ctx->ctx.sha512);
		ctx->block_len = SHA2_512_BLOCK_LEN;
		break;
	case CRYPTO_RIPEMD160:
		RMD160Init(&ctx->ctx.rmd160);
		ctx->block_len = RIPEMD160_BLOCK_LEN;
		break;
	default:
		return EOPNOTSUPP;
	};
	ctx->output_len = g_luks_digest_output_len(hash_alg);
	return(0);
}

int
g_luks_digest_update(struct g_luks_digest_ctx *ctx,
			const uint8_t *data, size_t len)
{
	switch(ctx->alg) {
	case CRYPTO_SHA1:
		SHA1Update(&ctx->ctx.sha1, data, len);
		break;
	case CRYPTO_SHA2_256:
		SHA256_Update(&ctx->ctx.sha256, data, len);
		break;
	case CRYPTO_SHA2_512:
		SHA512_Update(&ctx->ctx.sha512, data, len);
		break;
	case CRYPTO_RIPEMD160:
		RMD160Update(&ctx->ctx.rmd160, data, len);
		break;
	default:
		return EOPNOTSUPP;
	};
	return(0);
}

int
g_luks_digest_final(struct g_luks_digest_ctx *ctx, uint8_t* dest)
{
	uint8_t *p;

	if (dest == NULL)
		p = ctx->digest;
	else
		p = dest;

	switch(ctx->alg) {
	case CRYPTO_SHA1:
		SHA1Final(p, &ctx->ctx.sha1);
		break;
	case CRYPTO_SHA2_256:
		SHA256_Final(p, &ctx->ctx.sha256);
		break;
	case CRYPTO_SHA2_512:
		SHA512_Final(p, &ctx->ctx.sha512);
		break;
	case CRYPTO_RIPEMD160:
		RMD160Final(p, &ctx->ctx.rmd160);
		break;
	default:
		return EOPNOTSUPP;
	};
	return(0);
}

void
g_luks_digest_clear(struct g_luks_digest_ctx *ctx)
{
	explicit_bzero(ctx, sizeof(struct g_luks_digest_ctx));
}

/*******
 * KDF *
 *******/
int
g_luks_kdf_init(struct g_luks_kdf_ctx *ctx, g_luks_kdf type,
		const uint8_t *iv, size_t iv_len)
{
	explicit_bzero(ctx, sizeof(struct g_luks_kdf_ctx));
	switch(type) {
		case G_LUKS_KDF_PBKDF2:
			break;
		case G_LUKS_KDF_ARGON2I:
		case G_LUKS_KDF_ARGON2ID:
			return (EOPNOTSUPP);
		default:
			return (EOPNOTSUPP);
	}
	ctx->type = type;
	if (iv != NULL) {
		if (iv_len > G_LUKS_KDF_IV_MAX)
			return (EINVAL);
		memcpy(ctx->iv, iv, iv_len);
		ctx->iv_len = iv_len;
	}
	return (0);
}

/* PBKDF2 key derivation v2.1 */
static int
g_luks_pbkdf2(const uint8_t *passphrase, size_t pass_len,
		uint8_t *iv, size_t iv_len,
		uint8_t *buf, size_t buf_len,
		int iterations, int hash_alg)
{
	size_t left;
	size_t plen;
	size_t digest_len;
	uint8_t U[G_LUKS_DG_MAX_LEN];
	int i, j, bcount;
	uint8_t count[4];
	struct g_luks_hmac_ctx ctx;

	digest_len = g_luks_digest_output_len(hash_alg);
	if (digest_len == 0)
		return (EOPNOTSUPP);

	for (bcount = 1, left = buf_len; left > 0; bcount++) {
		/* F(P, S, c, i) = U1 xor U2 xor ... Uc
		 * U1 = PRF(P, S || i)
		 * U2 = PRF(P, U1)
	 	 * Uc = PRF(P, Uc-1)
	 	 */
		g_luks_hmac_init(&ctx, hash_alg, passphrase, pass_len);
		g_luks_hmac_update(&ctx, iv, iv_len);
		count[0] = (bcount >> 24) & 0xff;
		count[1] = (bcount >> 16) & 0xff;
		count[2] = (bcount >> 8) & 0xff;
		count[3] = bcount & 0xff;
		g_luks_hmac_update(&ctx, count, 4);
		g_luks_hmac_final(&ctx, U, digest_len);
		memcpy(buf, U, left < digest_len ? left : digest_len);
		for (i = 1; i < iterations; i++) {
			g_luks_hmac_init(&ctx, hash_alg, passphrase, pass_len);
			g_luks_hmac_update(&ctx, U, digest_len);
			g_luks_hmac_final(&ctx, U, digest_len);
			for (j = 0; j < digest_len; j++) {
				if (j < left)
					buf[j] ^= U[j];
			}
		}
		plen = (left >= digest_len) ? digest_len : left;
		buf += plen;
		left -= plen;
	}
	explicit_bzero(&ctx, sizeof(struct g_luks_hmac_ctx));

	return (0);
}

int
g_luks_kdf_do(struct g_luks_kdf_ctx *ctx,
		const uint8_t* passphrase, size_t pass_len,
		uint8_t *buf, size_t buf_len)
{
	switch(ctx->type) {
	case G_LUKS_KDF_PBKDF2:
		return (g_luks_pbkdf2(passphrase, pass_len,
			ctx->iv, ctx->iv_len, buf, buf_len,
			ctx->def.pbkdf2.iterations,
			ctx->def.pbkdf2.hash));
	default:
		return (EOPNOTSUPP);
	}
}
/********
 * HMAC *
 ********/
int
g_luks_hmac_init(struct g_luks_hmac_ctx *ctx, int hash_alg,
		const uint8_t *hkey, size_t hkeylen)
{
	u_char k_ipad[NULL_HMAC_BLOCK_LEN];
	u_char k_opad[NULL_HMAC_BLOCK_LEN];
	u_char key[NULL_HMAC_BLOCK_LEN];
	struct g_luks_digest_ctx lctx;
	size_t blk_len;
	u_int i;

	explicit_bzero(key, sizeof(key));
	if (g_luks_digest_init(&ctx->inner, hash_alg) != 0)
		return (EOPNOTSUPP);
	blk_len = ctx->inner.block_len;
	if (blk_len != NULL_HMAC_BLOCK_LEN)
		return (EOPNOTSUPP);
	g_luks_digest_init(&ctx->outer, hash_alg);

	if (hkeylen == 0) {
		/* do nothing */ 
	}
	else if (hkeylen <= blk_len)
		bcopy(hkey, key, hkeylen);
	else {
		/* If key is longer than blk_len bytes, hash the key */
		g_luks_digest_init(&lctx, hash_alg);
		g_luks_digest_update(&lctx, hkey, hkeylen);
		g_luks_digest_final(&lctx, key);
		g_luks_digest_clear(&lctx);
	}

	/* XOR key with ipad and opad values. */
	for (i = 0; i < NULL_HMAC_BLOCK_LEN; i++) {
		k_ipad[i] = key[i] ^ HMAC_IPAD_VAL;
		k_opad[i] = key[i] ^ HMAC_OPAD_VAL;
	}
	explicit_bzero(key, sizeof(key));

	/* Start inner. */
	g_luks_digest_update(&ctx->inner, k_ipad, blk_len);
	explicit_bzero(k_ipad, sizeof(k_ipad));

	/* Start outer. */
	g_luks_digest_update(&ctx->outer, k_opad, blk_len);
	explicit_bzero(k_opad, sizeof(k_opad));

	return (0);
}

void
g_luks_hmac_update(struct g_luks_hmac_ctx *ctx,
			uint8_t *data, size_t datasize)
{
	g_luks_digest_update(&ctx->inner, data, datasize);
}

void
g_luks_hmac_final(struct g_luks_hmac_ctx *ctx, uint8_t *md, size_t mdsize)
{
	/* Complete inner hash */
	g_luks_digest_final(&ctx->inner, NULL);

	/* Complete outer hash */
	g_luks_digest_update(&ctx->outer, ctx->inner.digest,
				ctx->inner.output_len);
	g_luks_digest_final(&ctx->outer, NULL);
	g_luks_digest_clear(&ctx->inner);

	if (mdsize == 0)
		mdsize = ctx->outer.output_len;
	bcopy(ctx->outer.digest, md, mdsize);
	g_luks_digest_clear(&ctx->outer);
}

int
g_luks_hmac(int hash_alg,
		const uint8_t *hkey, size_t hkeysize,
		uint8_t *data, size_t datasize,
		uint8_t *md, size_t mdsize)
{
	struct g_luks_hmac_ctx ctx;

	if (g_luks_hmac_init(&ctx, hash_alg, hkey, hkeysize) != 0)
		return (1);
	g_luks_hmac_update(&ctx, data, datasize);
	g_luks_hmac_final(&ctx, md, mdsize);
	return (0);
}

/***********
 * AES-XTS *
 ***********/
#define GF_128_FDBK	0x87

/* AES-XTS inplace encryption/decryption (unpadded) */
static int
g_luks_aes_xts(struct g_luks_cipher_ctx *ctx, uint8_t* in,
		uint8_t *out, size_t len)
{
	size_t j;
	int error = 0;
	uint8_t cin, cout;

	if (len % AES_BLOCK_LEN)
		error = EINVAL;
	if (out == NULL)
		out = in;

	for ( ; len > 0 && error == 0; len -= AES_BLOCK_LEN) {
		for (j = 0; j < AES_BLOCK_LEN; j++)
			out[j] = in[j] ^ ctx->iv[j];

		error = g_luks_cipher_do_block(ctx, 0, out, out, AES_BLOCK_LEN);

		for (j = 0; j < AES_BLOCK_LEN; j++)
			out[j] ^= ctx->iv[j];

		/* multiply IV by alpha */
		cin = 0;
		for (j = 0; j < AES_BLOCK_LEN; j++) {
			cout = (ctx->iv[j] >> 7) & 1;
			ctx->iv[j] = ((ctx->iv[j] << 1) + cin) & 0xff;
			cin = cout;
		}
		if (cout)
			ctx->iv[0] ^= GF_128_FDBK;
		in += AES_BLOCK_LEN;
		if (in != out)
			out += AES_BLOCK_LEN;
	}
	return (error);
}

/*******
 * AES *
 *******/
static void
g_luks_fill_iv_cbc(uint8_t *IV, uint32_t v)
{
	uint32_t* p = (uint32_t*) IV;

	*p++ = htole32(v);
	*p++ = 0;
	*p++ = 0;
	*p = 0;
}

static void
g_luks_fill_iv(uint8_t *IV, uint64_t v, size_t n)
{
	size_t i;

	for (i = 0; i < 8; i++) {
		IV[i] = v & 0xff;
		v >>= 8;
	}
	for ( ; i < n; i++)
		IV[i] = 0;
}

int
g_luks_cipher_setup_iv(struct g_luks_cipher_ctx *ctx, uint64_t iv_source)
{
	int error = 0;
	const int niv = RIJNDAEL_MAX_IV_SIZE;

	switch(ctx->mode) {
		case G_LUKS_MODE_ECB:
			/* no IV */
			break;
		case G_LUKS_MODE_CBC_PLAIN:
			/* IV = 32-bit sector number */
			g_luks_fill_iv_cbc(ctx->ci[0].IV,
						iv_source & 0xffffffff);
			break;
		case G_LUKS_MODE_CBC_ESSIV_SHA256:
			/* IV = E(SHA256(key),iv_source).
			 * SHA256 len = 32, AES block = IV len = 16 bytes. */
			g_luks_fill_iv_cbc(ctx->ci[0].IV,
						iv_source & 0xffffffff);
			g_luks_cipher_do_block(ctx, 1, ctx->ci[0].IV,
						ctx->ci[0].IV, niv);
			break;
		case G_LUKS_MODE_XTS_PLAIN64:
			/* IV is based on 64-bit sector number. Use k2. */
			g_luks_fill_iv(ctx->iv, iv_source, niv);
			g_luks_cipher_do_block(ctx, 1, ctx->iv, ctx->iv, niv);
			break;
		default:
			error = EOPNOTSUPP;
			break;
	}
	return (error);
}

static int g_luks_rijndael_init(struct g_luks_cipher_ctx *ctx, int n,
				int mode, int dir,
				const uint8_t* key, size_t len)
{
	if (rijndael_cipherInit(&ctx->ci[n], mode, NULL) != 1)
		return (-1);
	else if (rijndael_makeKey(&ctx->ki[n], dir, 8 * len, key) != 1)
		return (-1);
	else {
		explicit_bzero(&ctx->ki[n].keyMaterial, len);
		return (0);
	}
}

int
g_luks_cipher_init(struct g_luks_cipher_ctx *ctx, g_luks_cop cop,
			g_luks_cipher alg, g_luks_mode mode,
			const uint8_t *key, size_t len)
{
	int error = 0;
	int dir;
	struct g_luks_digest_ctx dg;

	explicit_bzero(ctx, sizeof(struct g_luks_cipher_ctx));
	if (cop == G_LUKS_COP_ENCRYPT)
		dir = DIR_ENCRYPT;
	else
		dir = DIR_DECRYPT;
		
	switch(alg) {
	case G_LUKS_CIPHER_AES:
		if (mode == G_LUKS_MODE_XTS_PLAIN64) {
			if ((len != 2*AES_MIN_KEY) && (len != 2*AES_MAX_KEY))
				return (EINVAL);
		}
		else if (len != AES_MIN_KEY && len != AES_MAX_KEY)
			return (EINVAL);
		break;
	default:
		return (EOPNOTSUPP);
	}

	ctx->alg = alg;
	ctx->mode = mode;
	ctx->cop = cop;

	/* setup the material */
	switch(ctx->mode) {
		case G_LUKS_MODE_XTS_PLAIN64:
			error = g_luks_rijndael_init(ctx, 0, MODE_ECB,
							dir, key, len / 2);
			if (error == 0)
				error = g_luks_rijndael_init(ctx, 1, MODE_ECB,
							DIR_ENCRYPT,
							key + (len / 2),
							len / 2);
			break;
		case G_LUKS_MODE_ECB:
			error = g_luks_rijndael_init(ctx, 0, MODE_ECB,
							dir, key, len);
			break;
		case G_LUKS_MODE_CBC_PLAIN:
			error = g_luks_rijndael_init(ctx, 0, MODE_CBC,
							dir, key, len);
			break;
		case G_LUKS_MODE_CBC_ESSIV_SHA256:
			error = g_luks_rijndael_init(ctx, 0, MODE_CBC,
							dir, key, len);
			if (error == 0) {
				g_luks_digest_init(&dg, G_LUKS_HASH_SHA256);
				g_luks_digest_update(&dg, key, len);
				g_luks_digest_final(&dg, NULL);
				error = g_luks_rijndael_init(ctx, 1, MODE_ECB,
								DIR_ENCRYPT,
								dg.digest,
								dg.output_len);
				g_luks_digest_clear(&dg);
			}
			break;
		default:
			error = EOPNOTSUPP;
			break;
	}

	return (error);
}

/* inplace block encryption/decryption using key #n of ctx */
int
g_luks_cipher_do_block(struct g_luks_cipher_ctx *ctx, int n,
			uint8_t *in, uint8_t *out, size_t len)
{
	if (n < 0 || n > 1 || (len % AES_BLOCK_LEN))
		return (EINVAL);

	if (ctx->ki[n].direction == DIR_ENCRYPT) {
		if (rijndael_blockEncrypt(&ctx->ci[n], &ctx->ki[n],
					in, len * 8, out) != len * 8)
			return (-1);
	}
	else {
		if (rijndael_blockDecrypt(&ctx->ci[n], &ctx->ki[n],
					in, len * 8, out) != len * 8)
			return (-1);
	}

	return (0);
}

/* inplace encryption/decryption using key #0 of ctx */
int
g_luks_cipher_do(struct g_luks_cipher_ctx *ctx, uint8_t *in, size_t len)
{
	switch(ctx->mode) {
	case G_LUKS_MODE_ECB:
	case G_LUKS_MODE_CBC_PLAIN:
	case G_LUKS_MODE_CBC_ESSIV_SHA256:
		return (g_luks_cipher_do_block(ctx, 0, in, in, len));
	case G_LUKS_MODE_XTS_PLAIN64:
		return (g_luks_aes_xts(ctx, in, in, len));
	default:
		return (EINVAL);
	}
}

int
g_luks_cipher_do_to(struct g_luks_cipher_ctx *ctx, uint8_t *in,
			uint8_t *out, size_t len)
{
	switch(ctx->mode) {
	case G_LUKS_MODE_ECB:
	case G_LUKS_MODE_CBC_PLAIN:
	case G_LUKS_MODE_CBC_ESSIV_SHA256:
		return (g_luks_cipher_do_block(ctx, 0, in, out, len));
	case G_LUKS_MODE_XTS_PLAIN64:
		return (g_luks_aes_xts(ctx, in, out, len));
	default:
		return (EINVAL);
	}
}

void
g_luks_cipher_clear(struct g_luks_cipher_ctx *ctx)
{
	explicit_bzero(ctx, sizeof(struct g_luks_cipher_ctx));
}
