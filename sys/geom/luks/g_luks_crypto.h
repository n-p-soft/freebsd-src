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

#ifndef _SYS_GEOM_LUKS_CRYPTO_H_
#define _SYS_GEOM_LUKS_CRYPTO_H_ 1

#include <sys/types.h>
#include <sys/time.h>
#include <sys/errno.h>
#include <sys/libkern.h>
#include <opencrypto/cryptodev.h>
#include <opencrypto/rmd160.h>
#include <crypto/sha1.h>
#include <crypto/sha2/sha256.h>
#include <crypto/sha2/sha512.h>
#include <crypto/rijndael/rijndael-api-fst.h>

#define G_LUKS_DG_MAX_LEN	SHA2_512_HASH_LEN
#define G_LUKS_DG_BLOCK_MAX_LEN	SHA2_512_BLOCK_LEN

typedef enum {
	G_LUKS_HASH_UNKNOWN = 0,
	G_LUKS_HASH_SHA1=CRYPTO_SHA1,
	G_LUKS_HASH_SHA256=CRYPTO_SHA2_256,
	G_LUKS_HASH_SHA512=CRYPTO_SHA2_512,
	G_LUKS_HASH_RMD160=CRYPTO_RIPEMD160,
} g_luks_hash;

typedef enum {
	G_LUKS_COP_ENCRYPT = 1,
	G_LUKS_COP_DECRYPT = 2
} g_luks_cop;

typedef enum {
	G_LUKS_MODE_UNKNOWN = 0,
	G_LUKS_MODE_ECB,
	G_LUKS_MODE_CBC_PLAIN,
	G_LUKS_MODE_CBC_ESSIV_SHA256,
	G_LUKS_MODE_XTS_PLAIN64,
} g_luks_mode;

struct g_luks_digest_ctx {
	g_luks_hash	alg;
	size_t		output_len;
	size_t		block_len;
	uint8_t		digest[G_LUKS_DG_MAX_LEN];
	union {
		RMD160_CTX rmd160;
		SHA1_CTX sha1;
		SHA256_CTX sha256;
		SHA512_CTX sha512;
	} ctx;
};

struct g_luks_hmac_ctx {
	struct g_luks_digest_ctx	inner;
	struct g_luks_digest_ctx	outer;
};

typedef enum {
	G_LUKS_CIPHER_UNKNOWN = 0,
	G_LUKS_CIPHER_AES,
} g_luks_cipher;

struct g_luks_cipher_ctx {
	g_luks_cipher	alg;
	g_luks_mode	mode;
	g_luks_cop	cop;
	cipherInstance	ci[2];
	keyInstance	ki[2];
	uint8_t		iv[64];
};

typedef enum {
	G_LUKS_KDF_UNKNOWN = 0,
	G_LUKS_KDF_PBKDF2,
	G_LUKS_KDF_ARGON2I,
	G_LUKS_KDF_ARGON2ID,
} g_luks_kdf;

#define G_LUKS_KDF_IV_MAX	64

typedef int (*g_luks_kdf_t)(struct g_luks_kdf_ctx *ctx,
				const uint8_t* passphrase, size_t pass_len,
				uint8_t *buf, size_t buf_len);

struct g_luks_kdf_ctx {
	g_luks_kdf	type;
	uint8_t		iv[G_LUKS_KDF_IV_MAX];
	union {
		struct {
			g_luks_hash	hash;
			unsigned long	iterations;
		} pbkdf2;
		struct {
			unsigned long	time;
			unsigned long	memory;
			unsigned long	cpus;
		} argon2i;
	} def;
};

int
g_luks_kdf_init(struct g_luks_kdf_ctx *ctx, g_luks_kdf type,
		const uint8_t *iv, size_t iv_len);

int
g_luks_kdf_do(struct g_luks_kdf_ctx *ctx,
		const uint8_t* passphrase, size_t pass_len,
		uint8_t *buf, size_t buf_len);

int
g_luks_cipher_init(struct g_luks_cipher_ctx *ctx, g_luks_cop op,
			g_luks_cipher alg, g_luks_mode mode,
			const uint8_t *key, size_t len);

int
g_luks_cipher_setup_iv(struct g_luks_cipher_ctx *ctx,
			uint64_t iv_source);

int
g_luks_cipher_do_block(struct g_luks_cipher_ctx *ctx, int n, uint8_t *in,
			uint8_t *out, size_t len);

int
g_luks_cipher_do(struct g_luks_cipher_ctx *ctx, uint8_t *in, size_t len);

int
g_luks_cipher_do_to(struct g_luks_cipher_ctx *ctx, uint8_t *in,
			uint8_t *out, size_t len);

void
g_luks_cipher_clear(struct g_luks_cipher_ctx *ctx);

void
g_luks_digest_clear(struct g_luks_digest_ctx *ctx);

int
g_luks_digest_init(struct g_luks_digest_ctx *ctx, int alg);

int
g_luks_digest_final(struct g_luks_digest_ctx *ctx, uint8_t* dest);

int
g_luks_digest_update(struct g_luks_digest_ctx *ctx,
			const uint8_t *data, size_t len);

int
g_luks_digest_output_len(int hash_alg);

g_luks_hash
g_luks_digest_from_str(const char *s, size_t len);

int
g_luks_hmac(int hash_alg,
		const uint8_t *hkey, size_t hkeysize,
		uint8_t *data, size_t datasize,
		uint8_t *md, size_t mdsize);

void
g_luks_hmac_final(struct g_luks_hmac_ctx *ctx,
			uint8_t *md, size_t mdsize);

void
g_luks_hmac_update(struct g_luks_hmac_ctx *ctx,
			uint8_t *data, size_t datasize);

int
g_luks_hmac_init(struct g_luks_hmac_ctx *ctx, int hash_alg,
		const uint8_t *hkey, size_t hkeylen);

#endif /* _SYS_GEOM_G_LUKS_CRYPTO_H_ */
