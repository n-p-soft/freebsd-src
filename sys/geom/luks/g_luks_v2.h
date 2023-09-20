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

#ifndef _G_LUKS_V2_H
#define _G_LUKS_V2_H

#define G_LUKS_JSTR_LEN		48	

typedef char g_luks_jstr[G_LUKS_JSTR_LEN+1];

struct g_luks_jconfig {
	size_t	json_size;
	size_t	keyslots_size;
};

struct g_luks_jsegment {
	size_t		offset;
	size_t		len;
	unsigned long	iv_tweak;
	g_luks_jstr	encryption;
	size_t		sector_size;
};

struct g_luks_kdf {
	g_luks_jstr	type;
	g_luks_jstr	salt64;
	union {
		struct {
			g_luks_jstr	hash;
			unsigned long	iterations;
		} pbkdf2;
		struct {
			unsigned long	time;
			unsigned long	memory;
			unsigned long	cpus;
		} argon2i;
	} def;
};

#define G_LUKS_V2_STRIPES	4000

struct g_luks_af {
	g_luks_jstr	hash;
	unsigned long	stripes;
};

struct g_luks_area {
	g_luks_jstr	type;
	g_luks_jstr	encryption;
	unsigned long	offset;
	size_t		size;
	size_t		key_size;
};

struct g_luks_jkeyslot {
	size_t			key_size;
	unsigned long		priority;
	struct g_luks_area	area;
	struct g_luks_af	af;
	struct g_luks_kdf	kdf;
};

#define G_LUKS_V2_MAX_SLOTS	16
#define G_LUKS_JARRAY_MAX	10
#define G_LUKS_JLIST_MAX	10

struct g_luks_jdata {
	char 		*buf;
	size_t	 	buf_len;
	char		*array[G_LUKS_JARRAY_MAX];
	size_t		array_size;
	char		*list[G_LUKS_JLIST_MAX];
	size_t		list_size;
	size_t		keyslots;

	struct g_luks_jconfig	config;
	struct g_luks_jsegment	segment;
	struct g_luks_jkeyslot	keyslot[G_LUKS_V2_MAX_SLOTS];
};

typedef enum {
	G_LUKS_VT_BLOCK = 1,
	G_LUKS_VT_VALUE,
	G_LUKS_VT_QUOTED_VALUE,
} g_luks_value_type;

int
g_luks_jparse(char *buf, size_t len, struct g_luks_jdata *jd);

#endif
