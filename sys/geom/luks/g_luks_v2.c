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

#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <geom/luks/g_luks.h>
#include <geom/luks/g_luks_v2.h>

#define G_LUKS_JDEBUG	printf

static inline int
g_luks_isspace(int c)
{
	if (c == ' ' || c == '\r' || c == '\n')
		return (1);
	else
		return (0);
}

static char *
g_luks_chr(char* start, char* max, int c)
{
	for ( ; start <= max; start++) {
		if (*start == 0)
			break;
		else if (*start == c)
			return (start);
	}
	return (NULL);
}

/* find the matching } for the end of the block starting at (start-1).
 * start[-1] == {
 */
static char *
g_luks_jfind_end(char *start, char *max)
{
	int par;

	for (par = 1; start <= max; start++) {
		if (*start == '{')
			par++;
		else if (*start == '}') {
			if (--par == 0)
				return (start);
		}
	}
	return (NULL);
}

/* extract one block: "name":{ data } or "name":data */
static int
g_luks_jblock(char **start, char* max,
		char *name, size_t name_len,
		char *data, size_t data_len,
		g_luks_value_type *vt)
{
	char *data_start;
	char *data_end;
	char *name_start;
	char *p;
	int quoted;

	for (name_start = *start; name_start <= max; name_start++) {
		if (g_luks_isspace(*name_start))
			continue;
		else if (*name_start == '"') {
			for (p = ++name_start; p < max; p++) {
				if (*p == '"') {
					*p = 0;
					if (p - name_start > name_len)
						return (ENOMEM);
					memcpy(name, name_start,
						p - name_start + 1);
					break;
				}
				else if (*p < 'a' || *p > 'z') {
					if (*p < '0' || *p > '9')
						return (EINVAL);
				}
			}	
			if (p == max || *(p+1) != ':')
				return (EINVAL);
			p += 2;
			break;
		}
		else
			return (EINVAL);
	}

	data_start = p;
	bzero(data, data_len);
	if (*data_start != '{') {
		/* name:value or name:"value" */
		if (*data_start == '"') {
			quoted = 1;
			data_start++;
			*vt = G_LUKS_VT_QUOTED_VALUE;
		}
		else {
			*vt = G_LUKS_VT_VALUE;
			quoted = 0;
		}
		for (data_end = data_start; data_end <= max; data_end++) {
			if (quoted == 1 && *data_end == '"') {
				*data_end = 0;
				quoted--;
				if (data_end < max && *(data_end+1) == ',')
					*(data_end + 1) = 0;
				*start = data_end + 2;
				break;
			}
			else if (*data_end == ',') {
				*data_end = 0;
				*start = data_end + 1;
				break;
			}
		}
		if (quoted != 0)
			return (EINVAL);
		if (data_end - data_start >= data_len)
			return (ENOMEM);
		memcpy(data, data_start, data_end - data_start);
		return (0);
	}

	*vt = G_LUKS_VT_BLOCK;
	*data_start++ = 0;
	data_end = g_luks_jfind_end(data_start, max);
	if (data_end == NULL)
		return (EINVAL);
	*data_end = 0;
	if (data_end - data_start > data_len)
		return (ENOMEM);
	memcpy(data, data_start, data_end - data_start);

	*start = data_end + 1;
	if (*start <= max && **start == ',') {
		**start = 0;
		(*start)++;
	}
	return (0);
}

static int
g_luks_jlong(const char *data, long *n)
{
	char *end = NULL;

	if (*data == 0)
		return (EINVAL);
	*n = strtol(data, &end, 10);
	if (end != NULL && *end != 0)
		return(EINVAL);
	else
		return (0);
}

static int
g_luks_julong(const char *data, unsigned long *n)
{
	char *end = NULL;

	if (*data == 0)
		return (EINVAL);
	*n = strtoul(data, &end, 10);
	if (end != NULL && *end != 0)
		return(EINVAL);
	else
		return (0);
}

static void
g_luks_jlist_free(struct g_luks_jdata *jd)
{
	size_t i;

	for (i = 0; i < jd->list_size; i++) {
		free(jd->list[i]);
		jd->list[i] = NULL;
	}
	jd->list_size = 0;
}

static void
g_luks_jarray_free(struct g_luks_jdata *jd)
{
	size_t i;

	for (i = 0; i < jd->array_size; i++) {
		free(jd->array[i]);
		jd->array[i] = NULL;
	}
	jd->array_size = 0;
}

/* split comma-separated data */
static int
g_luks_jlist_fill(struct g_luks_jdata *jd, char *data)
{
	char *start;
	char *end;
	char *p;
	int i;
	size_t len;
	int error = 0;

	if (data == NULL || *data == 0)
		return (0);
	end = data + strlen(data) - 1;
	for (i = 0, start = data;
		start != NULL && *start && i < G_LUKS_JLIST_MAX; i++) {
		for (p = start ; p <= end; p++) {
			if (*p == ':') {
				p++;
				break;
			}
		}
		if (p > end) {
			error = EINVAL;
			break;
		}
		if (*p == '{') {
			p = g_luks_jfind_end(p + 1, end);
			if (p == NULL || p > end) {
				error = EINVAL;
				break;
			}
			else if (p <= end) {
				if (p < end) {
					if (p[1] != 0 && p[1] != ',') {
						error = EINVAL;
						break;
					}
					p[1] = 0;
					p += 2;
				}
				else
					p++;
			}
		}
		else {
			p = g_luks_chr(p, end, ',');
			if (p != NULL)
				*p++ = 0;
		}
		len = strlen(start);
		jd->list[i] = malloc(len + 1);
		if (jd->list[i] == NULL) {
			error = ENOMEM;
			break;
		}
		memcpy(jd->list[i], start, len);
		jd->list[i][len] = 0;
		jd->list_size++;
		start = p;
	}
	if (i == G_LUKS_JLIST_MAX)
		error = ENOMEM;
	if (error != 0)
		g_luks_jlist_free(jd);
	return (error);
}

/* Search for name (stored as "name":"value" or "name":{block}) in actual list.
 * If data is NULL, returns 0 if the entry is found. Else data will store
 * on return either the unquoted value or {block}.
 * Return 0 if found, ENOATTR if not found, EINVAL on parsing error, ENOMEM
 * if data_len is too low.
 */
static int
g_luks_jlist_lookup(struct g_luks_jdata *jd, const char *name,
			char *data, size_t data_len)
{
	size_t i;
	char *p;
	char *q;
	size_t len;
	size_t nlen = strlen(name);

	if (data != NULL)
		bzero(data, data_len);
	if (nlen == 0)
		return (EINVAL);
	for (i = 0; i < jd->list_size; i++) {
		len = strlen(jd->list[i]);
		if (len <= nlen + 3)
			continue;
		if (jd->list[i][nlen + 2] != ':' ||
			jd->list[i][0] != '"' ||
			jd->list[i][nlen + 1] != '"')
			continue;
		if (memcmp(jd->list[i] + 1, name, nlen) == 0) {
			if (data == NULL)
				return (0);
			else if (len - nlen - 3 >= data_len)
				return (ENOMEM);
			p = jd->list[i] + nlen + 3;
			if (*p == '"') {
				p++;
				for (i = 0 ; *p != 0 && *p != '"'; p++, i++)
					data[i] = *p;
				if (*p == '"' && p[1] != 0)
					return (EINVAL);
			}
			else {
				for (i = 0 ; *p != 0; p++, i++)
					data[i] = *p;
			}
			return (0);
		}
	}
	return (ENOATTR);
}

static int
g_luks_jlist_lookup_ulong(struct g_luks_jdata *jd, const char *name,
				unsigned long *n)
{
	int error;
	char data[32];

	error = g_luks_jlist_lookup(jd, name, data, 32);
	if (error == 0)
		error = g_luks_julong(data, n);
	return (error);
}

/* split jd->buf content when it is an array (no more than 10 entries) */
static int
g_luks_jarray_fill(struct g_luks_jdata *jd)
{
	size_t len;
	size_t blen;
	char *start;
	int i;
	char name[32];
	char data[1024];
	g_luks_value_type vt;
	int error;

	blen = strlen(jd->buf);
	for (i = 0, error = 0, start = jd->buf;
		i < G_LUKS_JARRAY_MAX && start < jd->buf + blen - 1; i++) {
		error = g_luks_jblock(&start, jd->buf + blen - 1,
					name, 32, data, 1024, &vt);
		if (error != 0)
			break;
		if (name[0] != ('0' + i) || name[1] != 0) {
			error = EINVAL;
			break;
		}
		len = strlen(data);
		jd->array[i] = malloc(len + 1);
		if (jd->array[i] == NULL) {
			error = ENOMEM;
			break;
		}
		jd->array_size++;
		memcpy(jd->array[i], data, len);
		jd->array[i][len] = 0;
	}
	if (i == G_LUKS_JARRAY_MAX)
		error = EINVAL;
	if (error != 0)
		g_luks_jarray_free(jd);
	return (error);
}

/* Data segments definition. Restrict to one "crypt" segment. */
static int
g_luks_jsegments(struct g_luks_jdata *jd)
{
	int error;
	char data[32];

	error = g_luks_jarray_fill(jd);
	G_LUKS_JDEBUG("segments (%zu)\n", jd->array_size);
	if (error == 0) {
		if (jd->array_size != 1)
			error = EOPNOTSUPP;
		error = g_luks_jlist_fill(jd, jd->array[0]);
	}
	if (error == 0) {
		error = g_luks_jlist_lookup(jd, "type", data, 32);
		if (error == 0 && strcmp(data, "crypt"))
			error = EOPNOTSUPP;
	}
	if (error == 0) {
		error = g_luks_jlist_lookup_ulong(jd, "offset",
							&jd->segment.offset);
	}
	if (error == 0) {
		error = g_luks_jlist_lookup_ulong(jd, "sector_size",
						&jd->segment.sector_size);
	}
	if (error == 0) {
		error = g_luks_jlist_lookup_ulong(jd, "iv_tweak",
							&jd->segment.iv_tweak);
	}
	if (error == 0) {
		error = g_luks_jlist_lookup(jd, "encryption",
						jd->segment.encryption,
						G_LUKS_JSTR_LEN);
	}
	if (error == 0) {
		error = g_luks_jlist_lookup(jd, "size", data, 32);
		if (error == 0) {
			if (strcmp(data, "dynamic") == 0)
				jd->segment.len = 0;
			else {
				error = g_luks_julong(data,
							&jd->segment.len);
				if (error == 0 && jd->segment.len == 0)
					error = EINVAL;
			}
		}
	}
	g_luks_jlist_free(jd);
	g_luks_jarray_free(jd);
	return (error);
}

static int
g_luks_jconfig(struct g_luks_jdata *jd)
{
	int error;
	char data[16];

	G_LUKS_JDEBUG("config\n");
	error = g_luks_jlist_fill(jd, jd->buf);
	if (error == 0) {
		/* requirements is not supported */
		error = g_luks_jlist_lookup(jd, "requirements", NULL, 0);
		if (error == 0)
			error = EOPNOTSUPP;
		else
			error = 0;
	}
	if (error == 0) {
		error = g_luks_jlist_lookup_ulong(jd, "json_size",
						&jd->config.json_size);
	}
	if (error == 0) {
		error = g_luks_jlist_lookup_ulong(jd, "keyslots_size",
						&jd->config.keyslots_size);
	}
	g_luks_jlist_free(jd);
	return (error);
}

/* for a block {data} return data, else NULL. */
static char*
g_luks_jblock_extract(char *s)
{
	char *start = s;
	char *p;

	if (*start != '{')
		return NULL;
	p = g_luks_jfind_end(++start, s + strlen(s) - 1);
	if (p != NULL) {
		*p = 0;
		return (start);
	}
	return (NULL);
}

static int
g_luks_jkdf(struct g_luks_jdata *jd, char *s, struct g_luks_kdf *kdf)
{
	int error;
	char *blk = g_luks_jblock_extract(s);
	
	if (blk == NULL)
		return (EINVAL);

	error = g_luks_jlist_fill(jd, blk);
	if (error != 0)
		return (error);

	error = g_luks_jlist_lookup(jd, "type", kdf->type, G_LUKS_JSTR_LEN);
	if (error == 0) {
		if (strcmp(kdf->type, "pbkdf2") &&
			strcmp(kdf->type, "argon2i") &&
			strcmp(kdf->type, "argon2id"))
			error = EOPNOTSUPP;
	}
	if (error == 0) {
		error = g_luks_jlist_lookup(jd, "salt", kdf->salt64,
						G_LUKS_JSTR_LEN);
	}
	if (error == 0) {
		if (strcmp(kdf->type, "pbkdf2") == 0) {
			error = g_luks_jlist_lookup(jd, "hash",
							kdf->def.pbkdf2.hash,
							G_LUKS_JSTR_LEN);
			if (error == 0) {
				error = g_luks_jlist_lookup_ulong(jd,
							"iterations",
						&kdf->def.pbkdf2.iterations);
			}
		}
		else {
			error = g_luks_jlist_lookup_ulong(jd, "time",
						&kdf->def.argon2i.time);
			if (error == 0)
				error = g_luks_jlist_lookup_ulong(jd, "cpus",
							&kdf->def.argon2i.cpus);
			if (error == 0)
				error = g_luks_jlist_lookup_ulong(jd,
						"memory",
						&kdf->def.argon2i.memory);
		}
	}
	g_luks_jlist_free(jd);
	return (error);
}

static int
g_luks_jarea(struct g_luks_jdata *jd, char *s, struct g_luks_area *jarea)
{
	int error;
	char *blk = g_luks_jblock_extract(s);
	
	if (blk == NULL)
		return (EINVAL);

	error = g_luks_jlist_fill(jd, blk);
	if (error != 0)
		return (error);

	error = g_luks_jlist_lookup(jd, "type", jarea->type,
					G_LUKS_JSTR_LEN);
	if (error == 0 && strcmp(jarea->type, "raw"))
		error = EOPNOTSUPP;
	if (error == 0)
		error = g_luks_jlist_lookup_ulong(jd, "size", &jarea->size);
	if (error == 0)
		error = g_luks_jlist_lookup_ulong(jd, "offset",
							&jarea->offset);
	if (error == 0)
		error = g_luks_jlist_lookup_ulong(jd, "key_size",
							&jarea->key_size);
	if (error == 0)
		error = g_luks_jlist_lookup(jd, "encryption",
						jarea->encryption,
						G_LUKS_JSTR_LEN);

	g_luks_jlist_free(jd);
	return (error);
}

static int
g_luks_jaf(struct g_luks_jdata *jd, char *s, struct g_luks_af *jaf)
{
	int error;
	char *blk = g_luks_jblock_extract(s);
	char data[16];
	
	if (blk == NULL)
		return (EINVAL);

	error = g_luks_jlist_fill(jd, blk);
	if (error != 0)
		return (error);

	error = g_luks_jlist_lookup(jd, "type", data, 16);
	if (error == 0) {
		if (strcmp(data, "luks1"))
			error = EOPNOTSUPP;
	}
	if (error == 0) {
		error = g_luks_jlist_lookup_ulong(jd, "stripes",
							&jaf->stripes);
		if (error == 0 && jaf->stripes != G_LUKS_V2_STRIPES)
			error = EOPNOTSUPP;
	}
	if (error == 0) {
		error = g_luks_jlist_lookup(jd, "hash", jaf->hash,
						G_LUKS_JSTR_LEN);
	}
	g_luks_jlist_free(jd);
	return (error);
}

static int
g_luks_jkeyslot(struct g_luks_jdata *jd, int n, char *ks)
{
	int error;
	char data[16];
	char area[512];
	char af[256];
	char kdf[256];

	G_LUKS_JDEBUG("keyslot #%i\n", n);
	error = g_luks_jlist_fill(jd, ks);
	if (error != 0)
		return (error);

	if (error == 0) {
		error = g_luks_jlist_lookup(jd, "type", data, 16);
		if (error == 0 && strcmp(data, "luks2"))
			error = EOPNOTSUPP;
	}
	if (error == 0) {
		error = g_luks_jlist_lookup_ulong(jd, "key_size",
						&jd->keyslot[n].key_size);
	}
	if (error == 0) {
		error = g_luks_jlist_lookup_ulong(jd, "priority",
						&jd->keyslot[n].priority);
		if (error == 0 && jd->keyslot[n].priority > 2)
			error = EINVAL;
		else if (error == ENOATTR) {
			jd->keyslot[n].priority = 0;
			error = 0;
		}
	}
	/* extract objects area, kdf, af */
	if (error == 0)
		error = g_luks_jlist_lookup(jd, "af", af, 256);
	if (error == 0)
		error = g_luks_jlist_lookup(jd, "kdf", kdf, 256);
	if (error == 0)
		error = g_luks_jlist_lookup(jd, "area", area, 512);
	g_luks_jlist_free(jd);
	if (error == 0)
		error = g_luks_jkdf(jd, kdf, &jd->keyslot[n].kdf);
	if (error == 0)
		error = g_luks_jarea(jd, area, &jd->keyslot[n].area);
	if (error == 0)
		error = g_luks_jaf(jd, af, &jd->keyslot[n].af);

	return (error);
}

static int
g_luks_jkeyslots(struct g_luks_jdata *jd)
{
	int error;
	int i;

	error = g_luks_jarray_fill(jd);
	G_LUKS_JDEBUG("keyslots (%zu)\n", jd->array_size);
	if (error == 0) {
		if (jd->array_size > G_LUKS_V2_MAX_SLOTS)
			error = EOPNOTSUPP;
		else {
			jd->keyslots = jd->array_size;
			for (i = 0; i < jd->keyslots; i++) {
				error = g_luks_jkeyslot(jd, i, jd->array[i]);
				if (error != 0)
					break;
			}
		}
	}
	g_luks_jarray_free(jd);
	return (error);
}

static int
g_luks_jdigests(struct g_luks_jdata *jd)
{
	int error;

	error = g_luks_jarray_fill(jd);
	G_LUKS_JDEBUG("digests (%zu)\n", jd->array_size);
	if (error == 0) {
			/* TODO */
	}
	g_luks_jarray_free(jd);
	return (error);
}

static int
g_luks_jparse_top(char *start, char *end, struct g_luks_jdata *jd)
{
	char name[32];
	int error;
	g_luks_value_type vt;

	for ( ; start <= end; ) {
		error = g_luks_jblock(&start, end, name, 32,
					jd->buf, jd->buf_len, &vt);
		if (error != 0)
			break;
		if (*name == 0 || vt != G_LUKS_VT_BLOCK)
			return (EINVAL);
		if (strcmp(name, "keyslots") == 0)
			error = g_luks_jkeyslots(jd);
		else if (strcmp(name, "tokens") == 0) {
			/* ignored */
		}
		else if (strcmp(name, "segments") == 0)
			error = g_luks_jsegments(jd);
		else if (strcmp(name, "digests") == 0)
			error = g_luks_jdigests(jd);
		else if (strcmp(name, "config") == 0)
			error = g_luks_jconfig(jd);
		else
			return (EOPNOTSUPP);
		if (error != 0)
			return (error);
	}

	/* check there is no trailing data */
	for ( ; start <= end && *start; start++) {
		if (!g_luks_isspace(*start))
			return (EINVAL);
	}
	return (0);
}

int
g_luks_jparse(char *buf, size_t len, struct g_luks_jdata *jd)
{
	char *start;
	char *end;
	int error;

	/* get content of outer block */
	if (len == 0)
		return (EINVAL);
	start = g_luks_chr(buf, buf + len - 1, '{');
	if (start == NULL)
		return (EINVAL);
	end = g_luks_jfind_end(start + 1, buf + len - 1);
	if (end == NULL || start == end)
		return (EINVAL);

	bzero(jd, sizeof(struct g_luks_jdata));
	jd->buf = malloc(len);
	if (jd->buf == NULL)
		return (ENOMEM);
	jd->buf_len = len;

	error = g_luks_jparse_top(start + 1, end - 1, jd);

	free(jd->buf);
	jd->buf = NULL;
	return (error);
}


