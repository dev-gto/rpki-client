/*	$Id$ */
/*
 * Copyright (c) 2019 Kristaps Dzonsons <kristaps@bsd.lv>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#ifndef TEST_CORE_H
#define TEST_CORE_H

#include <stdlib.h>

typedef struct _filename{
	char *filename;
} FILEENTRY;

DEFINE_STACK_OF(FILEENTRY)
DECLARE_ASN1_ALLOC_FUNCTIONS(FILEENTRY)

typedef struct Session
{
	STACK_OF(FILEENTRY) *filenames;
} *HSESSION;

void hex_encode (unsigned char *lpcAsc, unsigned char *lpcBcd, size_t szBcd);

void print_cert(const struct cert *p);
void print_crl(X509_CRL *p);
void print_mft(const struct mft *p);
void print_roa(const struct roa *p);
void print_tal(const struct tal *p);

void sessionInit (HSESSION hSession);
int sessionFree (HSESSION hSession, int iRtn);

struct tal	*tal_parse_from_file(const char *fn);

#endif
