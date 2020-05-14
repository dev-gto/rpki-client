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
#include <openssl/safestack.h>
#include "extern.h"
#include "hash.h"

#define OPT_OUTPUT_TEXT 0
#define OPT_OUTPUT_JS_MONITOR 1

typedef struct {
    int iCode;
    char *lpcDescription;
    char *lpcReceived;
    char *lpcReference;
} Error;

void FileEntry_free(char *entry);

typedef struct Session
{
    int iOptRecursive;              // 1 - navigate through the internal file references
    int iOptOutput;                 // One of OPT_OUTPUT_*
    int iNumErrorsFound;
    char *lpcLocalRepository;       // Base directory for using with iOptRecursive
    char *lpcCurrentFilename;       // Current file being processed
	STACK_OF(OPENSSL_STRING) *filenames; // List of filenames to process (index zero record to be processed first)
    HHASH hCertFilenames;           // Hash key: certificate SKI; value: corresponding filename
    HHASH hCertSerialNumbers;       // Hash key: certificate SKI; value: corresponding serial number
    HHASH hASNs;                    // Hash key: certificate SKI; value: string of asns
    HHASH hV4s;                     // Hash key: certificate SKI; value: string of IPv4s
    HHASH hV6s;                     // Hash key: certificate SKI; value: string of IPv6s
    HHASH hStaleMFTs;               // Hash key: certificate AKI; value: int 1 - mft in stale (corresponding ROAs and other files with the same AKI are also considered 'stale')
    HHASH hHostnames;               // Cache of valid hostnames. Hash key: hostname; value: 1 - valid; 2 - invalid
} *HSESSION;

void hex_encode (unsigned char *lpcAsc, unsigned char *lpcBcd, size_t szBcd);

void print_cert(HSESSION hSession, const struct cert *p);
void print_crl(HSESSION hSession, X509_CRL *p);
void print_mft(HSESSION hSession, const struct mft *p);
void print_roa(HSESSION hSession, const struct roa *p);
void print_tal(HSESSION hSession, const struct tal *p);

void sessionInit (HSESSION hSession);
int sessionFree (HSESSION hSession, int iRtn);

struct tal	*tal_parse_from_file(const char *fn);

void jsMonitor(HSESSION hSession);
void txtDump(HSESSION hSession);

#endif
