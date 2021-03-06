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
#define OPT_OUTPUT_JSON 1
#define OPT_OUTPUT_JS_MONITOR 2

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
    int iOptAboutToStaleSeconds;    // >0 - should verify objects about to become stale in iOptAboutToStaleSeconds.
    int iNumErrorsFound;
    int iStage;                     // 0 - first pass, normal stage; 1 - second pass, processing missing certificates
    char *lpcLocalRepository;       // Base directory for using with iOptRecursive
    char *lpcCheckCertDirectory;    // Base directory for checking missing crt (optional)
    char *lpcCurrentFilename;       // Current file being processed
	STACK_OF(OPENSSL_STRING) *filenames; // List of filenames to process (index zero record to be processed first)
    HHASH hCertFilenames;           // Hash key: certificate SKI; value: corresponding filename
    HHASH hCertSerialNumbers;       // Hash key: certificate SKI; value: corresponding serial number
    HHASH hASNs;                    // Hash key: certificate SKI; value: string of asns
    HHASH hV4s;                     // Hash key: certificate SKI; value: string of IPv4s
    HHASH hV6s;                     // Hash key: certificate SKI; value: string of IPv6s
    HHASH hStaleMFTs;               // Hash key: certificate AKI; value: int 1 - mft in stale (corresponding ROAs and other files with the same AKI are also considered 'stale')
    HHASH hHostnames;               // Cache of valid hostnames. Hash key: hostname; value: 1 - valid; 2 - invalid
    HHASH hProcessed;               // Hash key: filename; value: 1 - processed
} *HSESSION;

void sessionInit (HSESSION hSession);
int sessionFree (HSESSION hSession, int iRtn);
int sessionRun (HSESSION hSession);

#endif
