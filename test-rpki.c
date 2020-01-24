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
#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <sys/stat.h>

#include "extern.h"
#include "test-core.h"

#define APP_NAME "test-rpki"
#define APP_VERSION "1.0.0.0"

#define STS_OK                       0
#define STS_ERROR_MISSING_PARAMS     1
#define STS_ERROR_NO_INPUT_FILES     2
#define STS_ERROR_INVALID_DIRECTORY  3

static void usage(int iSts) {
    printf("%s %s - dump information from .cer, .crl, .mft, .roa and .tal files.\n", APP_NAME, APP_VERSION);
	switch (iSts) {
		case STS_ERROR_MISSING_PARAMS:
			printf("Missing parameters.\n");
			break;
		case STS_ERROR_NO_INPUT_FILES:
			printf("No input files.\n");
			break;
		case STS_ERROR_INVALID_DIRECTORY:
			printf("Invalid directory.\n");
			break;
		default:
			printf("Invalid option.\n");
	}
    printf("Usage: %s [options] <files>\n\n"
           "  -h, --help                     Displays this help text.\n"
           "  -r, --recursive                Recursive. Follows internal file references.\n"
		   "  -f <format>                    Format output"
		   "                                    TEXT    - default\n"
		   "                                    MONITOR - JSON format containing only\n"
		   "  --local-repository <directory> Directory where the repository local cache will be read"
		   , APP_NAME
		   );
}

static int loadArguments(HSESSION hSession, int argc, char *argv [ ]) {
	int iargv;
	int iSts;
	int iShowUsage;
	char *lpcValue;
	struct stat st;

	iSts = STS_OK;
	iShowUsage = 0;
	for (iargv = 1; (iargv < argc); iargv++)
	{
		if (argv[iargv][0] != '-')
		{
			// Check if is a valid file
			if (stat (argv[iargv], &st) == 0) {
				if (S_ISREG(st.st_mode) || S_ISLNK(st.st_mode)) {
					FileEntry *entry;
					entry = FileEntry_new();
					entry->lpcFilename = strdup(argv[iargv]);
					sk_FileEntry_push(hSession->filenames, entry);
				}
			}
			continue;
		}
		if (strcmp (argv[iargv], "-h") == 0 || strcmp (argv[iargv], "--help") == 0)
		{
			iShowUsage = 1;
			break;
		}
		if (strcmp (argv[iargv], "-r") == 0 || strcmp (argv[iargv], "--recursive") == 0)
		{
			hSession->iOptRecursive = 1;
			continue;
		}

		if (memcmp (argv[iargv], "-f", 2) == 0)
		{
			lpcValue = &argv[iargv][2];
			if (!*lpcValue)
				lpcValue = argv[++iargv];
			if (lpcValue != NULL && strcmp (lpcValue, "MONITOR") == 0) {
				hSession->iOptOutput = OPT_OUTPUT_JS_MONITOR;
				hSession->iOptRecursive = 1;
				log_set_silent(1);
			}
			continue;
		}		
		if (memcmp (argv[iargv], "--local-repository", 18) == 0)
		{
			lpcValue = &argv[iargv][18];
			if (!*lpcValue)
				lpcValue = argv[++iargv];
			if (lpcValue != NULL) {
				if (stat (lpcValue, &st) == 0 && S_ISDIR(st.st_mode)) {
					hSession->lpcLocalRepository = lpcValue;
				}
				else {
					iSts = STS_ERROR_INVALID_DIRECTORY;
					break;
				}
			}

			continue;
		}
	}
	if (iSts == STS_OK) {
		if (sk_FileEntry_num(hSession->filenames) <= 0) {
			iSts = STS_ERROR_NO_INPUT_FILES;
		}
	}

	if (iShowUsage || iSts) {
		usage(iSts);
	}
	return iSts;
}

int main(int argc, char *argv[])
{
	struct Session sSession;
	HSESSION hSession = &sSession;

	sessionInit (hSession);

	if (loadArguments(hSession, argc, argv) != 0)
		return sessionFree(hSession, 4);

	if (hSession->iOptOutput == OPT_OUTPUT_JS_MONITOR) {
		jsMonitor(hSession);
	}
	else {
		txtDump(hSession);
	}

	return sessionFree (hSession, EXIT_SUCCESS);
}
