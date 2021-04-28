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
#define STS_ERROR_INVALID_PARAMETER  4

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
           "  -q, --quiet                    Quiet mode, do not output warning messages.\n"
           "  -r, --recursive                Recursive. Follows internal file references.\n"
		   "  -f <format>                    Format output\n"
		   "                                    TEXT    - text default output of parsed files\n"
		   "                                    JSON    - JSON output of parsed files\n"
		   "                                    MONITOR - JSON error report\n"
           "  -s, --about-to-stale <seconds> Also consider objets about to become stale in <seconds>.\n"
           "                                 Default: 0 (disabled)\n"
		   "  --local-repository <directory> Directory where the repository local cache will be read.\n"
		   "  --check-cert-dir <directory>   Base directory to scan for missing certificates.\n"
		   "\n"
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
					sk_OPENSSL_STRING_push(hSession->filenames, strdup(argv[iargv]));
				}
			}
			continue;
		}
		if (strcmp (argv[iargv], "-h") == 0 || strcmp (argv[iargv], "--help") == 0)
		{
			iShowUsage = 1;
			break;
		}
		if (strcmp (argv[iargv], "-q") == 0 || strcmp (argv[iargv], "--quiet") == 0)
		{
			log_set_silent(1);
			continue;
		}
		if (strcmp (argv[iargv], "-r") == 0 || strcmp (argv[iargv], "--recursive") == 0)
		{
			hSession->iOptRecursive = 1;
			continue;
		}
		if (strcmp (argv[iargv], "-s") == 0 || strcmp (argv[iargv], "--about-to-stale") == 0)
		{
			lpcValue = &argv[iargv][2];
			if (!*lpcValue)
				lpcValue = argv[++iargv];
			if (lpcValue != NULL) {
				hSession->iOptAboutToStaleSeconds = atoi(lpcValue);
				if (hSession->iOptAboutToStaleSeconds > 0) {
					continue;
				}
			}
			iSts = STS_ERROR_INVALID_PARAMETER;
			break;
		}

		if (memcmp (argv[iargv], "-f", 2) == 0)
		{
			lpcValue = &argv[iargv][2];
			if (!*lpcValue)
				lpcValue = argv[++iargv];
			if (lpcValue != NULL && strcasecmp (lpcValue, "MONITOR") == 0) {
				hSession->iOptOutput = OPT_OUTPUT_JS_MONITOR;
				hSession->iOptRecursive = 1;
				log_set_silent(1);
			}
			if (lpcValue != NULL && strcasecmp (lpcValue, "JSON") == 0) {
				hSession->iOptOutput = OPT_OUTPUT_JSON;
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
		if (memcmp (argv[iargv], "--check-cert-dir", 16) == 0)
		{
			lpcValue = &argv[iargv][16];
			if (!*lpcValue)
				lpcValue = argv[++iargv];
			if (lpcValue != NULL) {
				if (stat (lpcValue, &st) == 0 && S_ISDIR(st.st_mode)) {
					hSession->lpcCheckCertDirectory = lpcValue;
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
		if (sk_OPENSSL_STRING_num(hSession->filenames) <= 0) {
			iSts = STS_ERROR_NO_INPUT_FILES;
		}
	}

	if (iShowUsage || iSts) {
		usage(iSts);
		// Any error code is enough to exit
		iSts = STS_ERROR_MISSING_PARAMS;
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

	sessionRun(hSession);

	return sessionFree (hSession, EXIT_SUCCESS);
}
