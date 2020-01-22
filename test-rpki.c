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

static void usage(int iInvalidOption) {
    printf("%s %s - dump information from .cer, .crl, .mft, .roa and .tal files.\n", APP_NAME, APP_VERSION);
    if (iInvalidOption)
      printf("Invalid option.\n");
    printf("Usage: %s [options] <files>\n\n"
           "  -h, --help  Displays this help text.\n"
           "  -r          Recursive. Follows internal file references.\n"
		   , APP_NAME
		   );
}

static int loadArguments(HSESSION hSession, int argc, char *argv [ ]) {
	int iargv;
	int iInvalidOption;
	int iShowUsage;
	struct stat st;

	iInvalidOption = 0;
	iShowUsage = 0;
	for (iargv = 1; (iargv < argc); iargv++)
	{
		if (argv[iargv][0] != '-')
		{
			// Check if is a valid file
			if (stat (argv[iargv], &st) == 0) {
				if (S_ISREG(st.st_mode) || S_ISLNK(st.st_mode)) {
					FILEENTRY *entry;
					entry = FILEENTRY_new();
					entry->filename = strdup(argv[iargv]);
					sk_FILEENTRY_push(hSession->filenames, entry);
				}
			}
			continue;
		}
		if (strcmp (argv[iargv], "-h") == 0 || strcmp (argv[iargv], "--help") == 0)
		{
			iShowUsage = 1;
			break;
		}
	}

	if (sk_FILEENTRY_num(hSession->filenames) <= 0) {
		iShowUsage = 1;
	}

	if (iShowUsage || iInvalidOption) {
		usage(iInvalidOption);
	}
	return iInvalidOption;
}

static void processFile(HSESSION hSession, char *filename) {
	size_t		 sz;
	struct cert	*cert;
	struct mft	*mft;
	struct roa	*roa;
	struct tal	*tal;
	X509_CRL	*crl;
	X509		*xp = NULL;

	sz = strlen(filename);
	printf("Processing [%s]:\n", filename);
	if (strcasecmp(filename + sz - 4, ".mft") == 0) {
		if ((mft = mft_parse(&xp, filename, 1)) != NULL) {
			print_mft(mft);
			mft_free(mft);
		}
	}
	else if (strcasecmp(filename + sz - 4, ".roa") == 0) {
		if ((roa = roa_parse(&xp, filename, NULL)) != NULL) {
			print_roa(roa);
			roa_free(roa);
		}
	}
	else if (strcasecmp(filename + sz - 4, ".crl") == 0) {
		if ((crl = crl_parse(filename, NULL)) != NULL) {
			print_crl(crl);
			X509_CRL_free(crl);
		}
	}
	else if (strcasecmp(filename + sz - 4, ".tal") == 0) {
		if ((tal = tal_parse_from_file(filename)) != NULL) {
			print_tal(tal);
			tal_free(tal);
		}
	}
	else {
		log_set_silent(1);
		// Try checking a TA cert
		cert = ta_parse(&xp, filename, NULL, 0);
		log_set_silent(0);
		if (cert != NULL) {
			print_cert(cert);
			cert_free(cert);
		} else {
			log_set_silent(1);
			cert = cert_parse(&xp, filename, NULL);
			log_set_silent(0);
			if (cert != NULL) {
				print_cert(cert);
				cert_free(cert);
			}
			else {
				log_set_silent(1);
				// Try checking a TAL
				tal = tal_parse_from_file(filename);
				log_set_silent(0);
				if (tal != NULL) {
					print_tal(tal);
					tal_free(tal);
				}
				else {
					log_warnx("Unrecognized file [%s]", filename);
				}
			}
		}
	}

	if (xp != NULL) {
		X509_free(xp);
		xp = NULL;
	}
}

int
main(int argc, char *argv[])
{
	struct Session sSession;
	HSESSION hSession = &sSession;

	sessionInit (hSession);

	if (loadArguments(hSession, argc, argv) != 0)
		return sessionFree(hSession, 4);

	while (sk_FILEENTRY_num(hSession->filenames) > 0) {
		FILEENTRY *t = sk_FILEENTRY_value(hSession->filenames, 0);
		processFile(hSession, t->filename);
		sk_FILEENTRY_delete(hSession->filenames, 0);
		FILEENTRY_free(t);
	}

	return sessionFree (hSession, EXIT_SUCCESS);
}
