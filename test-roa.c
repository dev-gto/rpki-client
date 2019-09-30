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

#include <assert.h>
#include <err.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include "extern.h"
#include "test-core.h"

int	verbose;

static void
roa_print(const struct roa *p)
{
	char	 buf[128];
	size_t	 i;
	char caNotAfter[64], caNotBefore[64], caNow[64];
	time_t now;
	struct tm *tm;

	assert(p != NULL);

    now = time(NULL);
	tm = gmtime(&now);
	strftime(caNow, sizeof(caNow)-1, "%Y-%m-%d %H:%M:%S GMT", tm);

	tm = gmtime(&p->notBefore);
	strftime(caNotBefore, sizeof(caNotBefore)-1, "%Y-%m-%d %H:%M:%S GMT", tm);

	tm = gmtime(&p->notAfter);
	strftime(caNotAfter, sizeof(caNotAfter)-1, "%Y-%m-%d %H:%M:%S GMT", tm);

	printf("%*.*s: %s\n", TAB, TAB, "Now", caNow);
	print_sep_line("EE Certificate", 110);
	printf("%*.*s: %s\n", TAB, TAB, "Not Before", caNotBefore);
	printf("%*.*s: %s\n", TAB, TAB, "Not After", caNotAfter);
	printf("%*.*s: %s\n", TAB, TAB, "Subject key identifier", p->ski);
	printf("%*.*s: %s\n", TAB, TAB, "Authority key identifier", p->aki);
	print_sep_line("ROA", 110);
	printf("%*.*s: %" PRIu32 "\n", TAB, TAB, "asID", p->asid);
	for (i = 0; i < p->ipsz; i++) {
		ip_addr_print(&p->ips[i].addr,
			p->ips[i].afi, buf, sizeof(buf));
		printf("%*zu: %s (max: %zu)\n", TAB, i + 1,
			buf, p->ips[i].maxlength);
	}
}

int
main(int argc, char *argv[])
{
	int		 c;
	size_t		 i;
	X509		*xp = NULL;
	struct roa	*p;

	SSL_library_init();
	SSL_load_error_strings();

	while ((c = getopt(argc, argv, "v")) != -1)
		switch (c) {
		case 'v':
			verbose++;
			break;
		default:
			return EXIT_FAILURE;
		}

	argv += optind;
	argc -= optind;

	for (i = 0; i < (size_t)argc; i++) {
		if ((p = roa_parse(&xp, argv[i], NULL)) == NULL)
			break;
		if (verbose)
			roa_print(p);
		roa_free(p);
		X509_free(xp);
	}

	EVP_cleanup();
	CRYPTO_cleanup_all_ex_data();
	ERR_remove_state(0);
	ERR_free_strings();
	return i < (size_t)argc ? EXIT_FAILURE : EXIT_SUCCESS;
}
