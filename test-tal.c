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

#include "extern.h"
#include "test-core.h"

int	verbose;

int
main(int argc, char *argv[])
{
	int		 c;
	struct tal	*tal;
	size_t		 i;

	SSL_library_init();
	SSL_load_error_strings();

	while (-1 != (c = getopt(argc, argv, "v")))
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
		if ((tal = tal_parse(argv[i])) == NULL)
			break;
		if (verbose)
			print_tal(tal);
		tal_free(tal);
	}

	EVP_cleanup();
	CRYPTO_cleanup_all_ex_data();
	ERR_remove_thread_state(NULL);
	ERR_free_strings();
	return i < (size_t)argc ? EXIT_FAILURE : EXIT_SUCCESS;
}
