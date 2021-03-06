/*	$OpenBSD: output-json.c,v 1.6 2019/12/04 23:03:05 benno Exp $ */
/*
 * Copyright (c) 2019 Claudio Jeker <claudio@openbsd.org>
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

#include <stdint.h>
#include <stdlib.h>
#include <openssl/ssl.h>

#include "extern.h"

int
output_json(FILE *out, struct vrp_tree *vrps, void *arg)
{
	char		 buf[64];
	struct vrp	*v;
	int		 first = 1;

	if (fprintf(out, "{\n\t\"roas\": [\n") < 0)
		return -1;

	RB_FOREACH(v, vrp_tree, vrps) {
		if (first)
			first = 0;
		else {
			if (fprintf(out, ",\n") < 0)
				return -1;
		}

		ip_addr_print(&v->addr, v->afi, buf, sizeof(buf));

		if (fprintf(out, "\t\t{ \"asn\": \"AS%u\", \"prefix\": \"%s\", "
		    "\"maxLength\": %u, \"ta\": \"%s\" }",
		    v->asid, buf, v->maxlength, v->tal) < 0)
			return -1;
	}

	if (fprintf(out, "\n\t]\n}\n") < 0)
		return -1;
	return 0;
}
