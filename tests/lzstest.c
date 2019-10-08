/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Copyright © 2008-2015 Intel Corporation.
 *
 * Author: David Woodhouse <dwmw2@infradead.org>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * version 2.1, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 */

#define __OPENCONNECT_INTERNAL_H__

struct oc_packed_uint16_t {
	unsigned short d;
} __attribute__((packed));

int lzs_decompress(unsigned char *dst, int dstlen, const unsigned char *src, int srclen);
int lzs_compress(unsigned char *dst, int dstlen, const unsigned char *src, int srclen);

#include "../lzs.c"

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#define NR_PKTS 2048
#define MAX_PKT 65536

/*
 * Compressed data can encode an 11-bit offset of zero, which is invalid.
 * 10 00000000000 00   110000000
 * Compr offset  len   end marker
 *
 * In bytes:
 * 1000.0000 0000.0001 1000.0000
 */
static const unsigned char zero_ofs[] = { 0x80, 0x01, 0x80 };

int main(void)
{
	int i, j, ret;
	int pktlen;
	unsigned char pktbuf[MAX_PKT + 3];
	unsigned char comprbuf[MAX_PKT * 9 / 8 + 2];
	unsigned char uncomprbuf[MAX_PKT];

	srand(0xdeadbeef);

	uncomprbuf[0] = 0x5a;
	uncomprbuf[1] = 0xa5;

	ret = lzs_decompress(uncomprbuf, 3, zero_ofs, sizeof(zero_ofs));
	if (ret != -EINVAL) {
		fprintf(stderr, "Decompressing zero-offset should have failed -EINVAL: %d, bytes %08x %08x\n",
			ret, uncomprbuf[0], uncomprbuf[1]);
		exit(1);
	}

	for (i = 0; i < NR_PKTS; i++) {
		if (i)
			pktlen = (rand() % MAX_PKT) + 1;
		else
			pktlen = MAX_PKT;

		for (j = 0; j < pktlen; j++)
			pktbuf[j] = rand();

		ret = lzs_compress(comprbuf, sizeof(comprbuf), pktbuf, pktlen);
		if (ret < 0) {
			fprintf(stderr, "Compressing packet %d failed: %s\n", i, strerror(-ret));
			exit(1);
		}
		ret = lzs_decompress(uncomprbuf, pktlen, comprbuf, sizeof(comprbuf));
		if (ret != pktlen) {
			fprintf(stderr, "Compressing packet %d failed\n", i);
			exit(1);
		}
		if (memcmp(uncomprbuf, pktbuf, pktlen)) {
			fprintf(stderr, "Comparing packet %d failed\n", i);
			exit(1);
		}
	}

	return 0;
}
