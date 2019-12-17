/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Copyright © 2019 David Woodhouse
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

#include <config.h>

#include <stdint.h>
#include <stdio.h>

#define __OPENCONNECT_INTERNAL_H__

#define vpn_progress(v, d, ...) printf(__VA_ARGS__)
#define _(x) x

struct openconnect_info {
	char *ifname;
};

#define __LIST_TAPS__

#include "../tun-win32.c"

static intptr_t print_tun(struct openconnect_info *vpninfo, char *guid, wchar_t *wname)
{
	printf("Found tun device '%S'\n", wname);
	return 0;
}

int main(void)
{
	search_taps(NULL, print_tun, 1);
	return 0;
}
