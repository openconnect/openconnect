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

#ifndef __OPENCONNECT_GNUTLS_H__
#define __OPENCONNECT_GNUTLS_H__

#include <gnutls/gnutls.h>
#include <gnutls/pkcs12.h>
#include <gnutls/abstract.h>

#include "openconnect-internal.h"

int load_tpm1_key(struct openconnect_info *vpninfo, gnutls_datum_t *fdata,
		  gnutls_privkey_t *pkey, gnutls_datum_t *pkey_sig);
void release_tpm1_ctx(struct openconnect_info *info);

int load_tpm2_key(struct openconnect_info *vpninfo, gnutls_datum_t *fdata,
		 gnutls_privkey_t *pkey, gnutls_datum_t *pkey_sig);
void release_tpm2_ctx(struct openconnect_info *info);
int install_tpm2_key(struct openconnect_info *vpninfo, gnutls_privkey_t *pkey, gnutls_datum_t *pkey_sig,
		     unsigned int parent, int emptyauth, gnutls_datum_t *privdata, gnutls_datum_t *pubdata);

/* GnuTLS 3.6.0+ provides this. We have our own for older GnuTLS. There is
 * also _gnutls_encode_ber_rs_raw() in some older versions, but there were
 * zero-padding bugs in that, and some of the... less diligently maintained
 * distributions (like Ubuntu even in 18.04) don't have the fix yet, two
 * years later. */
#if GNUTLS_VERSION_NUMBER < 0x030600
#define gnutls_encode_rs_value oc_gnutls_encode_rs_value
int oc_gnutls_encode_rs_value(gnutls_datum_t *sig_value, const gnutls_datum_t *r, const gnutls_datum_t *s);
#endif

char *get_gnutls_cipher(gnutls_session_t session);

#endif /* __OPENCONNECT_GNUTLS_H__ */
