/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Copyright © 2018 David Woodhouse.
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

#include "config.h"

#include "openconnect-internal.h"
#include "gnutls.h"

#include <stdio.h>
#include <string.h>

#define TSSINCLUDE(x) < HAVE_TSS2/x >
#include TSSINCLUDE(tss.h)

struct oc_tpm2_ctx {
	TPM2B_PUBLIC pub;
	TPM2B_PRIVATE priv;
	TPM2B_DIGEST userauth;
	TPM2B_DIGEST ownerauth;
	unsigned int need_userauth:1;
	unsigned int need_ownerauth:1;
};

int tpm2_rsa_sign_hash_fn(gnutls_privkey_t key, gnutls_sign_algorithm_t algo,
			  void *_vpninfo, unsigned int flags,
			  const gnutls_datum_t *data, gnutls_datum_t *sig)
{
	return GNUTLS_E_PK_SIGN_FAILED;
}

int tpm2_ec_sign_hash_fn(gnutls_privkey_t key, gnutls_sign_algorithm_t algo,
			 void *_vpninfo, unsigned int flags,
			 const gnutls_datum_t *data, gnutls_datum_t *sig)
{
	return GNUTLS_E_PK_SIGN_FAILED;
}

int install_tpm2_key(struct openconnect_info *vpninfo, gnutls_privkey_t *pkey, gnutls_datum_t *pkey_sig,
		     unsigned int parent, int emptyauth, gnutls_datum_t *privdata, gnutls_datum_t *pubdata)
{
	vpn_progress(vpninfo, PRG_ERR,
		     _("TPM2 support via IBM TSS not yet implemented\n"));

	return -EINVAL;
}


void release_tpm2_ctx(struct openconnect_info *vpninfo)
{
	if (vpninfo->tpm2)
		free(vpninfo->tpm2);
	vpninfo->tpm2 = NULL;
}
