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

#include <config.h>

#include <errno.h>
#include <string.h>

#include <gnutls/gnutls.h>
#include "openconnect-internal.h"
#include <libtasn1.h>
#include "gnutls.h"

#ifdef HAVE_TSS2
#define TSSINCLUDE(x) < HAVE_TSS2/x >
#include TSSINCLUDE(tss.h)

struct oc_tpm2_ctx {
};
#include <libtasn1.h>

const asn1_static_node tpmkey_asn1_tab[] = {
  { "TPMKey", 536875024, NULL },
  { NULL, 1073741836, NULL },
  { "TPMKey", 536870917, NULL },
  { "type", 1073741836, NULL },
  { "emptyAuth", 1610637316, NULL },
  { NULL, 2056, "0"},
  { "parent", 1610637315, NULL },
  { NULL, 2056, "1"},
  { "pubkey", 1610637319, NULL },
  { NULL, 2056, "2"},
  { "privkey", 7, NULL },
  { NULL, 0, NULL }
};

int load_tpm2_key(struct openconnect_info *vpninfo, gnutls_datum_t *fdata,
		  gnutls_privkey_t *pkey, gnutls_datum_t *pkey_sig)
{
	gnutls_datum_t asn1;
	int err;
	ASN1_TYPE tpmkey_def = ASN1_TYPE_EMPTY, tpmkey = ASN1_TYPE_EMPTY;
	char value_buf[16];
	int value_buflen;
	int emptyauth = 0;
	unsigned int parent;

	err = gnutls_pem_base64_decode_alloc("TSS2 KEY BLOB", fdata, &asn1);
	if (err) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Error decoding TSS2 key blob: %s\n"),
			     gnutls_strerror(err));
		return -EINVAL;
	}

	err = asn1_array2tree(tpmkey_asn1_tab, &tpmkey_def, NULL);
	if (err != ASN1_SUCCESS) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to create ASN.1 type for TPM2: %s\n"),
			     asn1_strerror(err));
		goto out_asn1;
	}

	asn1_create_element(tpmkey_def, "TPMKey.TPMKey", &tpmkey);
	err = asn1_der_decoding(&tpmkey, asn1.data, asn1.size, NULL);
	if (err != ASN1_SUCCESS) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to decode TPM2 key ASN.1: %s\n"),
			     asn1_strerror(err));
		goto out_tpmkey;
	}
	asn1_print_structure(stdout, tpmkey, "", ASN1_PRINT_ALL);

	value_buflen = sizeof(value_buf);
	err = asn1_read_value(tpmkey, "type", value_buf, &value_buflen);
	if (err != ASN1_SUCCESS) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to identify type of TPM2 key: %s\n"),
			     asn1_strerror(err));
		goto out_tpmkey;
	}
	if (strcmp(value_buf, "2.23.133.10.2")) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Unsupported TPM2 key OID: %s\n"),
			     value_buf);
		goto out_tpmkey;
	}

	value_buflen = sizeof(value_buf);
	if (!asn1_read_value(tpmkey, "emptyAuth", value_buf, &value_buflen) ||
	    !strcmp(value_buf, "TRUE"))
		emptyauth = 1;

	memset(value_buf, 0, 4);
	value_buflen = 4;
	err = asn1_read_value(tpmkey, "parent", value_buf, &value_buflen);
	if (err == ASN1_ELEMENT_NOT_FOUND)
		parent = TPM_RH_OWNER;
	else if (err != ASN1_SUCCESS) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to parse TPM2 key parent: %s\n"),
			     asn1_strerror(err));
		goto out_tpmkey;
	} else {
		int i;
		parent = 0;

		for (i = 0; i < value_buflen; i++)
			parent |= value_buf[value_buflen - i - 1] << (8 * i);
	}
	vpn_progress(vpninfo, PRG_DEBUG,
		     _("Parsed TPM2 key with parent %x, emptyauth %d\n"),
		     parent, emptyauth);

	vpn_progress(vpninfo, PRG_ERR,
		     _("TPM2 not really implemented yet\n"));

 out_tpmkey:
	asn1_delete_structure(&tpmkey);
	asn1_delete_structure(&tpmkey_def);
 out_asn1:
	free(asn1.data);
	return -EINVAL;
}

void release_tpm2_ctx(struct openconnect_info *vpninfo)
{
	if (vpninfo->tpm2)
		free(vpninfo->tpm2);
	vpninfo->tpm2 = NULL;
}
#endif /* HAVE_TSS2 */
