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


static int decode_data(ASN1_TYPE n, gnutls_datum_t *r)
{
	ASN1_DATA_NODE d;
	int len, lenlen;

	if (!n)
		return -EINVAL;

	if (asn1_read_node_value(n, &d) != ASN1_SUCCESS)
		return -EINVAL;

	len = asn1_get_length_der(d.value, d.value_len, &lenlen);
	if (len < 0)
		return -EINVAL;

	r->data = (unsigned char *)d.value + lenlen;
	r->size = len;

	return 0;
}

int load_tpm2_key(struct openconnect_info *vpninfo, gnutls_datum_t *fdata,
		  gnutls_privkey_t *pkey, gnutls_datum_t *pkey_sig)
{
	gnutls_datum_t asn1, pubdata, privdata;
	ASN1_TYPE tpmkey_def = ASN1_TYPE_EMPTY, tpmkey = ASN1_TYPE_EMPTY;
	char value_buf[16];
	int value_buflen;
	int emptyauth = 0;
	unsigned int parent;
	int err, ret = -EINVAL;

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
	if (!asn1_read_value(tpmkey, "emptyAuth", value_buf, &value_buflen) &&
	    !strcmp(value_buf, "TRUE"))
		emptyauth = 1;

	memset(value_buf, 0, 4);
	value_buflen = 4;
	err = asn1_read_value(tpmkey, "parent", value_buf, &value_buflen);
	if (err == ASN1_ELEMENT_NOT_FOUND)
		parent = 0x40000001; // RH_OWNER
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

	if (decode_data(asn1_find_node(tpmkey, "pubkey"), &pubdata) < 0) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to parse TPM2 pubkey element\n"));
		goto out_tpmkey;
	}
	if (decode_data(asn1_find_node(tpmkey, "privkey"), &privdata) < 0) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to parse TPM2 privkey element\n"));
		goto out_tpmkey;
	}

	vpn_progress(vpninfo, PRG_DEBUG,
		     _("Parsed TPM2 key with parent %x, emptyauth %d\n"),
		     parent, emptyauth);

	/* Now we've extracted what we need from the ASN.1, invoke the
	 * actual TPM2 code (whichever implementation we end up with */
	ret = install_tpm2_key(vpninfo, pkey, pkey_sig, parent, emptyauth, &privdata, &pubdata);

 out_tpmkey:
	asn1_delete_structure(&tpmkey);
	asn1_delete_structure(&tpmkey_def);
 out_asn1:
	free(asn1.data);
	return ret;
}

#if GNUTLS_VERSION_NUMBER < 0x030600
static void append_bignum(struct oc_text_buf *sig_der, const gnutls_datum_t *d)
{
	unsigned char derlen[2];

	buf_append_bytes(sig_der, "\x02", 1); // INTEGER
	derlen[0] = d->size;
	/* If it might be interpreted as negative, prepend a zero */
	if (d->data[0] >= 0x80) {
		derlen[0]++;
		derlen[1] = 0;
		buf_append_bytes(sig_der, derlen, 2);
	} else {
		buf_append_bytes(sig_der, derlen, 1);
	}
	buf_append_bytes(sig_der, d->data, d->size);
}

int oc_gnutls_encode_rs_value(gnutls_datum_t *sig, const gnutls_datum_t *sig_r,
			      const gnutls_datum_t *sig_s)
{
	struct oc_text_buf *sig_der = NULL;
	/*
	 * Create the DER-encoded SEQUENCE containing R and S:
	 *
	 *	DSASignatureValue ::= SEQUENCE {
	 *	  r                   INTEGER,
	 *	  s                   INTEGER
	 *	}
	 */

	sig_der = buf_alloc();
	buf_append_bytes(sig_der, "\x30\x80", 2); // SEQUENCE, indeterminate length

	append_bignum(sig_der, sig_r);
	append_bignum(sig_der, sig_s);

	/* If the length actually fits in one byte (which it should), do
	 * it that way.  Else, leave it indeterminate and add two
	 * end-of-contents octets to mark the end of the SEQUENCE. */
	if (!buf_error(sig_der) && sig_der->pos <= 0x80)
		sig_der->data[1] = sig_der->pos - 2;
	else {
		buf_append_bytes(sig_der, "\0\0", 2);
		if (buf_error(sig_der))
			goto out;
	}

	sig->data = (void *)sig_der->data;
	sig->size = sig_der->pos;
	sig_der->data = NULL;
 out:
	return buf_free(sig_der);
}
#endif /* GnuTLS < 3.6.0 */

#endif /* HAVE_TSS2 */
