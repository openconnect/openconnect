/*******************************************************************************
 * Copyright 2017-2018, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * 3. Neither the name of tpm2-tss-engine nor the names of its contributors
 * may be used to endorse or promote products derived from this software
 * without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 ******************************************************************************/

#include "config.h"

#include "openconnect-internal.h"
#include "gnutls.h"

#ifdef HAVE_TSS2

#include <stdio.h>
#include <string.h>

#include <tss2/tss2_mu.h>
#include <tss2/tss2_esys.h>

struct oc_tpm2_ctx {
	TPM2B_PUBLIC pub;
	TPM2B_PRIVATE priv;
	TPM2B_DIGEST userauth;
	TPM2B_DIGEST ownerauth;
	unsigned int need_userauth:1;
	unsigned int need_ownerauth:1;
};

static TPM2B_PUBLIC primaryTemplate = {
	.publicArea = {
		.type = TPM2_ALG_ECC,
		.nameAlg = TPM2_ALG_SHA256,
		.objectAttributes = (TPMA_OBJECT_USERWITHAUTH |
				     TPMA_OBJECT_RESTRICTED |
				     TPMA_OBJECT_DECRYPT |
				     TPMA_OBJECT_NODA |
				     TPMA_OBJECT_SENSITIVEDATAORIGIN),
		.authPolicy = {
			.size = 0,
		},
		.parameters.eccDetail = {
			.symmetric = {
				.algorithm = TPM2_ALG_AES,
				.keyBits.aes = 128,
				.mode.aes = TPM2_ALG_CFB,
			},
			.scheme = {
				.scheme = TPM2_ALG_NULL,
				.details = {}
			},
			.curveID = TPM2_ECC_NIST_P256,
			.kdf = {
				.scheme = TPM2_ALG_NULL,
				.details = {}
			},
		},
		.unique.ecc = {
			.x.size = 0,
			.y.size = 0
		}
	}
};

static TPM2B_SENSITIVE_CREATE primarySensitive = {
	.sensitive = {
		.userAuth = {
			.size = 0,
		},
		.data = {
			.size = 0,
		}
	}
};
static TPM2B_DATA allOutsideInfo = {
	.size = 0,
};
static TPML_PCR_SELECTION allCreationPCR = {
	.count = 0,
};


/** Initialize the ESYS TPM connection and primary key
 *
 * Establish a connection with the TPM using ESYS libraries and create a primary
 * key under the owner hierarchy.
 * @param ctx The resulting ESYS context.
 * @param primaryHandle The resulting handle for the primary key.
 * @retval TSS2_RC_SUCCESS on success
 * @retval TSS2_RCs according to the error
 */
static int init_tpm2_primary(struct openconnect_info *vpninfo,
			     ESYS_CONTEXT **ctx, ESYS_TR *primaryHandle)
{
	TSS2_RC r;
	*primaryHandle = ESYS_TR_NONE;

	vpn_progress(vpninfo, PRG_DEBUG,
		     _("Establishing connection with TPM.\n"));

	r = Esys_Initialize(ctx, NULL, NULL);
	if (r) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("TPM2 Esys_Initialize failed: 0x%x\n"),
			     r);
		goto error;
	}

	r = Esys_Startup(*ctx, TPM2_SU_CLEAR);
	if (r == TPM2_RC_INITIALIZE) {
		vpn_progress(vpninfo, PRG_DEBUG,
			     _("TPM2 was already started up thus false positive failing in tpm2tss log.\n"));
	} else if (r) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("TPM2 Esys_Startup failed: 0x%x\n"),
			     r);
		goto error;
	}

	vpn_progress(vpninfo, PRG_DEBUG, _("Creating primary key under owner.\n"));
 reauth:
	if (vpninfo->tpm2->need_ownerauth) {
		char *pass = NULL;
		int err = request_passphrase(vpninfo, "openconnect_tpm2_owner",
					     &pass, _("Enter TPM2 owner password:"));
		if (err)
			goto error;

		if (strlen(pass) > sizeof(vpninfo->tpm2->ownerauth.buffer) - 1) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("TPM2 owner password too long; truncating\n"));
			pass[sizeof(vpninfo->tpm2->ownerauth.buffer) - 1] = 0;
		}
		vpninfo->tpm2->ownerauth.size = strlen(pass);
		strcpy((char *)vpninfo->tpm2->ownerauth.buffer, pass);
		memset(pass, 0, strlen(pass));
		free(pass);

		vpninfo->tpm2->need_ownerauth = 0;
	}
	r = Esys_TR_SetAuth(*ctx, ESYS_TR_RH_OWNER, &vpninfo->tpm2->ownerauth);
	if (r) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("TPM2 Esys_TR_SetAuth failed: 0x%x\n"),
			     r);
		goto error;
	}

	r = Esys_CreatePrimary(*ctx, ESYS_TR_RH_OWNER,
			       ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
			       &primarySensitive, &primaryTemplate,
			       &allOutsideInfo, &allCreationPCR,
			       primaryHandle, NULL, NULL, NULL, NULL);
	if (r == 0x000009a2) {
		vpn_progress(vpninfo, PRG_DEBUG,
			     _("TPM2 Esys_CreatePrimary owner auth failed\n"));
		vpninfo->tpm2->need_ownerauth = 1;
		goto reauth;
	} else if (r) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("TPM2 Esys_CreatePrimary failed: 0x%x\n"),
			     r);
		goto error;
	}

	return 0;
 error:
	if (*primaryHandle != ESYS_TR_NONE)
		Esys_FlushContext(*ctx, *primaryHandle);
	*primaryHandle = ESYS_TR_NONE;

	Esys_Finalize(ctx);
	return -EIO;
}

/** Initialize the ESYS TPM connection and load the key
 *
 * Establish a connection with the TPM using ESYS libraries, create a primary
 * key under the owner hierarchy and then load the TPM key and set its auth
 * value.
 * @param ctx The resulting ESYS context.
 * @param keyHandle The resulting handle for the key key.
 * @param tpm2Data The key data, owner auth and key auth to be used
 * @retval TSS2_RC_SUCCESS on success
 * @retval TSS2_RCs according to the error
 */
static int init_tpm2_key(ESYS_CONTEXT **ctx, ESYS_TR *keyHandle,
			 struct openconnect_info *vpninfo)
{
	TSS2_RC r;
	ESYS_TR primaryHandle = ESYS_TR_NONE;
	*keyHandle = ESYS_TR_NONE;

	if (init_tpm2_primary(vpninfo, ctx, &primaryHandle))
		goto error;

	vpn_progress(vpninfo, PRG_DEBUG, _("Loading TPM2 key blob.\n"));

	r = Esys_Load(*ctx, primaryHandle,
		      ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
		      &vpninfo->tpm2->priv, &vpninfo->tpm2->pub,
		      keyHandle);
	if (r) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("TPM2 Esys_Load failed: 0x%x\n"),
			     r);
		goto error;
	}

	r = Esys_FlushContext(*ctx, primaryHandle);
	if (r) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("TPM2 Esys_FlushContext failed: 0x%x\n"),
			     r);
		goto error;
	}
	primaryHandle = ESYS_TR_NONE;

	return 0;
 error:
	if (primaryHandle != ESYS_TR_NONE)
		Esys_FlushContext(*ctx, primaryHandle);
	if (*keyHandle != ESYS_TR_NONE)
		Esys_FlushContext(*ctx, *keyHandle);
	*keyHandle = ESYS_TR_NONE;

	Esys_Finalize(ctx);
	return -EIO;
}

static int auth_tpm2_key(struct openconnect_info *vpninfo, ESYS_CONTEXT *ctx, ESYS_TR key_handle)
{
	TSS2_RC r;

	if (vpninfo->tpm2->need_userauth || vpninfo->cert_password) {
		char *pass = NULL;

		if (vpninfo->cert_password) {
			pass = vpninfo->cert_password;
			vpninfo->cert_password = NULL;
		} else {
			int err = request_passphrase(vpninfo, "openconnect_tpm2_key",
						     &pass, _("Enter TPM2 key password:"));
			if (err)
				return err;
		}
		if (strlen(pass) > sizeof(vpninfo->tpm2->userauth.buffer) - 1) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("TPM2 key password too long; truncating\n"));
			pass[sizeof(vpninfo->tpm2->userauth.buffer) - 1] = 0;
		}
		vpninfo->tpm2->userauth.size = strlen(pass);
		strcpy((char *)vpninfo->tpm2->userauth.buffer, pass);
		memset(pass, 0, strlen(pass));
		free(pass);

		vpninfo->tpm2->need_userauth = 0;
	}

	r = Esys_TR_SetAuth(ctx, key_handle, &vpninfo->tpm2->userauth);
	if (r) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("TPM2 Esys_TR_SetAuth failed: 0x%x\n"),
			     r);
		return -EIO;
	}
	return 0;
}

#define PKCS1_PAD_OVERHEAD 11

/* Signing function for TPM privkeys, set with gnutls_privkey_import_ext() */
static int tpm2_rsa_sign_fn(gnutls_privkey_t key, void *_vpninfo,
			    const gnutls_datum_t *data, gnutls_datum_t *sig)
{
	struct openconnect_info *vpninfo = _vpninfo;
	int ret = GNUTLS_E_PK_SIGN_FAILED;
	ESYS_CONTEXT *ectx = NULL;
	TPM2B_PUBLIC_KEY_RSA digest, *tsig = NULL;
	TPM2B_DATA label = { .size = 0 };
	TPMT_RSA_DECRYPT inScheme = { .scheme = TPM2_ALG_NULL };
	ESYS_TR key_handle = ESYS_TR_NONE;
	TSS2_RC r;

	vpn_progress(vpninfo, PRG_DEBUG,
		     _("TPM2 RSA sign function called for %d bytes.\n"),
		     data->size);

	digest.size = vpninfo->tpm2->pub.publicArea.unique.rsa.size;

	if (data->size + PKCS1_PAD_OVERHEAD > digest.size) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("TPM2 digest too large: %d > %d\n"),
			     data->size, digest.size - PKCS1_PAD_OVERHEAD);
		return GNUTLS_E_PK_SIGN_FAILED;
	}

	/* PKCS#1 padding */
	digest.buffer[0] = 0;
	digest.buffer[1] = 1;
	memset(digest.buffer + 2, 0xff, digest.size - data->size - 3);
	digest.buffer[digest.size - data->size - 1] = 0;
	memcpy(digest.buffer + digest.size - data->size, data->data, data->size);

	if (init_tpm2_key(&ectx, &key_handle, vpninfo))
		goto out;
 reauth:
	if (auth_tpm2_key(vpninfo, ectx, key_handle))
		goto out;

	r = Esys_RSA_Decrypt(ectx, key_handle,
			     ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
			     &digest, &inScheme, &label, &tsig);
	if (r == 0x9a2) {
		vpn_progress(vpninfo, PRG_DEBUG,
			     _("TPM2 Esys_RSA_Decrypt auth failed\n"));
		vpninfo->tpm2->need_userauth = 1;
		goto reauth;
	}
	if (r) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("TPM2 failed to generate RSA signature: 0x%x\n"),
			     r);
		goto out;
	}

	sig->data = malloc(tsig->size);
	if (!sig->data)
		goto out;

	memcpy(sig->data, tsig->buffer, tsig->size);
	sig->size = tsig->size;

	ret = 0;
 out:
	if (tsig)
		free(tsig);

	if (key_handle != ESYS_TR_NONE)
		Esys_FlushContext(ectx, key_handle);

	if (ectx)
		Esys_Finalize(&ectx);

	return ret;
}

/* Signing function for TPM privkeys, set with gnutls_privkey_import_ext() */
static int tpm2_ec_sign_fn(gnutls_privkey_t key, void *_vpninfo,
			   const gnutls_datum_t *data, gnutls_datum_t *sig)
{
	struct openconnect_info *vpninfo = _vpninfo;
	int ret = GNUTLS_E_PK_SIGN_FAILED;
	ESYS_CONTEXT *ectx = NULL;
	TPM2B_DIGEST digest;
	TPMT_SIGNATURE *tsig = NULL;
	ESYS_TR key_handle = ESYS_TR_NONE;
	TSS2_RC r;
	TPMT_TK_HASHCHECK validation = { .tag = TPM2_ST_HASHCHECK,
					 .hierarchy = TPM2_RH_NULL,
					 .digest.size = 0 };
	TPMT_SIG_SCHEME inScheme = { .scheme = TPM2_ALG_ECDSA };
	struct oc_text_buf *sig_der = NULL;
	unsigned char derlen;

	vpn_progress(vpninfo, PRG_DEBUG,
		     _("TPM2 EC sign function called for %d bytes.\n"),
		     data->size);

	switch (data->size) {
	case 20: inScheme.details.ecdsa.hashAlg = TPM2_ALG_SHA1;   break;
	case 32: inScheme.details.ecdsa.hashAlg = TPM2_ALG_SHA256; break;
	case 48: inScheme.details.ecdsa.hashAlg = TPM2_ALG_SHA384; break;
	case 64: inScheme.details.ecdsa.hashAlg = TPM2_ALG_SHA512; break;
	default:
		vpn_progress(vpninfo, PRG_ERR,
			     _("Unknown TPM2 EC digest size %d\n"),
			     data->size);
		return GNUTLS_E_PK_SIGN_FAILED;
	}

	memcpy(digest.buffer, data->data, data->size);
	digest.size = data->size;

	if (init_tpm2_key(&ectx, &key_handle, vpninfo))
		goto out;
 reauth:
	if (auth_tpm2_key(vpninfo, ectx, key_handle))
		goto out;

	r = Esys_Sign(ectx, key_handle,
		      ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
		      &digest, &inScheme, &validation,
		      &tsig);
	if (r == 0x9a2) {
		vpn_progress(vpninfo, PRG_DEBUG,
			     _("TPM2 Esys_Sign auth failed\n"));
		vpninfo->tpm2->need_userauth = 1;
		goto reauth;
	}
	if (r) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("TPM2 failed to generate RSA signature: 0x%x\n"),
			     r);
		goto out;
	}

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
	buf_append_bytes(sig_der, "\x02", 1); // INTEGER
	derlen = tsig->signature.ecdsa.signatureR.size;
	buf_append_bytes(sig_der, &derlen, 1);
	buf_append_bytes(sig_der, tsig->signature.ecdsa.signatureR.buffer, tsig->signature.ecdsa.signatureR.size);

	buf_append_bytes(sig_der, "\x02", 1); // INTEGER
	derlen = tsig->signature.ecdsa.signatureS.size;
	buf_append_bytes(sig_der, &derlen, 1);
	buf_append_bytes(sig_der, tsig->signature.ecdsa.signatureS.buffer, tsig->signature.ecdsa.signatureS.size);

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

	ret = 0;
 out:
	buf_free(sig_der);
	free(tsig);

	if (key_handle != ESYS_TR_NONE)
		Esys_FlushContext(ectx, key_handle);

	if (ectx)
		Esys_Finalize(&ectx);

	return ret;
}


int install_tpm2_key(struct openconnect_info *vpninfo, gnutls_privkey_t *pkey, gnutls_datum_t *pkey_sig,
		     unsigned int parent, int emptyauth, gnutls_datum_t *privdata, gnutls_datum_t *pubdata)
{
	TSS2_RC r;

	if (parent != 0x40000001) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Cannot use TPM2 key with non-default parent 0x%x\n"),
			     parent);
		return -EINVAL;
	};

	vpninfo->tpm2 = calloc(1, sizeof(*vpninfo->tpm2));
	if (!vpninfo->tpm2)
		return -ENOMEM;

	r = Tss2_MU_TPM2B_PRIVATE_Unmarshal(privdata->data, privdata->size, NULL,
					    &vpninfo->tpm2->priv);
	if (r) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to import TPM2 private key data: 0x%x\n"),
			     r);
	err_out:
		release_tpm2_ctx(vpninfo);
		return -EINVAL;
	}

	r = Tss2_MU_TPM2B_PUBLIC_Unmarshal(pubdata->data, pubdata->size, NULL,
					   &vpninfo->tpm2->pub);
	if (r) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to import TPM2 private key data: 0x%x\n"),
			     r);
		goto err_out;
	}

	vpninfo->tpm2->need_userauth = !emptyauth;

	gnutls_privkey_init(pkey);

	switch(vpninfo->tpm2->pub.publicArea.type) {
	case TPM2_ALG_RSA:
		gnutls_privkey_import_ext(*pkey, GNUTLS_PK_RSA, vpninfo, tpm2_rsa_sign_fn, NULL, 0);
		break;

	case TPM2_ALG_ECC:
		gnutls_privkey_import_ext(*pkey, GNUTLS_PK_EC, vpninfo, tpm2_ec_sign_fn, NULL, 0);
		break;

	default:
		vpn_progress(vpninfo, PRG_ERR,
			     _("Unsupported TPM2 key type %d\n"),
			     vpninfo->tpm2->pub.publicArea.type);
		gnutls_privkey_deinit(*pkey);
		*pkey = NULL;
		goto err_out;
	}

	return 0;
}


void release_tpm2_ctx(struct openconnect_info *vpninfo)
{
	if (vpninfo->tpm2)
		free(vpninfo->tpm2);
	vpninfo->tpm2 = NULL;
}

#endif /* HAVE_TSS2 */
