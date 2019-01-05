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

/* Portions taken from tpm2-tss-engine, copyright as below: */

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

#include <errno.h>
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
	unsigned int did_ownerauth:1;
	unsigned int legacy_srk:1;
	unsigned int parent;
};

static TPM2B_PUBLIC primaryTemplate = {
	.publicArea = {
		.type = TPM2_ALG_ECC,
		.nameAlg = TPM2_ALG_SHA256,
		.objectAttributes = (TPMA_OBJECT_USERWITHAUTH |
				     TPMA_OBJECT_RESTRICTED |
				     TPMA_OBJECT_DECRYPT |
				     TPMA_OBJECT_FIXEDTPM |
				     TPMA_OBJECT_FIXEDPARENT |
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

static TPM2B_PUBLIC primaryTemplate_legacy = {
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


/* Where do these error values come from? */
#define KEY_AUTH_FAILED		0x9a2
#define PARENT_AUTH_FAILED	0x98e

static void install_tpm_passphrase(struct openconnect_info *vpninfo, TPM2B_DIGEST *auth, char *pass)
{
	if (strlen(pass) > sizeof(auth->buffer) - 1) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("TPM2 password too long; truncating\n"));
		pass[sizeof(auth->buffer) - 1] = 0;
	}
	auth->size = strlen(pass);
	strcpy((char *)auth->buffer, pass);
	free_pass(&pass);
}

static int init_tpm2_primary(struct openconnect_info *vpninfo,
			     ESYS_CONTEXT *ctx, ESYS_TR *primaryHandle)
{
	TSS2_RC r;
	const char *hierarchy_name;
	ESYS_TR hierarchy;

	switch(vpninfo->tpm2->parent) {
	case TPM2_RH_OWNER:	hierarchy = ESYS_TR_RH_OWNER;	hierarchy_name = _("owner"); break;
	case TPM2_RH_NULL:	hierarchy = ESYS_TR_RH_NULL;	hierarchy_name = _("null"); break;
	case TPM2_RH_ENDORSEMENT:hierarchy = ESYS_TR_RH_ENDORSEMENT; hierarchy_name = _("endorsement"); break;
	case TPM2_RH_PLATFORM:	hierarchy = ESYS_TR_RH_PLATFORM; hierarchy_name = _("platform"); break;
	default: return -EINVAL;
	}

	vpn_progress(vpninfo, PRG_DEBUG, _("Creating primary key under %s hierarchy.\n"), hierarchy_name);
 reauth:
	if (vpninfo->tpm2->need_ownerauth) {
		char *pass = NULL;
		if (request_passphrase(vpninfo, "openconnect_tpm2_hierarchy", &pass,
					   _("Enter TPM2 %s hierarchy password:"), hierarchy_name))
			return -EPERM;
		install_tpm_passphrase(vpninfo, &vpninfo->tpm2->ownerauth, pass);
		vpninfo->tpm2->need_ownerauth = 0;
	}
	r = Esys_TR_SetAuth(ctx, hierarchy, &vpninfo->tpm2->ownerauth);
	if (r) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("TPM2 Esys_TR_SetAuth failed: 0x%x\n"),
			     r);
		return -EPERM;
	}
	r = Esys_CreatePrimary(ctx, hierarchy,
			       ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
			       &primarySensitive,
			       vpninfo->tpm2->legacy_srk ? &primaryTemplate_legacy : &primaryTemplate,
			       &allOutsideInfo, &allCreationPCR,
			       primaryHandle, NULL, NULL, NULL, NULL);
	if (r == KEY_AUTH_FAILED) {
		vpn_progress(vpninfo, PRG_DEBUG,
			     _("TPM2 Esys_CreatePrimary owner auth failed\n"));
		vpninfo->tpm2->need_ownerauth = 1;
		goto reauth;
	} else if (r) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("TPM2 Esys_CreatePrimary failed: 0x%x\n"),
			     r);
		return -EIO;
	}
	return 0;
}

#define parent_is_generated(parent) ((parent) >> TPM2_HR_SHIFT == TPM2_HT_PERMANENT)
#define parent_is_persistent(parent) ((parent) >> TPM2_HR_SHIFT == TPM2_HT_PERSISTENT)

static int init_tpm2_key(ESYS_CONTEXT **ctx, ESYS_TR *keyHandle,
			 struct openconnect_info *vpninfo)
{
	ESYS_TR parentHandle = ESYS_TR_NONE;
	TSS2_RC r;

	*keyHandle = ESYS_TR_NONE;

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

	if (parent_is_generated(vpninfo->tpm2->parent)) {
		if (init_tpm2_primary(vpninfo, *ctx, &parentHandle))
			goto error;
	} else {
		r = Esys_TR_FromTPMPublic(*ctx, vpninfo->tpm2->parent,
					  ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &parentHandle);
		if (r) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Esys_TR_FromTPMPublic failed for handle 0x%x: 0x%x\n"),
				     vpninfo->tpm2->parent, r);
			goto error;
		}
		/* If we don't already have a password (and haven't already authenticated
		 * successfully), check the NODA flag on the parent and demand one if DA
		 * protection is enabled (since that strongly implies there is a non-empty
		 * password). */
		if (!vpninfo->tpm2->did_ownerauth && !vpninfo->tpm2->ownerauth.size) {
			TPM2B_PUBLIC *pub = NULL;

			r = Esys_ReadPublic(*ctx, parentHandle, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
					    &pub, NULL, NULL);
			if (!r && !(pub->publicArea.objectAttributes & TPMA_OBJECT_NODA))
				vpninfo->tpm2->need_ownerauth = 1;
			free(pub);
		}
	reauth:
		if (vpninfo->tpm2->need_ownerauth) {
			char *pass = NULL;
			if (request_passphrase(vpninfo, "openconnect_tpm2_parent", &pass,
					       _("Enter TPM2 parent key password:")))
				return -EPERM;
			install_tpm_passphrase(vpninfo, &vpninfo->tpm2->ownerauth, pass);
			vpninfo->tpm2->need_ownerauth = 0;
		}
		r = Esys_TR_SetAuth(*ctx, parentHandle, &vpninfo->tpm2->ownerauth);
		if (r) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("TPM2 Esys_TR_SetAuth failed: 0x%x\n"),
				     r);
			goto error;
		}
	}

	vpn_progress(vpninfo, PRG_DEBUG, _("Loading TPM2 key blob, parent %x.\n"), parentHandle);

	r = Esys_Load(*ctx, parentHandle,
		      ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
		      &vpninfo->tpm2->priv, &vpninfo->tpm2->pub,
		      keyHandle);
	if (r == PARENT_AUTH_FAILED) {
		vpn_progress(vpninfo, PRG_DEBUG,
			     _("TPM2 Esys_Load auth failed\n"));
		vpninfo->tpm2->need_ownerauth = 1;
		goto reauth;
	}
	if (r) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("TPM2 Esys_Load failed: 0x%x\n"),
			     r);
		goto error;
	}
	vpninfo->tpm2->did_ownerauth = 1;

	if (parent_is_generated(vpninfo->tpm2->parent)) {
		r = Esys_FlushContext(*ctx, parentHandle);
		if (r) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("TPM2 Esys_FlushContext for generated primary failed: 0x%x\n"),
				     r);
		}
		/* But it's non-fatal. */
	}

	return 0;
 error:
	if (parent_is_generated(vpninfo->tpm2->parent) && parentHandle != ESYS_TR_NONE)
		Esys_FlushContext(*ctx, parentHandle);
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
		install_tpm_passphrase(vpninfo, &vpninfo->tpm2->userauth, pass);
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

int tpm2_rsa_sign_hash_fn(gnutls_privkey_t key, gnutls_sign_algorithm_t algo,
			  void *_vpninfo, unsigned int flags,
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

	if (oc_pkcs1_pad(vpninfo, digest.buffer, digest.size, data))
		return GNUTLS_E_PK_SIGN_FAILED;

	if (init_tpm2_key(&ectx, &key_handle, vpninfo))
		goto out;
 reauth:
	if (auth_tpm2_key(vpninfo, ectx, key_handle))
		goto out;

	r = Esys_RSA_Decrypt(ectx, key_handle,
			     ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
			     &digest, &inScheme, &label, &tsig);
	if (r == KEY_AUTH_FAILED) {
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

int tpm2_ec_sign_hash_fn(gnutls_privkey_t key, gnutls_sign_algorithm_t algo,
			 void *_vpninfo, unsigned int flags,
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
	gnutls_datum_t sig_r, sig_s;

	vpn_progress(vpninfo, PRG_DEBUG,
		     _("TPM2 EC sign function called for %d bytes.\n"),
		     data->size);

	switch (algo) {
	case GNUTLS_SIGN_ECDSA_SHA1:   inScheme.details.ecdsa.hashAlg = TPM2_ALG_SHA1;   break;
	case GNUTLS_SIGN_ECDSA_SHA256: inScheme.details.ecdsa.hashAlg = TPM2_ALG_SHA256; break;
	case GNUTLS_SIGN_ECDSA_SHA384: inScheme.details.ecdsa.hashAlg = TPM2_ALG_SHA384; break;
	case GNUTLS_SIGN_ECDSA_SHA512: inScheme.details.ecdsa.hashAlg = TPM2_ALG_SHA512; break;
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
	if (r == KEY_AUTH_FAILED) {
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

	sig_r.data = tsig->signature.ecdsa.signatureR.buffer;
	sig_r.size = tsig->signature.ecdsa.signatureR.size;
	sig_s.data = tsig->signature.ecdsa.signatureS.buffer;
	sig_s.size = tsig->signature.ecdsa.signatureS.size;

	ret = gnutls_encode_rs_value(sig, &sig_r, &sig_s);
 out:
	free(tsig);

	if (key_handle != ESYS_TR_NONE)
		Esys_FlushContext(ectx, key_handle);

	if (ectx)
		Esys_Finalize(&ectx);

	return ret;
}

int install_tpm2_key(struct openconnect_info *vpninfo, gnutls_privkey_t *pkey, gnutls_datum_t *pkey_sig,
		     unsigned int parent, int emptyauth, int legacy, gnutls_datum_t *privdata, gnutls_datum_t *pubdata)
{
	TSS2_RC r;

	if (!parent_is_persistent(parent) &&
	    parent != TPM2_RH_OWNER && parent != TPM2_RH_NULL &&
	    parent != TPM2_RH_ENDORSEMENT && parent != TPM2_RH_PLATFORM) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Invalid TPM2 parent handle 0x%08x\n"), parent);
		return -EINVAL;
	}

	vpninfo->tpm2 = calloc(1, sizeof(*vpninfo->tpm2));
	if (!vpninfo->tpm2)
		return -ENOMEM;

	vpninfo->tpm2->parent = parent;

	r = Tss2_MU_TPM2B_PRIVATE_Unmarshal(privdata->data, privdata->size, NULL,
					    &vpninfo->tpm2->priv);
	if (r) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to import TPM2 private key data: 0x%x\n"),
			     r);
		goto err_out;
	}

	r = Tss2_MU_TPM2B_PUBLIC_Unmarshal(pubdata->data, pubdata->size, NULL,
					   &vpninfo->tpm2->pub);
	if (r) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to import TPM2 public key data: 0x%x\n"),
			     r);
		goto err_out;
	}

	vpninfo->tpm2->need_userauth = !emptyauth;
	vpninfo->tpm2->legacy_srk = legacy;

	switch(vpninfo->tpm2->pub.publicArea.type) {
	case TPM2_ALG_RSA: return GNUTLS_PK_RSA;
	case TPM2_ALG_ECC: return GNUTLS_PK_ECDSA;
	}

	vpn_progress(vpninfo, PRG_ERR,
		     _("Unsupported TPM2 key type %d\n"),
		     vpninfo->tpm2->pub.publicArea.type);
 err_out:
	release_tpm2_ctx(vpninfo);
	return -EINVAL;
}


void release_tpm2_ctx(struct openconnect_info *vpninfo)
{
	if (vpninfo->tpm2) {
		clear_mem(vpninfo->tpm2->ownerauth.buffer, sizeof(vpninfo->tpm2->ownerauth.buffer));
		clear_mem(vpninfo->tpm2->userauth.buffer, sizeof(vpninfo->tpm2->userauth.buffer));
		free(vpninfo->tpm2);
	}
	vpninfo->tpm2 = NULL;
}
