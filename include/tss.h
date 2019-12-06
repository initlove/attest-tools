/*
 * Copyright (C) 2018-2019 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 *
 * File: tss.h
 *      Header of tss.c.
 */

#ifndef _TSS_H
#define _TSS_H

#include <ibmtss/tss.h>
#include <ibmtss/tssmarshal.h>
#include <ibmtss/Unmarshal_fp.h>
#include <ibmtss/tssutils.h>
#include <ibmtss/tsscryptoh.h>
#include <ibmtss/tssresponsecode.h>

enum key_types { KEY_TYPE_AK, KEY_TYPE_ASYM_DEC, KEY_TYPE_SYM_HMAC,
		 KEY_TYPE__LAST };

int attest_tss_nvreadpublic(TSS_CONTEXT *tssContext, int nvIndex,
			    size_t *nvdata_len);
int attest_tss_nvread(TSS_CONTEXT *tssContext, int nvIndex, size_t nvdata_len,
		      BYTE **nvdata);
int attest_tss_getekcert(TSS_CONTEXT *tssContext, TPMI_ALG_PUBLIC algPublic,
			 size_t *nvdata_len, BYTE **nvdata);
int attest_tss_create_obj(TSS_CONTEXT *tssContext, TPMI_ALG_PUBLIC algPublic,
			  TPMI_ECC_CURVE curveID, TPMI_ALG_HASH nalg,
			  TPMI_ALG_HASH halg, enum key_types type,
			  BYTE *policy_digest, UINT16 *private_len,
			  BYTE **private, UINT16 *public_len, BYTE **public);
int attest_tss_createek(TSS_CONTEXT *tssContext, TPMI_ALG_PUBLIC algPublic,
			TPM_HANDLE *keyHandle);
int attest_tss_load(TSS_CONTEXT *tssContext, UINT16 private_len, BYTE *private,
		    UINT16 public_len, BYTE *public, TPM_HANDLE *keyHandle);
int attest_tss_startauthsession(TSS_CONTEXT *tssContext,
				TPMI_SH_AUTH_SESSION *sessionHandle);
int attest_tss_policysecret(TSS_CONTEXT *tssContext,
			    TPMI_SH_AUTH_SESSION sessionHandle);
int attest_tss_flushcontext(TSS_CONTEXT *tssContext, TPM_HANDLE handle);
int attest_tss_activatecredential(TSS_CONTEXT *tssContext,
				TPM_HANDLE activateHandle, TPM_HANDLE keyHandle,
				INT32 credentialblob_len, BYTE *credentialblob,
				INT32 secret_len, BYTE *secret,
				UINT16 *credential_len, BYTE **credential);
int attest_tss_certify(TSS_CONTEXT *tssContext, TPM_HANDLE objectHandle,
		       TPM_HANDLE signHandle, TPMI_ALG_PUBLIC algPublic,
		       TPMI_ALG_HASH halg, UINT16 *certify_info_len,
		       BYTE **certify_info, UINT16 *signature_len,
		       BYTE **signature);
int attest_tss_load_certify(TSS_CONTEXT *tssContext, char *akPrivPath,
			char *akPubPath, char *keyPrivPath, char *keyPubPath,
			TPMI_ALG_PUBLIC algPublic, TPMI_ALG_HASH halg,
			UINT16 *certify_info_len, BYTE **certify_info,
			UINT16 *signature_len, BYTE **signature);
int attest_tss_pcrread(TSS_CONTEXT *tssContext, TPMI_DH_PCR pcr,
		       TPMI_ALG_HASH halg, BYTE *pcr_value);
int attest_tss_loadexternal(TSS_CONTEXT *tssContext, EVP_PKEY *ek_pub,
			    TPM_HANDLE *handle);
int attest_tss_makecredential(TSS_CONTEXT *tssContext, TPM_HANDLE ek_handle,
			      TPM2B_DIGEST *cred, TPM2B_NAME *name,
			      BYTE **cred_blob, UINT16 *cred_blob_len,
			      BYTE **secret, UINT16 *secret_len);
int attest_tss_quote(TSS_CONTEXT *tssContext, TPM_HANDLE ak_handle,
		     UINT16 ak_public_len, BYTE *ak_public, UINT16 nonce_len,
		     const BYTE *nonce, const TPML_PCR_SELECTION *pcrSelection,
		     UINT16 *quote_len, BYTE **quote, UINT16 *signature_len,
		     BYTE **signature);

#endif /*_TSS_H*/
