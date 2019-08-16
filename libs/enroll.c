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
 * File: enroll.c
 *      Enrollment functions.
 */

/** @defgroup enroll-api Enrollment API
 *  @ingroup user-api
 *  Enrollment API
 */

/**
 * @name Enrollment API
 * \addtogroup enroll-api
 *  @{
 */

#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>

#include "ctx.h"
#include "crypto.h"
#include "enroll.h"

#define TPM_HAVE_TPM2_DECLARATIONS
#include <libtpms/tpm_library.h>

#include <tss2/tss.h>
#include <tss2/tssmarshal.h>
#include <tss2/Unmarshal_fp.h>
#include <tss2/ekutils.h>
#include <tss2/cryptoutils.h>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>

#define TYPE_ST                 2

static int validateAK(attest_ctx_data *d_ctx, attest_ctx_verifier *v_ctx,
		      struct data_item *ak, TPM2B_NAME *name)
{
	TPMT_HA digest;
	TPM2B_PUBLIC pub;
	struct verification_log *log;
	BYTE *buffer;
	INT32 buffer_len;
	UINT32 req_mask = (TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT |
			   TPMA_OBJECT_SENSITIVEDATAORIGIN | TPMA_OBJECT_SIGN |
			   TPMA_OBJECT_RESTRICTED);
	int rc;

	log = attest_ctx_verifier_add_log(v_ctx, "check TPM AK");

	buffer = ak->data;
	buffer_len = ak->len;

	rc = TPM2B_PUBLIC_Unmarshal(&pub, &buffer, &buffer_len, 0);
	check_goto(rc, -EINVAL, out, v_ctx,
		   "TPMT_PUBLIC_Unmarshal() error: %d", rc);

	check_goto((pub.publicArea.objectAttributes.val & req_mask) != req_mask,
		   -EINVAL, out, v_ctx, "TPM AK flags invalid");

	digest.hashAlg = pub.publicArea.nameAlg;

	rc = TSS_Hash_Generate(&digest, ak->len - sizeof(UINT16),
			       ak->data + sizeof(UINT16), 0, NULL);
	check_goto(rc, -EINVAL, out, v_ctx,
		   "TSS_Hash_Generate() error: %d", rc);

	buffer = name->b.buffer;
	name->b.size = 0;

	rc = TSS_TPMT_HA_Marshal(&digest, &name->b.size, &buffer, NULL);
	check_goto(rc, -EINVAL, out, v_ctx,
		   "TSS_TPMT_HA_Marshal() error: %d", rc);
out:
	attest_ctx_verifier_end_log(v_ctx, log, rc);
	return rc;
}

static int attest_enroll_init_tpm(attest_ctx_verifier *v_ctx)
{
	Startup_In inStartup;
	int rc;

	current_log(v_ctx);

	rc = TPMLIB_ChooseTPMVersion(TPMLIB_TPM_VERSION_2);
	check_goto(rc, -EINVAL, out, v_ctx, "TPMLIB_ChooseTPMVersion() error");

	rc = TPMLIB_MainInit();
	check_goto(rc, -EINVAL, out, v_ctx, "TPMLIB_MainInit() error");

	inStartup.startupType = TPM_SU_CLEAR;

	rc = TPM2_Startup(&inStartup);
	check_goto(rc, -EINVAL, out, v_ctx, "TPM2_Startup() error");
out:
	if (rc)
		TPMLIB_Terminate();

	return rc;
}

int verbose;

static int attest_enroll_hmac(attest_ctx_verifier *v_ctx,
			      BYTE *akpub, int akpub_len,
			      BYTE *credential, int credential_len,
			      BYTE *hmac, unsigned int *hmac_len)
{
	HMAC_CTX *ctx;
	int rc;

	current_log(v_ctx);

	ctx = HMAC_CTX_new();
	check_goto(!ctx, -ENOMEM, out, v_ctx, "HMAC_CTX_new() error");

	rc = HMAC_Init_ex(ctx, v_ctx->key, sizeof(v_ctx->key),
			  EVP_sha256(), NULL);
	check_goto(!rc, -EINVAL, out_free, v_ctx, "HMAC_Init_ex() error");

	rc = HMAC_Update(ctx, credential, credential_len);
	check_goto(!rc, -EINVAL, out_free, v_ctx, "HMAC_Update() error");

	rc = HMAC_Update(ctx, akpub, akpub_len);
	check_goto(!rc, -EINVAL, out_free, v_ctx, "HMAC_Update() error");

	rc = HMAC_Final(ctx, hmac, hmac_len);
	check_goto(!rc, -EINVAL, out_free, v_ctx, "HMAC_Final() error");

	rc = 0;
out_free:
	HMAC_CTX_free(ctx);
out:
	return rc;
}

/**
 * Make credential for the client
 *
 * @param[in] d_ctx_in	input data context
 * @param[in] d_ctx_out	output data context
 * @param[in] v_ctx	verifier context
 *
 * @returns 0 on success, a negative value on error
 */
int attest_enroll_make_credential(attest_ctx_data *d_ctx_in,
				  attest_ctx_data *d_ctx_out,
				  attest_ctx_verifier *v_ctx)
{
	LoadExternal_Out outLoad;
	FlushContext_In inFlush;
	struct verification_log *log;
	BYTE buffer[MAX_RESPONSE_SIZE], *buffer_ptr;
	TPM2B_NAME name;
	X509 *cert;
	EVP_PKEY *evpPkey;
	TPM2B_PUBLIC ekPub;
	TPM2B_DIGEST cred;
	UINT16 written = 0, credBlobSize, secretSize;
	INT32 outBufSize = sizeof(buffer);
	BYTE hmac[EVP_MAX_MD_SIZE];
	unsigned int hmac_len = sizeof(hmac);
	struct data_item *ak;
	int rc;

	log = attest_ctx_verifier_add_log(v_ctx, "make credential");

	rc = attest_enroll_init_tpm(v_ctx);
	check_goto(rc, rc, out, v_ctx,
		   "attest_enroll_init_tpm() error: %d", rc);

	ak = attest_ctx_data_get(d_ctx_in, CTX_TPM_AK_KEY);
	check_goto(!ak, -ENOENT, out_tpm, v_ctx,
		   "TPM attestation key not provided");

	rc = validateAK(d_ctx_in, v_ctx, ak, &name);
	check_goto(rc, rc, out_tpm, v_ctx, "validateAK() error: %d", rc);

	rc = attest_crypto_verify_cert(d_ctx_in, v_ctx, CTX_EK_CERT,
				       CTX_EK_CA_CERT, &cert);
	check_goto(rc, rc, out_tpm, v_ctx,
		   "attest_crypto_verify_cert() error: %d", rc);

	evpPkey = X509_get_pubkey(cert);
	check_goto(!evpPkey, -ENOENT, out_cert, v_ctx,
		   "X509_get_pubkey() error");

	switch (EVP_PKEY_id(evpPkey)) {
	case EVP_PKEY_RSA:
		rc = convertRsaKeyToPublic(&ekPub, TYPE_ST, TPM_ALG_NULL,
					   TPM_ALG_SHA256, TPM_ALG_SHA256,
					   EVP_PKEY_get1_RSA(evpPkey));
		break;
	case EVP_PKEY_EC:
		rc = convertEcKeyToPublic(&ekPub, TYPE_ST, TPM_ALG_NULL,
					  TPM_ALG_SHA256, TPM_ALG_SHA256,
					  EVP_PKEY_get1_EC_KEY(evpPkey));
		break;
	default:
		rc = -ENOENT;
		break;
	}

	check_goto(rc, -EINVAL, out_cert, v_ctx, "convert key to public error");

	cred.t.size = EVP_MD_size(EVP_sha256());

	rc = RAND_bytes(cred.t.buffer, cred.t.size);
	check_goto(!rc, -EIO, out_cert, v_ctx, "RAND_bytes() error");

	buffer_ptr = buffer;

	rc = TSS_TPM2B_PUBLIC_Marshal(&ekPub, &written, &buffer_ptr, NULL);
	check_goto(rc, -EINVAL, out_cert, v_ctx,
		   "TSS_TPM2B_PUBLIC_Marshal() error");

	rc = TPM2_LoadExternal_SW(written, buffer, &outBufSize, buffer);
	check_goto(rc, -EINVAL, out_cert, v_ctx,
		   "TPM2_LoadExternal_SW() error");

	buffer_ptr = buffer;

	rc = TPM_HANDLE_Unmarshal(&outLoad.objectHandle, &buffer_ptr,
				  &outBufSize);
	check_goto(rc, -EINVAL, out_flush, v_ctx,
		   "TPM_HANDLE_Unmarshal() error");

	buffer_ptr = buffer;
	written = 0;

	rc = TSS_TPM_HANDLE_Marshal(&outLoad.objectHandle, &written,
				    &buffer_ptr, NULL);
	check_goto(rc, -EINVAL, out_flush, v_ctx,
		   "TSS_TPM2B_DIGEST_Marshal() error");

	rc = TSS_TPM2B_DIGEST_Marshal(&cred, &written, &buffer_ptr, NULL);
	check_goto(rc, -EINVAL, out_flush, v_ctx,
		   "TSS_TPM2B_DIGEST_Marshal() error");

	rc = TSS_TPM2B_NAME_Marshal(&name, &written, &buffer_ptr, NULL);
	check_goto(rc, -EINVAL, out_flush, v_ctx,
		   "TSS_TPM2B_NAME_Marshal() error");

	rc = TPM2_MakeCredential_SW(written, buffer, &outBufSize, buffer);
	check_goto(rc, -EINVAL, out_flush, v_ctx,
		   "TPM2_MakeCredential_SW() error");

	buffer_ptr = buffer;

	UINT16_Unmarshal(&credBlobSize, &buffer_ptr, &outBufSize);

	rc = attest_ctx_data_add_copy(d_ctx_out, CTX_CREDBLOB,
				      credBlobSize + sizeof(UINT16),
				      buffer_ptr - sizeof(UINT16), NULL);
	check_goto(rc, rc, out_flush, v_ctx,
		   "attest_ctx_data_add_copy() error");

	buffer_ptr += credBlobSize;

	UINT16_Unmarshal(&secretSize, &buffer_ptr, &outBufSize);

	rc = attest_ctx_data_add_copy(d_ctx_out, CTX_SECRET,
				      secretSize + sizeof(UINT16),
				      buffer_ptr - sizeof(UINT16), NULL);
	check_goto(rc, rc, out_flush, v_ctx,
		   "attest_ctx_data_add_copy() error");

	rc = attest_enroll_hmac(v_ctx, ak->data, ak->len,
				cred.t.buffer, cred.t.size, hmac, &hmac_len);
	check_goto(rc, rc, out_flush, v_ctx, "attest_enroll_hmac() error");

	rc = attest_ctx_data_add_copy(d_ctx_out, CTX_CRED_HMAC, hmac_len,
				      hmac, NULL);
	check_goto(rc, rc, out_flush, v_ctx,
		   "attest_ctx_verifier_add_output() error");
out_flush:
	inFlush.flushHandle = outLoad.objectHandle;

	rc = TPM2_FlushContext(&inFlush);
	check_goto(rc, -EINVAL, out_cert, v_ctx,
		   "TPM2_FlushContext_SW() error");
out_cert:
	X509_free(cert);
out_tpm:
	TPMLIB_Terminate();
out:
	attest_ctx_verifier_end_log(v_ctx, log, rc);
	return rc;
}

static int attest_enroll_verify_credential(attest_ctx_data *d_ctx_in,
					   attest_ctx_verifier *v_ctx,
					   struct data_item *ak)
{
	struct data_item *cred, *cred_hmac;
	BYTE hmac[EVP_MAX_MD_SIZE];
	unsigned int hmac_len = sizeof(hmac);
	struct verification_log *log;
	int rc;

	log = attest_ctx_verifier_add_log(v_ctx, "verify credential");

	cred = attest_ctx_data_get(d_ctx_in, CTX_CRED);
	check_goto(!cred, -ENOENT, out, v_ctx, "credential not provided");

	cred_hmac = attest_ctx_data_get(d_ctx_in, CTX_CRED_HMAC);
	check_goto(!cred_hmac, -ENOENT, out, v_ctx,
		   "Credential HMAC not provided");

	rc = attest_enroll_hmac(v_ctx, ak->data, ak->len, cred->data,
				cred->len, hmac, &hmac_len);
	check_goto(rc, -EINVAL, out, v_ctx, "attest_enroll_hmac() error");

	check_goto((cred_hmac->len != hmac_len), -EINVAL, out, v_ctx,
		   "credential HMAC length mismatch");

	check_goto(memcmp(hmac, cred_hmac->data, cred_hmac->len),
		   -EINVAL, out, v_ctx, "Credential mismatch");
out:
	attest_ctx_verifier_end_log(v_ctx, log, rc);
	return rc;
}

/**
 * Make certificate for the client
 *
 * @param[in] d_ctx_in	input data context
 * @param[in] d_ctx_out	output data context
 * @param[in] v_ctx	verifier context
 * @param[in] pcaKeyPath	path of CA private key
 * @param[in] pcaKeyPassword	CA private key password
 * @param[in] pcaCertPath	path of CA certificate
 * @param[in] hostname	client hostname
 *
 * @returns 0 on success, a negative value on error
 */
int attest_enroll_make_cert(attest_ctx_data *d_ctx_in,
			    attest_ctx_data *d_ctx_out,
			    attest_ctx_verifier *v_ctx,
			    char *pcaKeyPath, char *pcaKeyPassword,
			    char *pcaCertPath, char *hostname)
{
	BYTE *attestCertBin = NULL;
	char *akX509CertString = NULL, *akCertPemString = NULL;
	UINT32 attestCertBinLen = 0;
	struct verification_log *log;
	struct data_item *ak;
	TPM2B_PUBLIC pub;
	BYTE *buffer_ptr;
	INT32 buffer_len;
	int rc;

	/* FIXME should come from command line or config file */
	char *subjectEntries[] = {
		NULL,		/* 0 country */
		NULL,		/* 1 state */
		NULL,		/* 2 locality*/
		NULL,		/* 3 organization */
		NULL,		/* 4 organization unit */
		hostname,	/* 5 common name */
		NULL		/* 6 email */
	};

	/* FIXME should come from server privacy CA root certificate */
	char *issuerEntries[] = {
		"US"			,
		"NY"			,
		"Yorktown"		,
		"IBM"			,
		NULL			,
		"AK CA"			,
		NULL
	};

	log = attest_ctx_verifier_add_log(v_ctx, "create certificate");

	ak = attest_ctx_data_get(d_ctx_in, CTX_TPM_AK_KEY);
	check_goto(!ak, -ENOENT, out, v_ctx,
		   "TPM attestation key not provided");

	rc = attest_enroll_verify_credential(d_ctx_in, v_ctx, ak);
	check_goto(rc, rc, out, v_ctx,
		   "attest_enroll_verify_credential() error: %d", rc);

	buffer_ptr = ak->data;
	buffer_len = ak->len;

	rc = TPM2B_PUBLIC_Unmarshal(&pub, &buffer_ptr, &buffer_len, 0);
	check_goto(rc, -EINVAL, out, v_ctx,
		   "TPMT_PUBLIC_Unmarshal() error: %d", rc);

	rc = calculateNid();
	check_goto(rc, -EINVAL, out, v_ctx, "calculateNid() error");

	rc = createCertificate(&akX509CertString, &akCertPemString,
			       &attestCertBinLen, &attestCertBin,
			       &pub.publicArea, pcaKeyPath,
			       sizeof(issuerEntries)/sizeof(char *),
			       issuerEntries,
			       sizeof(subjectEntries)/sizeof(char *),
			       subjectEntries, pcaKeyPassword);
	check_goto(rc, -EINVAL, out, v_ctx, "createCertificate() error");

	rc = attest_ctx_data_add(d_ctx_out, CTX_AIK_CERT,
				 strlen(akCertPemString),
				 (BYTE *)akCertPemString, NULL);
	if (rc) {
		free(akCertPemString);
		goto out;
	}

	rc = attest_ctx_data_add_file(d_ctx_out, CTX_PRIVACY_CA_CERT,
				      pcaCertPath, NULL);

	free(akX509CertString);
	free(attestCertBin);

	check_goto(rc, rc, out, v_ctx,
		   "attest_ctx_verifier_add_output() error");
out:
	attest_ctx_verifier_end_log(v_ctx, log, rc);
	return rc;
}
/** @}*/
