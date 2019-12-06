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
 * File: tss.c
 *      TSS functions.
 */

/**
 * @defgroup tss-api TSS API
 * @ingroup developer-api
 * @brief
 * Functions to perform operations with the TPM.
 */

/**
 * @addtogroup tss-api
 *  @{
 */

#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/mman.h>

#include <ibmtss/ekutils.h>
#include <ibmtss/cryptoutils.h>

#include "tss.h"
#include "util.h"

int verbose;

static void tss_print_error(char *cmd, int rc)
{
	const char *msg;
	const char *submsg;
	const char *num;

	printf("%s: failed, rc %08x\n", cmd, rc);
	TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	printf("%s%s%s\n", msg, submsg, num);
}

/**
 * Read size of public part of NV
 * @param[in] tssContext	TSS context
 * @param[in] nvIndex		NV index
 * @param[in,out] nvdata_len	NV data length
 *
 * @returns 0 on success, a negative value on error
 */
int attest_tss_nvreadpublic(TSS_CONTEXT *tssContext, int nvIndex,
			    size_t *nvdata_len)
{
	NV_ReadPublic_In in;
	NV_ReadPublic_Out out;
	int rc;

	in.nvIndex = nvIndex;

	rc = TSS_Execute(tssContext, (RESPONSE_PARAMETERS *)&out,
			 (COMMAND_PARAMETERS *)&in, NULL, TPM_CC_NV_ReadPublic,
			 TPM_RH_NULL, NULL, 0);
	if (rc) {
		tss_print_error("TPM_CC_NV_ReadPublic", rc);
		return -EINVAL;
	}

	*nvdata_len = out.nvPublic.nvPublic.dataSize;
	return 0;
}

/**
 * Read public part of NV
 * @param[in] tssContext	TSS context
 * @param[in] nvIndex		NV index
 * @param[in] nvdata_len	NV data length
 * @param[in,out] nvdata	NV data
 *
 * @returns 0 on success, a negative value on error
 */
int attest_tss_nvread(TSS_CONTEXT *tssContext, int nvIndex, size_t nvdata_len,
		      BYTE **nvdata)
{
	NV_Read_In in;
	NV_Read_Out out;
	uint16_t bytesRead = 0;
	uint32_t nvBufferMax;
	int rc;

	in.authHandle = TPM_RH_OWNER;
	in.nvIndex = nvIndex;
	in.offset = 0;

	rc = readNvBufferMax(tssContext, &nvBufferMax);
	if (rc)
		return -EINVAL;
	
	*nvdata = malloc(nvdata_len);
	if (!*nvdata)
		return -ENOMEM;

	while (bytesRead < nvdata_len) {
		in.offset = bytesRead;
		in.size = nvdata_len - bytesRead;

		if (in.size > nvBufferMax)
			in.size = nvBufferMax;

		rc = TSS_Execute(tssContext, (RESPONSE_PARAMETERS *)&out,
				 (COMMAND_PARAMETERS *)&in, NULL,
				 TPM_CC_NV_Read, TPM_RS_PW, NULL, 0,
				 TPM_RH_NULL, NULL, 0);
		if (rc) {
			tss_print_error("TPM_CC_NV_Read", rc);
			return rc;
		}

		memcpy(*nvdata + bytesRead, out.data.b.buffer, out.data.b.size);
		bytesRead += out.data.b.size;
	}

	return 0;
}

/**
 * Get EK cert from NV
 * @param[in] tssContext	TSS context
 * @param[in] algPublic		EK algorithm
 * @param[in,out] nvdata_len	EK cert length
 * @param[in,out] nvdata	EK cert
 *
 * @returns 0 on success, a negative value on error
 */
int attest_tss_getekcert(TSS_CONTEXT *tssContext, TPMI_ALG_PUBLIC algPublic,
			 size_t *nvdata_len, BYTE **nvdata)
{
	int rc, nvIndex;

	switch (algPublic) {
	case TPM_ALG_RSA:
		nvIndex = EK_CERT_RSA_INDEX;
		break;
	case TPM_ALG_ECC:
		nvIndex = EK_CERT_EC_INDEX;
		break;
	default:
		return -EINVAL;
	}

	rc = attest_tss_nvreadpublic(tssContext, nvIndex, nvdata_len);
	if (rc)
		return rc;

	return attest_tss_nvread(tssContext, nvIndex, *nvdata_len, nvdata);
}

static int asymPublicTemplate(TPMT_PUBLIC *publicArea,
			      TPMI_ALG_PUBLIC algPublic, TPMI_ECC_CURVE curveID,
			      TPMI_ALG_HASH nalg, TPMI_ALG_HASH halg,
			      int restricted, const char *policyFilename)
{
	TPMU_PUBLIC_PARMS *params;
	TPM_RC rc = 0;

	publicArea->objectAttributes.val |= TPMA_OBJECT_NODA;
	publicArea->objectAttributes.val |= TPMA_OBJECT_FIXEDTPM;
	publicArea->objectAttributes.val |= TPMA_OBJECT_FIXEDPARENT;
	publicArea->objectAttributes.val |= TPMA_OBJECT_SENSITIVEDATAORIGIN;
	publicArea->objectAttributes.val |= TPMA_OBJECT_USERWITHAUTH;
	publicArea->type = algPublic;
	publicArea->nameAlg = nalg;

	if (restricted) {
		publicArea->objectAttributes.val |= TPMA_OBJECT_RESTRICTED;
		publicArea->objectAttributes.val |= TPMA_OBJECT_SIGN;
	} else {
		publicArea->objectAttributes.val |= TPMA_OBJECT_DECRYPT;
	}
	params = &publicArea->parameters;

	if (algPublic == TPM_ALG_RSA) {
		params->rsaDetail.symmetric.algorithm = TPM_ALG_NULL;
		params->rsaDetail.scheme.scheme = TPM_ALG_NULL;
		if (restricted) {
			params->rsaDetail.scheme.scheme = TPM_ALG_RSASSA;
			params->rsaDetail.scheme.details.rsassa.hashAlg = halg;
		}

		params->rsaDetail.keyBits = 2048;
		params->rsaDetail.exponent = 0;
		publicArea->unique.rsa.t.size = 0;
	} else {
		params->eccDetail.symmetric.algorithm = TPM_ALG_NULL;
		params->eccDetail.scheme.scheme = TPM_ALG_NULL;
		params->eccDetail.curveID = curveID;
		params->eccDetail.kdf.scheme = TPM_ALG_NULL;

		if (restricted) {
			params->eccDetail.scheme.scheme = TPM_ALG_ECDSA;
			params->eccDetail.scheme.details.ecdsa.hashAlg = halg;
			params->eccDetail.curveID = curveID;
			params->eccDetail.kdf.scheme = TPM_ALG_NULL;
			params->eccDetail.kdf.details.mgf1.hashAlg = halg;
		}

		publicArea->unique.ecc.x.t.size = 0;
		publicArea->unique.ecc.y.t.size = 0;
	}

	publicArea->authPolicy.t.size = 0;

	if (policyFilename) {
		rc = TSS_File_Read2B(&publicArea->authPolicy.b,
				     sizeof(publicArea->authPolicy.t.buffer),
				     policyFilename);
	}

	return rc;
}

static int blPublicTemplate(TPMT_PUBLIC *publicArea, TPMI_ALG_HASH nalg,
			    const char *policyFilename)
{
	TPM_RC rc = 0;

	publicArea->type = TPM_ALG_KEYEDHASH;
	publicArea->nameAlg = nalg;
	publicArea->objectAttributes.val &= ~TPMA_OBJECT_SIGN;
	publicArea->objectAttributes.val &= ~TPMA_OBJECT_DECRYPT;
	publicArea->objectAttributes.val &= ~TPMA_OBJECT_RESTRICTED;
	publicArea->objectAttributes.val |= TPMA_OBJECT_SENSITIVEDATAORIGIN;
	publicArea->objectAttributes.val |= TPMA_OBJECT_USERWITHAUTH;
	publicArea->objectAttributes.val |= TPMA_OBJECT_FIXEDTPM;
	publicArea->objectAttributes.val |= TPMA_OBJECT_FIXEDPARENT;
	publicArea->objectAttributes.val &= ~TPMA_OBJECT_ADMINWITHPOLICY;
	publicArea->parameters.keyedHashDetail.scheme.scheme = TPM_ALG_NULL;
	publicArea->unique.sym.t.size = 0;

	publicArea->authPolicy.t.size = 0;

	if (policyFilename) {
		rc = TSS_File_Read2B(&publicArea->authPolicy.b,
				     sizeof(publicArea->authPolicy.t.buffer),
				     policyFilename);
	}

	return rc;
}

/**
 * Create TPM key or sealed data blob
 * @param[in] tssContext	TSS context
 * @param[in] algPublic		EK algorithm
 * @param[in] curveID		Elliptic Curve identifier
 * @param[in] nalg		Object name algorithm
 * @param[in] halg		Hash algorithm
 * @param[in] type		Key type
 * @param[in] policy_digest	Policy digest
 * @param[in,out] private_len	New key private part length
 * @param[in,out] private	New key private part
 * @param[in,out] public_len	New key public part length
 * @param[in,out] public	New key public part
 *
 * @returns 0 on success, a negative value on error
 */
int attest_tss_create_obj(TSS_CONTEXT *tssContext, TPMI_ALG_PUBLIC algPublic,
			  TPMI_ECC_CURVE curveID, TPMI_ALG_HASH nalg,
			  TPMI_ALG_HASH halg, enum key_types type,
			  BYTE *policy_digest, UINT16 *private_len,
			  BYTE **private, UINT16 *public_len, BYTE **public)
{
	Create_In in;
	Create_Out out;
	int rc;

	in.parentHandle = 0x81000001;
	in.inSensitive.sensitive.userAuth.t.size = 0;
	in.inSensitive.sensitive.data.t.size = 0;
	in.outsideInfo.t.size = 0;
	in.creationPCR.count = 0;

	memset(&in.inPublic.publicArea, 0, sizeof(in.inPublic.publicArea));
	switch (type) {
	case KEY_TYPE_AK:
	case KEY_TYPE_ASYM_DEC:
		rc = asymPublicTemplate(&in.inPublic.publicArea, algPublic,
					TPM_ECC_NONE, nalg, halg,
					(type == KEY_TYPE_AK), NULL);
		break;
	case KEY_TYPE_SYM_HMAC:
		rc = blPublicTemplate(&in.inPublic.publicArea, nalg, NULL);
		break;
	default:
		rc = -ENOTSUP;
		break;
	}

	if (rc)
		return -EINVAL;

	if (policy_digest) {
		in.inPublic.publicArea.objectAttributes.val &=
			~TPMA_OBJECT_USERWITHAUTH;
		rc = TSS_TPM2B_Create(&in.inPublic.publicArea.authPolicy.b,
				      policy_digest, TSS_GetDigestSize(nalg),
				      sizeof(TPMU_HA));
		if (rc)
			return -EINVAL;
	}

	rc = TSS_Execute(tssContext, (RESPONSE_PARAMETERS *)&out,
			 (COMMAND_PARAMETERS *)&in, NULL, TPM_CC_Create,
			 TPM_RS_PW, NULL, 0, TPM_RH_NULL, NULL, 0);
	if (rc) {
		tss_print_error("TPM_CC_Create", rc);
		return -EINVAL;
	}

	*private = NULL;
	*private_len = 0;
	rc = TSS_Structure_Marshal(private, private_len, &out.outPrivate,
				(MarshalFunction_t)TSS_TPM2B_PRIVATE_Marshal);
	if (rc)
		return -ENOMEM;

	*public = NULL;
	*public_len = 0;
	rc = TSS_Structure_Marshal(public, public_len, &out.outPublic,
				(MarshalFunction_t)TSS_TPM2B_PUBLIC_Marshal);
	if (rc)
		free(*private);

	return rc;
}

/**
 * Create EK
 * @param[in] tssContext	TSS context
 * @param[in] algPublic		EK algorithm
 * @param[in,out] keyHandle	EK handle
 *
 * @returns 0 on success, a negative value on error
 */
int attest_tss_createek(TSS_CONTEXT *tssContext, TPMI_ALG_PUBLIC algPublic,
			TPM_HANDLE *keyHandle)
{
	TPMI_RH_NV_INDEX ekCertIndex;
	TPMI_RH_NV_INDEX ekNonceIndex;
	TPMI_RH_NV_INDEX ekTemplateIndex;

	switch (algPublic) {
	case TPM_ALG_RSA:
		ekCertIndex = EK_CERT_RSA_INDEX;
		ekNonceIndex = EK_NONCE_RSA_INDEX;
		ekTemplateIndex = EK_TEMPLATE_RSA_INDEX;
		break;
	case TPM_ALG_ECC:
		ekCertIndex = EK_CERT_EC_INDEX;
		ekNonceIndex = EK_NONCE_EC_INDEX;
		ekTemplateIndex = EK_TEMPLATE_EC_INDEX;
		break;
	default:
		return -EINVAL;
	}

	return processPrimary(tssContext, keyHandle, ekCertIndex, ekNonceIndex,
			      ekTemplateIndex, 1 , 0);
}

/**
 * Load TPM key
 * @param[in] tssContext	TSS context
 * @param[in] private_len	New key private part length
 * @param[in] private		New key private part
 * @param[in] public_len	New key public part length
 * @param[in] public		New key public part
 * @param[in,out] keyHandle	EK handle
 *
 * @returns 0 on success, a negative value on error
 */
int attest_tss_load(TSS_CONTEXT *tssContext, UINT16 private_len, BYTE *private,
		    UINT16 public_len, BYTE *public, TPM_HANDLE *keyHandle)
{
	Load_In in;
	Load_Out out;
	INT32 priv_len = private_len;
	INT32 pub_len = public_len;
	int rc;

	in.parentHandle = 0x81000001;

	rc = TPM2B_PRIVATE_Unmarshal(&in.inPrivate, &private, &priv_len);
	if (rc)
		return -EINVAL;

	rc = TPM2B_PUBLIC_Unmarshal(&in.inPublic, &public, &pub_len, FALSE);
	if (rc)
		return -EINVAL;

	rc = TSS_Execute(tssContext, (RESPONSE_PARAMETERS *)&out,
			 (COMMAND_PARAMETERS *)&in, NULL, TPM_CC_Load,
			 TPM_RS_PW, NULL, 0, TPM_RH_NULL, NULL, 0);
	if (rc) {
		tss_print_error("TPM_CC_Load", rc);
		return -EINVAL;
	}

	*keyHandle = out.objectHandle;
	return 0;
}

/**
 * Start auth session
 * @param[in] tssContext	TSS context
 * @param[in,out] sessionHandle	Session handle
 *
 * @returns 0 on success, a negative value on error
 */
int attest_tss_startauthsession(TSS_CONTEXT *tssContext,
				TPMI_SH_AUTH_SESSION *sessionHandle)
{
	StartAuthSession_In startAuthSessionIn;
	StartAuthSession_Out startAuthSessionOut;
	StartAuthSession_Extra startAuthSessionExtra;
	int rc;

	startAuthSessionIn.sessionType = TPM_SE_POLICY;
	startAuthSessionIn.tpmKey = TPM_RH_NULL;
	startAuthSessionIn.bind = TPM_RH_NULL;
	startAuthSessionIn.symmetric.algorithm = TPM_ALG_XOR;
	startAuthSessionIn.authHash = TPM_ALG_SHA256;
	startAuthSessionIn.symmetric.keyBits.xorr = TPM_ALG_SHA256;
	startAuthSessionIn.symmetric.mode.sym = TPM_ALG_NULL;
	startAuthSessionExtra.bindPassword = NULL;

	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&startAuthSessionOut, 
			 (COMMAND_PARAMETERS *)&startAuthSessionIn,
			 (EXTRA_PARAMETERS *)&startAuthSessionExtra,
			 TPM_CC_StartAuthSession, TPM_RH_NULL, NULL, 0);
	if (rc) {
		tss_print_error("TPM_CC_StartAuthSession", rc);
		return -EINVAL;
	}

	*sessionHandle = startAuthSessionOut.sessionHandle;
	return 0;
}

/**
 * Add policysecret to auth session
 * @param[in] tssContext	TSS context
 * @param[in] sessionHandle	Session handle
 *
 * @returns 0 on success, a negative value on error
 */
int attest_tss_policysecret(TSS_CONTEXT *tssContext,
			    TPMI_SH_AUTH_SESSION sessionHandle)
{
	PolicySecret_In policySecretIn;
	PolicySecret_Out policySecretOut;
	int rc;

	policySecretIn.authHandle = TPM_RH_ENDORSEMENT;
	policySecretIn.policySession = sessionHandle;
	policySecretIn.nonceTPM.b.size = 0;
	policySecretIn.cpHashA.b.size = 0;
	policySecretIn.policyRef.b.size = 0;
	policySecretIn.expiration = 0;

	rc = TSS_Execute(tssContext, (RESPONSE_PARAMETERS *)&policySecretOut, 
			 (COMMAND_PARAMETERS *)&policySecretIn, NULL,
			 TPM_CC_PolicySecret, TPM_RS_PW, NULL, 0,
			 TPM_RH_NULL, NULL, 0);
	if (rc) {
		tss_print_error("TPM_CC_PolicySecret", rc);
		return -EINVAL;
	}

	return 0;
}

/**
 * Flush context
 * @param[in] tssContext	TSS context
 * @param[in] handle		Handle of object to flush
 *
 * @returns 0 on success, a negative value on error
 */
int attest_tss_flushcontext(TSS_CONTEXT *tssContext, TPM_HANDLE handle)
{
	FlushContext_In in;
	int rc;

	in.flushHandle = handle;

	rc = TSS_Execute(tssContext, NULL,  (COMMAND_PARAMETERS *)&in, NULL,
			 TPM_CC_FlushContext, TPM_RH_NULL, NULL, 0);
	if (rc) {
		tss_print_error("TPM_CC_FlushContext", rc);
		return -EINVAL;
	}

	return 0;
}

/**
 * Activate credential
 * @param[in] tssContext		TSS context
 * @param[in] activateHandle		AK handle
 * @param[in] keyHandle			EK handle
 * @param[in] credentialblob_len	Credential blob length
 * @param[in] credentialblob		Credential blob
 * @param[in] secret_len		Secret length
 * @param[in] secret			Secret
 * @param[in,out] credential_len	Credential length
 * @param[in,out] credential		Credential
 *
 * @returns 0 on success, a negative value on error
 */
int attest_tss_activatecredential(TSS_CONTEXT *tssContext,
				TPM_HANDLE activateHandle, TPM_HANDLE keyHandle,
				INT32 credentialblob_len, BYTE *credentialblob,
				INT32 secret_len, BYTE *secret,
				UINT16 *credential_len, BYTE **credential)
{
	TPMI_SH_AUTH_SESSION sessionHandle;
	ActivateCredential_In in;
	ActivateCredential_Out out;
	int rc;

	in.activateHandle = activateHandle;
	in.keyHandle = keyHandle;

	rc = TPM2B_ID_OBJECT_Unmarshal(&in.credentialBlob, &credentialblob,
				       &credentialblob_len);
	if (rc)
		return -EINVAL;

	rc = TPM2B_ENCRYPTED_SECRET_Unmarshal(&in.secret, &secret, &secret_len);
	if (rc)
		return -EINVAL;

	rc = attest_tss_startauthsession(tssContext, &sessionHandle);
	if (rc)
		return -EINVAL;

	rc = attest_tss_policysecret(tssContext, sessionHandle);
	if (rc) {
		rc = -EINVAL;
		goto out;
	}

	rc = TSS_Execute(tssContext, (RESPONSE_PARAMETERS *)&out,
			 (COMMAND_PARAMETERS *)&in, NULL,
			 TPM_CC_ActivateCredential, TPM_RS_PW, NULL, 0,
			 sessionHandle, NULL, 0, TPM_RH_NULL, NULL, 0);
	if (rc) {
		tss_print_error("TPM_CC_ActivateCredential", rc);
		rc = -EINVAL;
		goto out;
	}

	*credential_len = out.certInfo.t.size;
	*credential = malloc(*credential_len);
	if (!*credential)
		rc = -ENOMEM;
	else
		rc = 0;

	memcpy(*credential, out.certInfo.t.buffer, *credential_len);
out:
	if (rc == -EINVAL)
		attest_tss_flushcontext(tssContext, sessionHandle);
	return rc;
}

/**
 * Certify key
 * @param[in] tssContext		TSS context
 * @param[in] objectHandle		Key handle
 * @param[in] signHandle		AK handle
 * @param[in] algPublic			Signature algorithm
 * @param[in] halg			Hash algorithm
 * @param[in,out] certify_info_len	CertifyInfo length
 * @param[in,out] certify_info		CertifyInfo
 * @param[in,out] signature_len		Signature length
 * @param[in,out] signature		Signature
 *
 * @returns 0 on success, a negative value on error
 */
int attest_tss_certify(TSS_CONTEXT *tssContext, TPM_HANDLE objectHandle,
		       TPM_HANDLE signHandle, TPMI_ALG_PUBLIC algPublic,
		       TPMI_ALG_HASH halg, UINT16 *certify_info_len,
		       BYTE **certify_info, UINT16 *signature_len,
		       BYTE **signature)
{
	int rc;
	Certify_In in;
	Certify_Out out;

	switch(algPublic) {
	case TPM_ALG_RSA:
		in.inScheme.scheme = TPM_ALG_RSASSA;
		in.inScheme.details.rsassa.hashAlg = halg;
		break;
	case TPM_ALG_ECC:
		in.inScheme.scheme = TPM_ALG_ECDSA;
		in.inScheme.details.ecdsa.hashAlg = halg;
		break;
	default:
		return -EINVAL;
	}

	in.objectHandle = objectHandle;
	in.signHandle = signHandle;
	in.qualifyingData.t.size = 0;

	rc = TSS_Execute(tssContext, (RESPONSE_PARAMETERS *)&out,
			 (COMMAND_PARAMETERS *)&in, NULL, TPM_CC_Certify,
			 TPM_RS_PW, NULL, 0, TPM_RS_PW, NULL, 0,
			 TPM_RH_NULL, NULL, 0, TPM_RH_NULL, NULL, 0);
	if (rc) {
		tss_print_error("TPM_CC_Certify", rc);
		return -EINVAL;
	}

	*certify_info_len = out.certifyInfo.t.size;
	*certify_info = malloc(*certify_info_len);
	if (!*certify_info)
		return -ENOMEM;

	memcpy(*certify_info, out.certifyInfo.t.attestationData,
	       *certify_info_len);

	*signature = NULL;
	*signature_len = 0;
	rc = TSS_Structure_Marshal(signature, signature_len, &out.signature,
				(MarshalFunction_t)TSS_TPMT_SIGNATURE_Marshal);
	if (rc)
		return -ENOMEM;

	return 0;
}

/**
 * Load and certify key
 * @param[in] tssContext	TSS context
 * @param[in] akPrivPath	AK private part
 * @param[in] akPubPath	AK public part
 * @param[in] keyPrivPath	Key private part
 * @param[in] keyPubPath	Key public part
 * @param[in] algPublic	Key algorithm
 * @param[in] halg	Hash algorithm
 * @param[in,out] certify_info_len	Certify info length
 * @param[in,out] certify_info	Certify info
 * @param[in,out] signature_len	Signature length
 * @param[in,out] signature	Signature
 *
 * @returns 0 on success, a negative value on error
 */
int attest_tss_load_certify(TSS_CONTEXT *tssContext, char *akPrivPath,
			char *akPubPath, char *keyPrivPath, char *keyPubPath,
			TPMI_ALG_PUBLIC algPublic, TPMI_ALG_HASH halg,
			UINT16 *certify_info_len, BYTE **certify_info,
			UINT16 *signature_len, BYTE **signature)
{
	TPM_HANDLE signHandle, keyHandle;

	BYTE *ak_private = NULL, *ak_public = NULL;
	BYTE *key_private = NULL, *key_public = NULL;
	size_t ak_private_len, ak_public_len, key_private_len, key_public_len;
	int rc;

	rc = attest_util_read_file(keyPrivPath, &key_private_len, &key_private);
	if (rc)
		goto out;

	rc = attest_util_read_file(keyPubPath, &key_public_len, &key_public);
	if (rc)
		goto out;

	rc = attest_util_read_file(akPrivPath, &ak_private_len, &ak_private);
	if (rc)
		goto out;

	rc = attest_util_read_file(akPubPath, &ak_public_len, &ak_public);
	if (rc)
		goto out;

	rc = attest_tss_load(tssContext, key_private_len, key_private,
			     key_public_len, key_public, &keyHandle);
	if (rc)
		goto out;

	rc = attest_tss_load(tssContext, ak_private_len, ak_private,
			     ak_public_len, ak_public, &signHandle);
	if (rc)
		goto out_flush_key;

	rc = attest_tss_certify(tssContext, keyHandle, signHandle, algPublic,
				halg, certify_info_len, certify_info,
				signature_len, signature);

	attest_tss_flushcontext(tssContext, signHandle);
out_flush_key:
	attest_tss_flushcontext(tssContext, keyHandle);
out:
	if (ak_private)
		munmap(ak_private, ak_private_len);
	if (ak_public)
		munmap(ak_public, ak_public_len);
	if (key_private)
		munmap(key_private, key_private_len);
	if (key_public)
		munmap(key_public, key_public_len);

	return rc;
}

/**
 * Read PCR
 * @param[in] tssContext		TSS context
 * @param[in] pcr			PCR handle
 * @param[in] halg			PCR bank
 * @param[in,out] pcr_value		PCR value
 *
 * @returns 0 on success, a negative value on error
 */
int attest_tss_pcrread(TSS_CONTEXT *tssContext, TPMI_DH_PCR pcr,
		       TPMI_ALG_HASH halg, BYTE *pcr_value)
{
	PCR_Read_In in;
	PCR_Read_Out out;
	int rc;

	in.pcrSelectionIn.count = 1;
	in.pcrSelectionIn.pcrSelections[0].sizeofSelect = 3;
	in.pcrSelectionIn.pcrSelections[0].pcrSelect[0] = 0;
	in.pcrSelectionIn.pcrSelections[0].pcrSelect[1] = 0;
	in.pcrSelectionIn.pcrSelections[0].pcrSelect[2] = 0;
	in.pcrSelectionIn.pcrSelections[0].pcrSelect[pcr / 8] = 1 << (pcr % 8);
	in.pcrSelectionIn.pcrSelections[0].hash = halg;

	rc = TSS_Execute(tssContext, (RESPONSE_PARAMETERS *)&out,
			 (COMMAND_PARAMETERS *)&in, NULL, TPM_CC_PCR_Read,
			 TPM_RH_NULL, NULL, 0);
	if (rc) {
		tss_print_error("TPM_CC_PCR_Read", rc);
		return -EINVAL;
	}

	memcpy(pcr_value, out.pcrValues.digests[0].t.buffer,
	       out.pcrValues.digests[0].t.size);

	return 0;
}

#define TYPE_ST                 2

/**
 * Load an external key
 * @param[in] tssContext		TSS context
 * @param[in] ek_pub			EK public key
 * @param[in,out] handle		EK handle
 *
 * @returns 0 on success, a negative value on error
 */
int attest_tss_loadexternal(TSS_CONTEXT *tssContext, EVP_PKEY *ek_pub,
			    TPM_HANDLE *handle)
{
	LoadExternal_In in;
	LoadExternal_Out out;
	int rc;

	in.hierarchy = TPM_RH_NULL;
	in.inPrivate.t.size = 0;

	switch (EVP_PKEY_id(ek_pub)) {
	case EVP_PKEY_RSA:
		rc = convertRsaKeyToPublic(&in.inPublic, TYPE_ST, TPM_ALG_NULL,
					   TPM_ALG_SHA256, TPM_ALG_SHA256,
					   EVP_PKEY_get0_RSA(ek_pub));
		break;
	case EVP_PKEY_EC:
		rc = convertEcKeyToPublic(&in.inPublic, TYPE_ST, TPM_ALG_NULL,
					  TPM_ALG_SHA256, TPM_ALG_SHA256,
					  EVP_PKEY_get0_EC_KEY(ek_pub));
		break;
	default:
		rc = -ENOENT;
		break;
	}

	if (rc < 0)
		return rc;

	in.inPublic.publicArea.objectAttributes.val &=
						~TPMA_OBJECT_USERWITHAUTH;

	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&out, 
			 (COMMAND_PARAMETERS *)&in,
			 NULL,
			 TPM_CC_LoadExternal,
			 TPM_RH_NULL, NULL, 0);
	if (rc) {
		tss_print_error("TPM_CC_LoadExternal", rc);
		return -EINVAL;
	}

	*handle = out.objectHandle;
	return rc;
}

/**
 * Make a credential blob
 * @param[in] tssContext		TSS context
 * @param[in] ek_handle			EK key handle
 * @param[in] cred			Credential
 * @param[in] name			AK object name
 * @param[in,out] cred_blob		Credential blob
 * @param[in,out] cred_blob_len		Credential blob length
 * @param[in,out] secret		Secret
 * @param[in,out] secret_len		Secret length
 *
 * @returns 0 on success, a negative value on error
 */
int attest_tss_makecredential(TSS_CONTEXT *tssContext, TPM_HANDLE ek_handle,
			      TPM2B_DIGEST *cred, TPM2B_NAME *name,
			      BYTE **cred_blob, UINT16 *cred_blob_len,
			      BYTE **secret, UINT16 *secret_len)
{
	MakeCredential_In in;
	MakeCredential_Out out;
	int rc;

	in.handle = ek_handle;
	in.credential.b.size = cred->b.size;
	memcpy(in.credential.b.buffer, cred->b.buffer, cred->b.size);

	in.objectName.b.size = name->b.size;
	memcpy(in.objectName.b.buffer, name->b.buffer, name->b.size);

	rc = TSS_Execute(tssContext, (RESPONSE_PARAMETERS *)&out,
			 (COMMAND_PARAMETERS *)&in, NULL, TPM_CC_MakeCredential,
			 TPM_RH_NULL, NULL, 0);
	if (rc < 0) {
		tss_print_error("TPM_CC_MakeCredential", rc);
		return -EINVAL;
	}

	*cred_blob_len = 0;
	*cred_blob = NULL;

	rc = TSS_Structure_Marshal(cred_blob, cred_blob_len,
				&out.credentialBlob,
				(MarshalFunction_t)TSS_TPM2B_ID_OBJECT_Marshal);
	if (rc) {
		rc = -EINVAL;
		goto out;
	}

	*secret_len = 0;
	*secret = NULL;

	rc = TSS_Structure_Marshal(secret, secret_len, &out.secret,
			(MarshalFunction_t)TSS_TPM2B_ENCRYPTED_SECRET_Marshal);
out:
	if (rc) {
		if (*cred_blob)
			free(*cred_blob);
		if (*secret)
			free(*secret);
	}

	return rc;
}

/**
 * Make a quote
 * @param[in] tssContext	TSS context
 * @param[in] ak_handle		AK handle
 * @param[in] ak_public_len	Marshalled AK length
 * @param[in] ak_public		Marshalled AK
 * @param[in] nonce_len		Nonce length
 * @param[in] nonce		Nonce
 * @param[in] pcrSelection	PCR selection
 * @param[in,out] quote_len	Quote length
 * @param[in,out] quote		Quote
 * @param[in,out] signature_len	Signature length
 * @param[in,out] signature	Signature
 *
 * @returns 0 on success, a negative value on error
 */
int attest_tss_quote(TSS_CONTEXT *tssContext, TPM_HANDLE ak_handle,
		     UINT16 ak_public_len, BYTE *ak_public, UINT16 nonce_len,
		     const BYTE *nonce, const TPML_PCR_SELECTION *pcrSelection,
		     UINT16 *quote_len, BYTE **quote, UINT16 *signature_len,
		     BYTE **signature)
{
	TPM_RC rc = 0;
	TPM2B_PUBLIC ak;
	INT32 len = ak_public_len;
	TPMU_PUBLIC_PARMS *params;
	Quote_In in;
	Quote_Out out;

	rc = TPM2B_PUBLIC_Unmarshal(&ak, &ak_public, &len, 0);
	if (rc)
		return -EINVAL;

	params = &ak.publicArea.parameters;

	switch(ak.publicArea.type) {
	case TPM_ALG_RSA:
		in.inScheme.scheme = params->rsaDetail.scheme.scheme;
		in.inScheme.details.rsassa.hashAlg =
				params->rsaDetail.scheme.details.rsassa.hashAlg;
		break;
	case TPM_ALG_ECC:
		in.inScheme.scheme = params->eccDetail.scheme.scheme;
		in.inScheme.details.ecdsa.hashAlg =
				params->eccDetail.scheme.details.ecdsa.hashAlg;
		break;
	default:
		return -EINVAL;
	}

	in.signHandle = ak_handle;
	in.PCRselect.count = 1;
	in.PCRselect = *pcrSelection;

	if (nonce_len > sizeof(in.qualifyingData.t.buffer))
		return -EINVAL;

	memcpy(in.qualifyingData.t.buffer, nonce, nonce_len);
	in.qualifyingData.t.size = nonce_len;

	rc = TSS_Execute(tssContext, (RESPONSE_PARAMETERS *)&out,
			 (COMMAND_PARAMETERS *)&in, NULL, TPM_CC_Quote,
			 TPM_RS_PW, NULL, 0, TPM_RH_NULL, NULL, 0);
	if (rc) {
		tss_print_error("TPM_CC_Quote", rc);
		return -EINVAL;
	}

	*quote_len = out.quoted.t.size;
	*quote = malloc(*quote_len);
	if (!*quote)
		return -ENOMEM;

	memcpy(*quote, out.quoted.t.attestationData, *quote_len);

	*signature_len = 0;
	*signature = NULL;

	rc = TSS_Structure_Marshal(signature, signature_len, &out.signature,
			(MarshalFunction_t)TSS_TPMT_SIGNATURE_Marshal);

	if (rc) {
		if (*quote)
			free(*quote);
		if (*signature)
			free(*signature);
	}

	return rc;
}
/** @}*/
