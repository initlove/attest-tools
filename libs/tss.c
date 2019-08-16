/** @defgroup tss-api TSS API
 *  @ingroup user-api
 *  TSS API
 */

/**
 * @name TSS API
 * \addtogroup tss-api
 *  @{
 */

#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>

#include "tss.h"

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
int tss_nvreadpublic(TSS_CONTEXT *tssContext, int nvIndex, size_t *nvdata_len)
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
int tss_nvread(TSS_CONTEXT *tssContext, int nvIndex, size_t nvdata_len,
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
int tss_getekcert(TSS_CONTEXT *tssContext, TPMI_ALG_PUBLIC algPublic,
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

	rc = tss_nvreadpublic(tssContext, nvIndex, nvdata_len);
	if (rc)
		return rc;

	return tss_nvread(tssContext, nvIndex, *nvdata_len, nvdata);
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
	publicArea->objectAttributes.val |= TPMA_OBJECT_SIGN;
	publicArea->type = algPublic;
	publicArea->nameAlg = nalg;

	if (restricted)
		publicArea->objectAttributes.val |= TPMA_OBJECT_RESTRICTED;

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

/**
 * Create TPM key
 * @param[in] tssContext	TSS context
 * @param[in] algPublic		EK algorithm
 * @param[in] curveID		Elliptic Curve identifier
 * @param[in] nalg		Object name algorithm
 * @param[in] halg		Hash algorithm
 * @param[in] restricted	Restricted or unrestricted key
 * @param[in,out] private_len	New key private part length
 * @param[in,out] private	New key private part
 * @param[in,out] public_len	New key public part length
 * @param[in,out] public	New key public part
 *
 * @returns 0 on success, a negative value on error
 */
int tss_create(TSS_CONTEXT *tssContext, TPMI_ALG_PUBLIC algPublic,
	       TPMI_ECC_CURVE curveID, TPMI_ALG_HASH nalg, TPMI_ALG_HASH halg,
	       int restricted, UINT16 *private_len, BYTE **private,
	       UINT16 *public_len, BYTE **public)
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
	rc = asymPublicTemplate(&in.inPublic.publicArea, algPublic,
				TPM_ECC_NONE, nalg, halg, restricted, NULL);
	if (rc)
		return -EINVAL;

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
int tss_createek(TSS_CONTEXT *tssContext, TPMI_ALG_PUBLIC algPublic,
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
 * @param[in] algPublic		EK algorithm
 * @param[in] private_len	New key private part length
 * @param[in] private		New key private part
 * @param[in] public_len	New key public part length
 * @param[in] public		New key public part
 * @param[in,out] keyHandle	EK handle
 *
 * @returns 0 on success, a negative value on error
 */
int tss_load(TSS_CONTEXT *tssContext, UINT16 private_len, BYTE *private,
	     UINT16 public_len, BYTE *public, TPM_HANDLE *keyHandle)
{
	Load_In in;
	Load_Out out;
	int rc;

	in.parentHandle = 0x81000001;

	rc = TPM2B_PRIVATE_Unmarshal(&in.inPrivate, &private,
				     (INT32 *)&private_len);
	if (rc)
		return -EINVAL;

	rc = TPM2B_PUBLIC_Unmarshal(&in.inPublic, &public,
				    (INT32 *)&public_len, FALSE);
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
int tss_startauthsession(TSS_CONTEXT *tssContext,
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
int tss_policysecret(TSS_CONTEXT *tssContext,
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
int tss_flushcontext(TSS_CONTEXT *tssContext, TPM_HANDLE handle)
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
 * Flush context
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
int tss_activatecredential(TSS_CONTEXT *tssContext, TPM_HANDLE activateHandle,
			   TPM_HANDLE keyHandle, UINT16 credentialblob_len,
			   BYTE *credentialblob, UINT16 secret_len,
			   BYTE *secret, UINT16 *credential_len,
			   BYTE **credential)
{
	TPMI_SH_AUTH_SESSION sessionHandle;
	ActivateCredential_In in;
	ActivateCredential_Out out;
	int rc;

	in.activateHandle = activateHandle;
	in.keyHandle = keyHandle;

	rc = TPM2B_ID_OBJECT_Unmarshal(&in.credentialBlob, &credentialblob,
				       (INT32 *)&credentialblob_len);
	if (rc)
		return -EINVAL;

	rc = TPM2B_ENCRYPTED_SECRET_Unmarshal(&in.secret, &secret,
					      (INT32 *)&secret_len);
	if (rc)
		return -EINVAL;

	rc = tss_startauthsession(tssContext, &sessionHandle);
	if (rc)
		return -EINVAL;

	rc = tss_policysecret(tssContext, sessionHandle);
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

	*credential = malloc(out.certInfo.t.size);
	if (!*credential)
		rc = -ENOMEM;
	else
		rc = 0;

	*credential_len = out.certInfo.t.size;
	memcpy(*credential, out.certInfo.t.buffer, out.certInfo.t.size);
out:
	if (rc == -EINVAL)
		tss_flushcontext(tssContext, sessionHandle);
	return rc;
}
/** @}*/
