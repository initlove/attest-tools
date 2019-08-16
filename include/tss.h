#ifndef _TSS_H
#define _TSS_H

#include <tss2/tss.h>
#include <tss2/tssmarshal.h>
#include <tss2/Unmarshal_fp.h>
#include <tss2/tssutils.h>
#include <tss2/tssresponsecode.h>

#include <tss2/ekutils.h>

int tss_nvreadpublic(TSS_CONTEXT *tssContext, int nvIndex, size_t *nvdata_len);
int tss_nvread(TSS_CONTEXT *tssContext, int nvIndex, size_t nvdata_len,
	       BYTE **nvdata);
int tss_getekcert(TSS_CONTEXT *tssContext, TPMI_ALG_PUBLIC algPublic,
		  size_t *nvdata_len, BYTE **nvdata);
int tss_create(TSS_CONTEXT *tssContext, TPMI_ALG_PUBLIC algPublic,
	       TPMI_ECC_CURVE curveID, TPMI_ALG_HASH nalg, TPMI_ALG_HASH halg,
	       int restricted, UINT16 *private_len, BYTE **private,
	       UINT16 *public_len, BYTE **public);
int tss_createek(TSS_CONTEXT *tssContext, TPMI_ALG_PUBLIC algPublic,
		 TPM_HANDLE *keyHandle);
int tss_load(TSS_CONTEXT *tssContext, UINT16 private_len, BYTE *private,
	     UINT16 public_len, BYTE *public, TPM_HANDLE *keyHandle);
int tss_startauthsession(TSS_CONTEXT *tssContext,
			 TPMI_SH_AUTH_SESSION *sessionHandle);
int tss_policysecret(TSS_CONTEXT *tssContext,
		     TPMI_SH_AUTH_SESSION sessionHandle);
int tss_flushcontext(TSS_CONTEXT *tssContext, TPM_HANDLE handle);
int tss_activatecredential(TSS_CONTEXT *tssContext, TPM_HANDLE activateHandle,
                           TPM_HANDLE keyHandle, UINT16 credentialblob_len,
                           BYTE *credentialblob, UINT16 secret_len,
                           BYTE *secret, UINT16 *credential_len,
                           BYTE **credential);

#endif /*_TSS_H*/
