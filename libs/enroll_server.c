/*
 * Copyright (C) 2019 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 *
 * File: enroll_server.c
 *      Server side enrollment functions.
 */

/**
 * @defgroup enroll-server-api Server Side Enrollment API
 * @ingroup enroll-api
 * @brief
 * Functions to parse enrollment requests and generate responses for a client.
 * @addtogroup enroll-server-api
 *  @{
 */

#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/wait.h>

#include "ctx_json.h"
#include "crypto.h"
#include "skae.h"
#include "util.h"
#include "tss.h"
#include "verifier.h"
#include "enroll_server.h"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>

#include <ibmtss/ekutils.h>
#include <ibmtss/cryptoutils.h>

#define NONCE_LEN 32

int verbose;

/**
 * Perform HMAC of AK and credential to correlate challenge and certificate reqs
 * @param[in] v_ctx		verifier context
 * @param[in] akpub_len		AK public part length
 * @param[in] akpub		AK public part
 * @param[in] credential_len	Credential length
 * @param[in] credential	Credential
 * @param[in,out] hmac_len	Length of HMAC buffer
 * @param[in,out] hmac		HMAC buffer
 *
 * @returns 0 on success, a negative value on error
 */
int attest_enroll_hmac(attest_ctx_verifier *v_ctx, int akpub_len, BYTE *akpub,
		       int credential_len, BYTE *credential,
		       unsigned int *hmac_len, BYTE *hmac)
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

static int attest_enroll_verify_hmac(attest_ctx_data *d_ctx_in,
				     attest_ctx_verifier *v_ctx,
				     struct data_item *item,
				     struct data_item *ak,
				     enum ctx_fields field_hmac)
{
	struct data_item *item_hmac;
	BYTE hmac[EVP_MAX_MD_SIZE];
	unsigned int hmac_len = sizeof(hmac);
	struct verification_log *log;
	int rc;

	log = attest_ctx_verifier_add_log(v_ctx, "verify HMAC");

	item_hmac = attest_ctx_data_get(d_ctx_in, field_hmac);
	check_goto(!item_hmac, -ENOENT, out, v_ctx, "HMAC not provided");

	rc = attest_enroll_hmac(v_ctx, ak->len, ak->data, item->len, item->data,
				&hmac_len, hmac);
	check_goto(rc, -EINVAL, out, v_ctx, "attest_enroll_hmac() error");

	check_goto((item_hmac->len != hmac_len), -EINVAL, out, v_ctx,
		   "credential HMAC length mismatch");

	check_goto(memcmp(hmac, item_hmac->data, item_hmac->len), -EINVAL, out,
		   v_ctx, "HMAC mismatch");
out:
	attest_ctx_verifier_end_log(v_ctx, log, rc);
	return rc;
}

static char *name_fields[] = {
	"countryName",
	"stateOrProvinceName",
	"localityName",
	"organizationName",
	"organizationalUnitName",
	"commonName",
	"emailAddress",
	NULL
};

/**
 * Make a certificate
 * @param[in] d_ctx_in		input data context
 * @param[in] d_ctx_out		output data context
 * @param[in] v_ctx		verifier context
 * @param[in] pcaKeyPath	Privacy CA private key path
 * @param[in] pcaKeyPassword	Privacy CA private key password
 * @param[in,out] pcaCertPath	Privacy CA certificate
 *
 * @returns 0 on success, a negative value on error
 */
int attest_enroll_make_cert(attest_ctx_data *d_ctx_in,
			    attest_ctx_data *d_ctx_out,
			    attest_ctx_verifier *v_ctx, char *pcaKeyPath,
			    char *pcaKeyPassword, char *pcaCertPath)
{
	BYTE *attestCertBin = NULL;
	char *akX509CertString = NULL, *akCertPemString = NULL;
	UINT32 attestCertBinLen = 0;
	struct verification_log *log;
	struct data_item *ak, *cred, *hostname;
	TPM2B_PUBLIC pub;
	BYTE *buffer_ptr;
	INT32 buffer_len;
	X509 *issuer_cert = NULL;
	X509_NAME *issuer_name = NULL;
	FILE *fp = NULL;
	int rc, i;

        char *subjectEntries[] = {
		"DE",
		"Bayern",
		"Muenchen",
		"Huawei",
		NULL,
		NULL,
		NULL
	};

        char *issuerEntries[] = {
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL
	};

	log = attest_ctx_verifier_add_log(v_ctx, "create certificate");

	hostname = attest_ctx_data_get(d_ctx_in, CTX_HOSTNAME);
	check_goto(!hostname, -ENOENT, out, v_ctx,
		   "Hostname not provided");

	subjectEntries[5] = (char *)hostname->data;

	fp = fopen(pcaCertPath, "r");
	check_goto(!fp, -EACCES, out, v_ctx, "CA cert not found");

	issuer_cert = PEM_read_X509(fp, NULL, NULL, NULL);
	check_goto(!issuer_cert, -EINVAL, out, v_ctx,
		   "CA cert cannot be parsed");

	issuer_name = X509_get_subject_name(issuer_cert);

	for (i = 0; name_fields[i]; i++) {
		char buf[128];

		rc = X509_NAME_get_text_by_NID(issuer_name,
					  OBJ_txt2nid(name_fields[i]),
					  buf, sizeof(buf));

		if (rc == -1)
			continue;

		issuerEntries[i] = strdup(buf);
		check_goto(!issuerEntries[i], -ENOMEM, out, v_ctx,
			"Out of memory");
	}

	ak = attest_ctx_data_get(d_ctx_in, CTX_TPM_AK_KEY);
	check_goto(!ak, -ENOENT, out, v_ctx,
		   "TPM attestation key not provided");

	cred = attest_ctx_data_get(d_ctx_in, CTX_CRED);
	check_goto(!cred, -ENOENT, out, v_ctx, "Credential not provided");

	rc = attest_enroll_verify_hmac(d_ctx_in, v_ctx, cred, ak,
				       CTX_CRED_HMAC);
	check_goto(rc, rc, out, v_ctx,
		   "attest_enroll_verify_hmac() error: %d", rc);

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
	if (fp)
		fclose(fp);
	if (issuer_cert)
		X509_free(issuer_cert);
	for (i = 0; name_fields[i]; i++)
		free(issuerEntries[i]);

	attest_ctx_verifier_end_log(v_ctx, log, rc);
	return rc;
}

/**
 * Make a credential blob
 * @param[in] d_ctx_in		input data context
 * @param[in] d_ctx_out		output data context
 * @param[in] v_ctx		verifier context
 *
 * @returns 0 on success, a negative value on error
 */
int attest_enroll_make_credential(attest_ctx_data *d_ctx_in,
				  attest_ctx_data *d_ctx_out,
				  attest_ctx_verifier *v_ctx)
{
	struct verification_log *log;
	TPM2B_NAME name;
	X509 *cert;
	EVP_PKEY *evpPkey;
	TPM2B_DIGEST cred;
	UINT16 cred_blob_len, secret_len = 0;
	BYTE *cred_blob = NULL, *secret = NULL;
	BYTE hmac[EVP_MAX_MD_SIZE];
	TPM_HANDLE ek_handle;
	TPM_ALG_ID nameAlg;
	void *tssContext;
	unsigned int hmac_len = sizeof(hmac);
	struct data_item *ak;
	UINT32 req_mask = (TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT |
			   TPMA_OBJECT_SENSITIVEDATAORIGIN | TPMA_OBJECT_SIGN |
			   TPMA_OBJECT_RESTRICTED);
	int rc;

	log = attest_ctx_verifier_add_log(v_ctx, "make credential");

	rc = TSS_Create((TSS_CONTEXT **)&tssContext);
	check_goto(rc, -EACCES, out, v_ctx, "TSS_Create() error: %d", rc);

	ak = attest_ctx_data_get(d_ctx_in, CTX_TPM_AK_KEY);
	check_goto(!ak, -ENOENT, out_tpm, v_ctx,
		   "TPM attestation key not provided");

	rc = attest_verifier_check_tpm2b_public(d_ctx_in, v_ctx, ak->len,
						ak->data, 0, req_mask,
						CTX__LAST, &nameAlg, &name);
	check_goto(rc, rc, out_tpm, v_ctx,
		   "attest_verifier_check_tpm2b_public() error: %d", rc);

	rc = attest_crypto_verify_cert(d_ctx_in, v_ctx, CTX_EK_CERT,
				       CTX_EK_CA_CERT, &cert);
	check_goto(rc, rc, out_tpm, v_ctx,
		   "attest_crypto_verify_cert() error: %d", rc);

	evpPkey = X509_get0_pubkey(cert);
	check_goto(!evpPkey, -ENOENT, out_cert, v_ctx,
		   "X509_get_pubkey() error");

	check_goto(rc, -EINVAL, out_cert, v_ctx, "convert key to public error");

	cred.t.size = EVP_MD_size(EVP_sha256());

	rc = RAND_bytes(cred.t.buffer, cred.t.size);
	check_goto(!rc, -EIO, out_cert, v_ctx, "RAND_bytes() error");

	rc = attest_tss_loadexternal(tssContext, evpPkey, &ek_handle);
	check_goto(rc, rc, out_cert, v_ctx, "attest_tss_load_external() error");

	rc = attest_tss_makecredential(tssContext, ek_handle, &cred, &name,
				       &cred_blob, &cred_blob_len, &secret,
				       &secret_len);
	check_goto(rc, rc, out_cert, v_ctx,
		   "attest_tss_make_credential() error");

	rc = attest_ctx_data_add(d_ctx_out, CTX_CREDBLOB, cred_blob_len,
				 cred_blob, NULL);
	check_goto(rc, rc, out_flush, v_ctx,
		   "attest_ctx_data_add_copy() error");

	rc = attest_ctx_data_add(d_ctx_out, CTX_SECRET, secret_len, secret,
				 NULL);
	check_goto(rc, rc, out_flush, v_ctx,
		   "attest_ctx_data_add_copy() error");

	rc = attest_enroll_hmac(v_ctx, ak->len, ak->data, cred.t.size,
				cred.t.buffer, &hmac_len, hmac);
	check_goto(rc, rc, out_flush, v_ctx, "attest_enroll_hmac() error");

	rc = attest_ctx_data_add_copy(d_ctx_out, CTX_CRED_HMAC, hmac_len,
				      hmac, NULL);
	check_goto(rc, rc, out_flush, v_ctx,
		   "attest_ctx_data_add_copy() error");
out_flush:
	attest_tss_flushcontext(tssContext, ek_handle);
out_cert:
	X509_free(cert);
out_tpm:
	TSS_Delete(tssContext);
out:
	attest_ctx_verifier_end_log(v_ctx, log, rc);
	return rc;
}

/**
 * Process a CSR for a TPM key
 * @param[in] d_ctx_in		input data context
 * @param[in] v_ctx		verifier context
 * @param[in] reqPath		Path of requirements for TPM key policy check
 * @param[in,out] csr_str	CSR in PEM format
 *
 * @returns 0 on success, a negative value on error
 */
int attest_enroll_process_csr(attest_ctx_data *d_ctx_in,
			      attest_ctx_verifier *v_ctx, char *reqPath,
			      char **csr_str)
{
	X509_REQ *req = NULL;
	EVP_PKEY *pktmp = NULL;
	struct data_item *csr;
	unsigned char *data_ptr;
	struct verification_log *log;
	char *reqs, *data;
	BIO *bio = NULL;
	int rc = 0, csr_str_len;

	log = attest_ctx_verifier_add_log(v_ctx, "verify CSR");

	csr = attest_ctx_data_get(d_ctx_in, CTX_CSR);
	if (!csr) {
		printf("CSR not provided\n");
		return -ENOENT;
	}

	data_ptr = csr->data;

	req = d2i_X509_REQ(&req, (const unsigned char **)&data_ptr, csr->len);
	if (!req)
		goto out;

	pktmp = X509_REQ_get0_pubkey(req);
	if (!pktmp) {
		printf("error unpacking public key\n");
		goto out;
	}

	rc = X509_REQ_verify(req, pktmp);
	if (rc < 0) {
		printf("Signature verification problems....\n");
		rc = -EINVAL;
		goto out;
	} else if (!rc) {
		printf("Signature did not match the certificate request\n");
		rc = -EINVAL;
		goto out;
	}

	rc = attest_ctx_verifier_req_add_json_file(v_ctx, reqPath);
	if (rc < 0) {
		printf("Verifier's requirements not provided\n");
		goto out;
	}

	printf("Processing SKAE with the following requirements:\n");
	reqs = attest_ctx_verifier_req_print_json(v_ctx);
	printf("%s\n", reqs);
	free(reqs);

	rc = skae_verify_x509_req(d_ctx_in, v_ctx, req);
	if (rc != 1) {
		rc = -EINVAL;
		goto out;
	}

	bio = BIO_new(BIO_s_mem());
	if (!bio) {
		rc = -ENOMEM;
		goto out;
	}

	rc = PEM_write_bio_X509_REQ(bio, req);
	if (rc != 1) {
		rc = -EINVAL;
		goto out;
	}

	csr_str_len = BIO_get_mem_data(bio, &data);

	*csr_str = malloc(csr_str_len + 1);
	if (!*csr_str) {
		rc = -ENOMEM;
		goto out;
	}

	rc = BIO_read(bio, *csr_str, csr_str_len);
	if (rc <= 0) {
		rc = -EIO;
		goto out;
	}

	memcpy(*csr_str, data, csr_str_len);
	(*csr_str)[csr_str_len] = '\0';
	rc = 0;
out:
	X509_REQ_free(req);
	if (bio)
		BIO_free(bio);

	attest_ctx_verifier_end_log(v_ctx, log, rc);
	return rc;
}

/**
 * Sign a CSR
 * @param[in] caKeyPath	CA private key path
 * @param[in] caKeyPassword	CA private key password
 * @param[in] caCertPath	CA certificate path
 * @param[in] csr_str	CSR to sign
 * @param[in,out] cert_str	Signed certificate
 *
 * @returns 0 on success, a negative value on error
 */
int attest_enroll_sign_csr(char *caKeyPath, char *caKeyPassword,
			   char *caCertPath, char *csr_str, char **cert_str)
{
	attest_ctx_data *d_ctx_in = NULL;
	char path_csr[PATH_MAX];
	char path_cert[PATH_MAX];
	char pass_arg[64];
	size_t len;
	int rc = -EINVAL, status;

	attest_ctx_data_init(&d_ctx_in);

	snprintf(path_csr, sizeof(path_csr), "%s/csr.pem", d_ctx_in->data_dir);
	snprintf(path_cert, sizeof(path_cert),
		 "%s/cert.pem", d_ctx_in->data_dir);

	snprintf(pass_arg, sizeof(pass_arg), "pass:%s", caKeyPassword);

	rc = attest_util_write_file(path_csr, strlen(csr_str),
				    (uint8_t *)csr_str, 0);
	if (rc < 0)
		return rc;

	if (!fork())
		return execlp("openssl", "openssl", "ca", "-cert", caCertPath,
			      "-keyfile", caKeyPath, "-passin", pass_arg,
			      "-in", path_csr, "-out", path_cert, "-batch",
			      NULL);

	wait(&status);

	if (status)
		goto out;

	rc = attest_util_read_seq_file(path_cert, &len, (uint8_t **)cert_str);
out:
	unlink(path_cert);
	unlink(path_csr);

	attest_ctx_data_cleanup(d_ctx_in);

	return rc;
}

/**
 * @name Protocol API
 *  @{
 */

/**
 * Make a credential blob message
 * @param[in] hmac_key		HMAC key to correlate client requests
 * @param[in] hmac_key_len	HMAC key length
 * @param[in] pcaKeyPath	Privacy CA private key path
 * @param[in] pcaKeyPassword	Privacy CA private key password
 * @param[in] pcaCertPath	Privacy CA certificate path
 * @param[in] message_in	Request sent by the client
 * @param[in,out] message_out	Response to be sent to the client
 *
 * @returns 0 on success, a negative value on error
 */
int attest_enroll_msg_make_credential(uint8_t *hmac_key, int hmac_key_len,
				      char *pcaKeyPath, char *pcaKeyPassword,
				      char *pcaCertPath, char *message_in,
				      char **message_out)
{
	attest_ctx_data *d_ctx_in = NULL, *d_ctx_out = NULL;
	attest_ctx_verifier *v_ctx = NULL;
#ifdef DEBUG
	char *message_in_stripped, *message_out_stripped;
#endif
	char *logs;
	int rc;

	attest_ctx_data_init(&d_ctx_in);
	attest_ctx_data_init(&d_ctx_out);
	attest_ctx_verifier_init(&v_ctx);
	attest_ctx_verifier_set_key(v_ctx, hmac_key_len, hmac_key);

	rc = attest_ctx_data_add_json_data(d_ctx_in, message_in,
					   strlen(message_in));
	if (rc < 0)
		goto out;
#ifdef DEBUG
	attest_ctx_data_print_json_no_value(d_ctx_in, &message_in_stripped);
	printf("<- %s\n", message_in_stripped);
	free(message_in_stripped);
#endif
	rc = attest_enroll_make_credential(d_ctx_in, d_ctx_out, v_ctx);

	logs = attest_ctx_verifier_result_print_json(v_ctx);
	printf("%s\n", logs);
	free(logs);

	if (rc < 0)
		goto out;

	rc = attest_ctx_data_print_json(d_ctx_out, message_out);
	if (rc)
		goto out;
#ifdef DEBUG
	attest_ctx_data_print_json_no_value(d_ctx_out, &message_out_stripped);
	printf("-> %s\n", message_out_stripped);
	free(message_out_stripped);
#endif
out:
	attest_ctx_data_cleanup(d_ctx_in);
	attest_ctx_data_cleanup(d_ctx_out);
	attest_ctx_verifier_cleanup(v_ctx);
	return rc;
}

/**
 * Make a certificate message
 * @param[in] hmac_key		HMAC key to correlate client requests
 * @param[in] hmac_key_len	HMAC key length
 * @param[in] pcaKeyPath	Privacy CA private key path
 * @param[in] pcaKeyPassword	Privacy CA private key password
 * @param[in] pcaCertPath	Privacy CA certificate path
 * @param[in] message_in	Request sent by the client
 * @param[in,out] message_out	Response to be sent to the client
 *
 * @returns 0 on success, a negative value on error
 */
int attest_enroll_msg_make_cert(uint8_t *hmac_key, int hmac_key_len,
				char *pcaKeyPath, char *pcaKeyPassword,
				char *pcaCertPath, char *message_in,
				char **message_out)
{
	attest_ctx_data *d_ctx_in = NULL, *d_ctx_out = NULL;
	attest_ctx_verifier *v_ctx = NULL;
#ifdef DEBUG
	char *message_in_stripped, *message_out_stripped;
#endif
	char *logs;
	int rc;

	attest_ctx_data_init(&d_ctx_in);
	attest_ctx_data_init(&d_ctx_out);
	attest_ctx_verifier_init(&v_ctx);
	attest_ctx_verifier_set_key(v_ctx, hmac_key_len, hmac_key);

	rc = attest_ctx_data_add_json_data(d_ctx_in, message_in,
					   strlen(message_in));
	if (rc < 0)
		goto out;
#ifdef DEBUG
	attest_ctx_data_print_json_no_value(d_ctx_in, &message_in_stripped);
	printf("<- %s\n", message_in_stripped);
	free(message_in_stripped);
#endif
	rc = attest_enroll_make_cert(d_ctx_in, d_ctx_out, v_ctx, pcaKeyPath,
				     pcaKeyPassword, pcaCertPath);
	if (rc < 0)
		goto out;

	logs = attest_ctx_verifier_result_print_json(v_ctx);
	printf("%s\n", logs);
	free(logs);

	if (rc < 0)
		goto out;

	rc = attest_ctx_data_print_json(d_ctx_out, message_out);
	if (rc)
		goto out;
#ifdef DEBUG
	attest_ctx_data_print_json_no_value(d_ctx_out, &message_out_stripped);
	printf("-> %s\n", message_out_stripped);
	free(message_out_stripped);
#endif
out:
	attest_ctx_data_cleanup(d_ctx_in);
	attest_ctx_data_cleanup(d_ctx_out);
	attest_ctx_verifier_cleanup(v_ctx);
	return rc;
}

/**
 * Process a CSR message
 * @param[in] pcr_mask_len	Length of required PCR mask
 * @param[in] pcr_mask		Mask of PCR to check
 * @param[in] reqPath		Path of requirements for TPM key policy check
 * @param[in] ima_violations	allow IMA violations
 * @param[in] message_in	input message
 * @param[in,out] csr_str	CSR in PEM format
 *
 * @returns 0 on success, a negative value on error
 */
int attest_enroll_msg_process_csr(int pcr_mask_len, uint8_t *pcr_mask,
				  char *reqPath, int ima_violations,
				  char *message_in, char **csr_str)
{
	attest_ctx_data *d_ctx_in = NULL;
	attest_ctx_verifier *v_ctx = NULL;
#ifdef DEBUG
	char *message_in_stripped;
#endif
	char *logs;
	int rc;

	attest_ctx_data_init(&d_ctx_in);
	attest_ctx_verifier_init(&v_ctx);
	attest_ctx_verifier_set_pcr_mask(v_ctx, pcr_mask_len, pcr_mask);
	if (ima_violations)
		attest_ctx_verifier_allow_ima_violations(v_ctx);

	rc = attest_ctx_data_add_json_data(d_ctx_in, message_in,
					   strlen(message_in));
	if (rc < 0)
		goto out;
#ifdef DEBUG
	attest_ctx_data_print_json_no_value(d_ctx_in, &message_in_stripped);
	printf("<- %s\n", message_in_stripped);
	free(message_in_stripped);
#endif
	rc = attest_enroll_process_csr(d_ctx_in, v_ctx, reqPath, csr_str);

	logs = attest_ctx_verifier_result_print_json(v_ctx);
	printf("%s\n", logs);
	free(logs);
out:
	attest_ctx_data_cleanup(d_ctx_in);
	attest_ctx_verifier_cleanup(v_ctx);
	return rc;
}

/**
 * Send signed certificate to client
 *
 * @param[in] cert_str	Signed certificate
 * @param[in] ca_cert_str	CA certificate
 * @param[in,out] message_out	Response for the client
 *
 * @returns 0 on success, a negative value on error
 */
int attest_enroll_msg_return_cert(char *cert_str, char *ca_cert_str,
				  char **message_out)
{
	attest_ctx_data *d_ctx_out = NULL;
#ifdef DEBUG
	char *message_out_stripped;
#endif
	int rc;

	attest_ctx_data_init(&d_ctx_out);

	rc = attest_ctx_data_add_copy(d_ctx_out, CTX_KEY_CERT, strlen(cert_str),
				      (uint8_t*)cert_str, NULL);
	if (rc < 0)
		goto out;

	rc = attest_ctx_data_add_copy(d_ctx_out, CTX_CA_CERT, strlen(ca_cert_str),
				      (uint8_t*)ca_cert_str, NULL);
	if (rc < 0)
		goto out;

	rc = attest_ctx_data_print_json(d_ctx_out, message_out);
#ifdef DEBUG
	attest_ctx_data_print_json_no_value(d_ctx_out, &message_out_stripped);
	printf("-> %s\n", message_out_stripped);
	free(message_out_stripped);
#endif
out:
	attest_ctx_data_cleanup(d_ctx_out);
	return rc;
}

/**
 * Generate a quote nonce response
 * @param[in] hmac_key_len	HMAC key length
 * @param[in] hmac_key		HMAC key to correlate client requests
 * @param[in,out] message_out	Message containing quote nonce response
 *
 * @returns 0 on success, a negative value on error
 */
int attest_enroll_msg_gen_quote_nonce(int hmac_key_len, uint8_t *hmac_key,
				      char *message_in, char **message_out)
{
#ifdef DEBUG
	char *message_in_stripped;
	char *message_out_stripped;
#endif
	attest_ctx_data *d_ctx_in, *d_ctx_out;
	attest_ctx_verifier *v_ctx;
	struct verification_log *log;
	uint8_t nonce[NONCE_LEN], hmac[EVP_MAX_MD_SIZE];
	unsigned int hmac_len = sizeof(hmac);
	struct data_item *ak_cert;
	char *logs;
	int rc;

	attest_ctx_data_init(&d_ctx_in);
	attest_ctx_data_init(&d_ctx_out);
	attest_ctx_verifier_init(&v_ctx);
	attest_ctx_verifier_set_key(v_ctx, hmac_key_len, hmac_key);

	log = attest_ctx_verifier_add_log(v_ctx, "generate quote nonce");

	rc = attest_ctx_data_add_json_data(d_ctx_in, message_in,
					   strlen(message_in));
	check_goto(rc, rc, out, v_ctx, "attest_ctx_data_add_json_data() error");
#ifdef DEBUG
	attest_ctx_data_print_json_no_value(d_ctx_in, &message_in_stripped);
	printf("<- %s\n", message_in_stripped);
	free(message_in_stripped);
#endif
	ak_cert = attest_ctx_data_get(d_ctx_in, CTX_AIK_CERT);
	check_goto(!ak_cert, -ENOENT, out, v_ctx,
		   "AK certificate not provided");

	rc = RAND_bytes(nonce, sizeof(nonce));
	check_goto(!rc, -EIO, out, v_ctx, "RAND_bytes() error");

	rc = attest_ctx_data_add_copy(d_ctx_out, CTX_NONCE, sizeof(nonce),
				      nonce, NULL);
	check_goto(rc, rc, out, v_ctx, "attest_ctx_data_add() error");

	rc = attest_enroll_hmac(v_ctx, ak_cert->len, ak_cert->data,
				sizeof(nonce), nonce, &hmac_len, hmac);
	check_goto(rc, rc, out, v_ctx, "attest_enroll_hmac() error");

	rc = attest_ctx_data_add_copy(d_ctx_out, CTX_NONCE_HMAC, hmac_len,
				      hmac, NULL);
#ifdef DEBUG
	attest_ctx_data_print_json_no_value(d_ctx_out, &message_out_stripped);
	printf("<- %s\n", message_out_stripped);
	free(message_out_stripped);
#endif
	if (rc < 0)
		goto out;

	rc = attest_ctx_data_print_json(d_ctx_out, message_out);
out:
	attest_ctx_verifier_end_log(v_ctx, log, rc);

	logs = attest_ctx_verifier_result_print_json(v_ctx);
	printf("%s\n", logs);
	free(logs);

	attest_ctx_data_cleanup(d_ctx_in);
	attest_ctx_data_cleanup(d_ctx_out);
	attest_ctx_verifier_cleanup(v_ctx);
	return rc;
}

/**
 * Process a quote message
 * @param[in] hmac_key_len	HMAC key length
 * @param[in] hmac_key		HMAC key to correlate client requests
 * @param[in] pcr_mask_len	Length of required PCR mask
 * @param[in] pcr_mask		Mask of PCR to check
 * @param[in] reqPath		Path of requirements for TPM key policy check
 * @param[in] ima_violations	allow IMA violations
 * @param[in] message_in	input message
 * @param[in,out] message_out	output message
 *
 * @returns 0 on success, a negative value on error
 */
int attest_enroll_msg_process_quote(int hmac_key_len, uint8_t *hmac_key,
				    int pcr_mask_len, uint8_t *pcr_mask,
				    char *reqPath, int ima_violations,
				    char *message_in, char **message_out)
{
	attest_ctx_data *d_ctx = NULL;
	attest_ctx_verifier *v_ctx = NULL;
	struct verification_log *log;
	struct data_item *ak_cert, *nonce, *tpms_attest, *tpms_attest_sig;
#ifdef DEBUG
	char *message_in_stripped;
#endif
	char *logs, *reqs;
	int rc;

	attest_ctx_data_init(&d_ctx);
	attest_ctx_verifier_init(&v_ctx);
	attest_ctx_verifier_set_pcr_mask(v_ctx, pcr_mask_len, pcr_mask);
	attest_ctx_verifier_set_key(v_ctx, hmac_key_len, hmac_key);
	if (ima_violations)
		attest_ctx_verifier_allow_ima_violations(v_ctx);

	log = attest_ctx_verifier_add_log(v_ctx, "verify quote");

	rc = attest_ctx_data_add_json_data(d_ctx, message_in,
					   strlen(message_in));
	check_goto(rc, rc, out, v_ctx,
		   "attest_ctx_data_add_json_data() error");
#ifdef DEBUG
	attest_ctx_data_print_json_no_value(d_ctx, &message_in_stripped);
	printf("<- %s\n", message_in_stripped);
	free(message_in_stripped);
#endif
	ak_cert = attest_ctx_data_get(d_ctx, CTX_AIK_CERT);
	check_goto(!ak_cert, -ENOENT, out, v_ctx,
		   "AK certificate not provided");

	nonce = attest_ctx_data_get(d_ctx, CTX_NONCE);
	check_goto(!nonce, -ENOENT, out, v_ctx, "Nonce not provided");

	rc = attest_enroll_verify_hmac(d_ctx, v_ctx, nonce, ak_cert,
				       CTX_NONCE_HMAC);
	check_goto(rc, rc, out, v_ctx,
		   "attest_enroll_verify_hmac() error: %d", rc);

	rc = attest_ctx_verifier_req_add_json_file(v_ctx, reqPath);
	check_goto(rc, rc, out, v_ctx,
		   "verifier's requirements not provided\n");

	printf("Processing quote with the following requirements:\n");
	reqs = attest_ctx_verifier_req_print_json(v_ctx);
	printf("%s\n", reqs);
	free(reqs);

	tpms_attest = attest_ctx_data_get(d_ctx, CTX_TPMS_ATTEST);
	check_goto(!tpms_attest, -ENOENT, out, v_ctx,
		   "TPM attestation data not provided");

	tpms_attest_sig = attest_ctx_data_get(d_ctx, CTX_TPMS_ATTEST_SIG);
	check_goto(!tpms_attest_sig, -ENOENT, out, v_ctx,
		   "TPM attestation data signature not provided");

	rc = attest_verifier_check_tpms_attest(d_ctx, v_ctx, tpms_attest->len,
					       tpms_attest->data,
					       tpms_attest_sig->len,
					       tpms_attest_sig->data, NULL);

	check_goto(rc, rc, out, v_ctx,
		   "attest_verifier_check_tpms_attest() error");

	*message_out = calloc(1, sizeof(char));
	if (!*message_out)
		rc = -ENOMEM;

out:
	attest_ctx_verifier_end_log(v_ctx, log, rc);

	logs = attest_ctx_verifier_result_print_json(v_ctx);
	printf("%s\n", logs);
	free(logs);

	attest_ctx_data_cleanup(d_ctx);
	attest_ctx_verifier_cleanup(v_ctx);
	return rc;
}
/** @}*/
/** @}*/
