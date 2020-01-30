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
 * File: enroll_client.c
 *      Client side enrollment functions.
 */

/**
 * @defgroup enroll-api Enrollment API
 * @ingroup app-api
 * @brief
 * Functions to perform enrollment of a device with TPM.
 */

/**
 * @defgroup enroll-client-api Client Side Enrollment API
 * @ingroup enroll-api
 * @brief
 * Functions to generate enrollment requests and parse responses from a server.
 * @addtogroup enroll-client-api
 *  @{
 */

#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <getopt.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netdb.h>

#include "enroll_client.h"
#include "ctx_json.h"
#include "util.h"
#include "tss.h"
#include "skae.h"
#include "event_log.h"

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/engine.h>

#include <ibmtss/ekutils.h>
#include <ibmtss/cryptoutils.h>

#include "tpm2-asn.h"

#define NAME_ALG_AK TPM_ALG_SHA256
#define HASH_ALG_AK TPM_ALG_SHA256
#define NAME_ALG_KEY TPM_ALG_SHA256
#define HASH_ALG_KEY TPM_ALG_SHA256
#define PCR_ALG TPM_ALG_SHA1

static enum ctx_fields key_type_to_ctx_field[KEY_TYPE__LAST] = {
	[KEY_TYPE_AK] = CTX_TPM_AK_KEY,
	[KEY_TYPE_ASYM_DEC] = CTX_TPM_KEY_TEMPLATE,
	[KEY_TYPE_SYM_HMAC] = CTX_TPM_SYM_KEY,
};

/**
 * Add EK certificate to data context
 * @param[in] d_ctx		data context
 * @param[in] tssContext	TSS context
 *
 * @returns 0 on success, a negative value on error
 */
int attest_enroll_add_ek_cert(attest_ctx_data *d_ctx, TSS_CONTEXT *tssContext)
{
	size_t nvdata_len;
	BYTE *nvdata, *nvdata_ptr;
	X509 *ek_cert;
	char *ek_cert_pem;
	int rc;

	rc = attest_tss_getekcert(tssContext, TPM_ALG_RSA, &nvdata_len,
				  &nvdata);
	if (rc)
		return rc;

	nvdata_ptr = nvdata;

	ek_cert = d2i_X509(NULL, (const unsigned char **)&nvdata_ptr,
			   nvdata_len);
	if (!ek_cert) {
		printf("Cannot parse EK cert\n");
		rc = -EINVAL;
		goto out;
	}

	rc = convertX509ToPemMem(&ek_cert_pem, ek_cert);
	if (rc) {
		printf("Cannot convert EK cert\n");
		rc = -EINVAL;
	}

	rc = attest_ctx_data_add(d_ctx, CTX_EK_CERT, strlen(ek_cert_pem),
				 (unsigned char *)ek_cert_pem, NULL);
	X509_free(ek_cert);
out:
	free(nvdata);
	return rc;
}

static int openssl_write_tpmfile(const char *file, BYTE *pubkey, int pubkey_len,
				 BYTE *privkey, int privkey_len,
				 BYTE *policy_bin, int policy_bin_len)
{
	TPM_HANDLE parent = 0x81000001;
	STACK_OF(TSSOPTPOLICY) *sk = NULL;
	TSSOPTPOLICY *policy = NULL;
	union {
		TSSLOADABLE tssl;
		TSSPRIVKEY tpk;
	} k;
	BIO *outb;
	int rc = 0;
	sk = sk_TSSOPTPOLICY_new_null();
	if (!sk)
		return -ENOMEM;

	if (policy_bin) {
		policy = TSSOPTPOLICY_new();
		if (!policy) {
			rc = -ENOMEM;
			goto out;
		}

		ASN1_INTEGER_set(policy->CommandCode, TPM_CC_PolicyPCR);
		ASN1_STRING_set(policy->CommandPolicy,
				policy_bin + sizeof(TPM_CC),
				policy_bin_len - sizeof(TPM_CC));
		sk_TSSOPTPOLICY_push(sk, policy);
	}

	/* clear structure so as not to have to set optional parameters */
	memset(&k, 0, sizeof(k));
	if ((outb = BIO_new_file(file, "w")) == NULL) {
                fprintf(stderr, "Error opening file for write: %s\n", file);
		goto out;
	}

	k.tpk.type = OBJ_txt2obj(OID_loadableKey, 1);
	k.tpk.emptyAuth = 1;
	k.tpk.parent = ASN1_INTEGER_new();
	ASN1_INTEGER_set(k.tpk.parent, parent);

	k.tpk.pubkey = ASN1_OCTET_STRING_new();
	ASN1_STRING_set(k.tpk.pubkey, pubkey, pubkey_len);
	k.tpk.privkey = ASN1_OCTET_STRING_new();
	ASN1_STRING_set(k.tpk.privkey, privkey, privkey_len);
	k.tpk.policy = sk;

	PEM_write_bio_TSSPRIVKEY(outb, &k.tpk);

	ASN1_OBJECT_free(k.tpk.type);
	ASN1_INTEGER_free(k.tpk.parent);
	ASN1_OCTET_STRING_free(k.tpk.pubkey);
	ASN1_OCTET_STRING_free(k.tpk.privkey);

	BIO_free(outb);
out:
	if (policy)
		TSSOPTPOLICY_free(policy);
	if (sk)
		sk_TSSOPTPOLICY_free(sk);

	return rc;
}

/**
 * Create and add key to data context
 * @param[in] d_ctx		data context
 * @param[in] tssContext	TSS context
 * @param[in] keyPrivPath	Path of new file containing private part
 * @param[in] keyPubPath	Path of new file containing public part
 * @param[in] type		Type of key to generate
 * @param[in] nalg		TSS Object name algorithm
 * @param[in] halg		TSS Hash algorithm
 * @param[in] policy_bin_len	Key policy length
 * @param[in] policy_bin	Key policy
 *
 * @returns 0 on success, a negative value on error
 */
int attest_enroll_add_key(attest_ctx_data *d_ctx, TSS_CONTEXT *tssContext,
			  char *keyPrivPath, char *keyPubPath,
			  enum key_types type, TPMI_ALG_HASH nalg,
			  TPMI_ALG_HASH halg, UINT16 policy_bin_len,
			  BYTE *policy_bin)
{
	UINT16 private_len, public_len;
	BYTE *private, *public;
	TPMT_HA calculated_digest = { 0 };
	BYTE *policy_digest = NULL;
	int rc;

	if (policy_bin_len) {
		memset(&calculated_digest, 0, sizeof(calculated_digest));

		calculated_digest.hashAlg = nalg;

		rc = TSS_Hash_Generate(&calculated_digest,
				TSS_GetDigestSize(calculated_digest.hashAlg),
				(uint8_t *)&calculated_digest.digest,
				policy_bin_len, policy_bin, 0, NULL);
		if (rc) {
			rc = -EINVAL;
			goto out;
		}

		policy_digest = (uint8_t *)&calculated_digest.digest;
	}

	rc = attest_tss_create_obj(tssContext, TPM_ALG_RSA, TPM_ECC_NONE, nalg,
				   halg, type, policy_digest, &private_len,
				   &private, &public_len, &public);
	if (rc)
		return rc;

	rc = attest_util_write_file(keyPrivPath, private_len, private, 0);
	if (rc < 0)
		goto out;

	rc = attest_util_write_file(keyPubPath, public_len, public, 0);
	if (rc < 0)
		goto out;

	if (type == KEY_TYPE_ASYM_DEC) {
		rc = openssl_write_tpmfile("tpm_key.pem", public, public_len,
					   private, private_len, policy_bin,
					   policy_bin_len);
		if (rc < 0)
			goto out;
	}

	rc = attest_ctx_data_add(d_ctx, key_type_to_ctx_field[type], public_len,
				 public, NULL);
out:
	if (private)
		free(private);

	if (rc) {
		unlink(keyPrivPath);
		unlink(keyPubPath);
		free(public);
	}

	return rc;
}

/**
 * Decrypt and add decrypted credential to data context
 * @param[in] d_ctx		input data context
 * @param[in] d_ctx_cred	output data context containing decrypted cred
 * @param[in] tssContext	TSS context
 * @param[in] akPrivPath	Path of new file containing AK private part
 * @param[in] akPubPath		Path of new file containing AK public part
 *
 * @returns 0 on success, a negative value on error
 */
int attest_enroll_add_cred(attest_ctx_data *d_ctx, attest_ctx_data *d_ctx_cred,
			   TSS_CONTEXT *tssContext, char *akPrivPath,
			   char *akPubPath)
{
	TPM_HANDLE activateHandle, keyHandle;
	BYTE *private, *public, *cred;
	size_t private_len, public_len;
	struct data_item *credblob, *secret, *credhmac;
	UINT16 cred_len;
	int rc;

	rc = attest_tss_createek(tssContext, TPM_ALG_RSA, &activateHandle);
	if (rc)
		return rc;

	rc = attest_util_read_file(akPrivPath, &private_len, &private);
	if (rc)
		goto out_flush_ek;

	rc = attest_util_read_file(akPubPath, &public_len, &public);
	if (rc)
		goto out_munmap_priv;

	rc = attest_ctx_data_add_copy(d_ctx, CTX_TPM_AK_KEY, public_len,
				      public, NULL);
	if (rc)
		goto out_munmap_pub;

	rc = attest_ctx_data_add_copy(d_ctx_cred, CTX_TPM_AK_KEY, public_len,
				      public, NULL);
	if (rc)
		goto out_munmap_pub;

	rc = attest_tss_load(tssContext, private_len, private, public_len,
			     public, &keyHandle);
	if (rc)
		goto out_munmap_pub;

	credblob = attest_ctx_data_get(d_ctx, CTX_CREDBLOB);
	if (!credblob)
		goto out_flush_ak;

	secret = attest_ctx_data_get(d_ctx, CTX_SECRET);
	if (!secret)
		goto out_flush_ak;

	credhmac = attest_ctx_data_get(d_ctx, CTX_CRED_HMAC);
	if (!secret)
		goto out_flush_ak;

	rc = attest_ctx_data_add_copy(d_ctx_cred, CTX_CRED_HMAC, credhmac->len,
				      credhmac->data, NULL);
	if (rc)
		goto out_flush_ak;

	rc = attest_tss_activatecredential(tssContext, keyHandle,
				activateHandle, credblob->len, credblob->data,
				secret->len, secret->data, &cred_len, &cred);
	if (rc)
		goto out_flush_ak;

	rc = attest_ctx_data_add(d_ctx_cred, CTX_CRED, cred_len, cred, NULL);
out_flush_ak:
	attest_tss_flushcontext(tssContext, keyHandle);
out_munmap_pub:
	munmap(public, public_len);
out_munmap_priv:
	munmap(private, private_len);
out_flush_ek:
	attest_tss_flushcontext(tssContext, activateHandle);
	return rc;
}

static int save_certs(attest_ctx_data *d_ctx, enum ctx_fields cert,
		      enum ctx_fields ca_cert)
{
	struct data_item *item;
	char filename[NAME_MAX + 1];
	enum ctx_fields fields[2] = { cert, ca_cert };
	int rc = 0, i;

	for (i = 0; i < 2; i++) {
		item = attest_ctx_data_get(d_ctx, fields[i]);
		if (!item) {
			printf("Item %s not found\n",
			       attest_ctx_data_get_field(i));
			return -ENOENT;
		}


		snprintf(filename, sizeof(filename), "%s.pem",
			 attest_ctx_data_get_field(fields[i]));

		rc = attest_util_write_file(filename, item->len, item->data, 0);
		if (rc < 0)
			return rc;
	}

	return 0;
}

#define SECURITYFS_PATH "/sys/kernel/security/"
#define BIOS_FILENAME "binary_bios_measurements"
#define BIOS_BINARY_MEASUREMENTS SECURITYFS_PATH "tpm0/" BIOS_FILENAME
#define IMA_FILENAME "binary_runtime_measurements"
#define IMA_BINARY_MEASUREMENTS SECURITYFS_PATH "ima/" IMA_FILENAME

static int collect_data(attest_ctx_data *d_ctx, attest_ctx_verifier *v_ctx,
			int kernel_bios_log, int kernel_ima_log,
			int send_unsigned_files)
{
	unsigned char *data = NULL;
	struct stat st;
	size_t len;
	int rc = 0;

	if (kernel_bios_log && !stat(BIOS_BINARY_MEASUREMENTS, &st)) {
		rc = attest_util_read_seq_file(BIOS_BINARY_MEASUREMENTS, &len,
					       &data);
		if (rc < 0)
			goto out;

		rc = attest_ctx_data_add(d_ctx, CTX_EVENT_LOG, len, data,
					 "bios");
	} else if (!stat(BIOS_FILENAME, &st)) {
		rc = attest_ctx_data_add_file(d_ctx, CTX_EVENT_LOG,
					      BIOS_FILENAME, "bios");
	}

	if (rc)
		goto out;

	if (kernel_ima_log && !stat(IMA_BINARY_MEASUREMENTS, &st)) {
		rc = attest_util_read_seq_file(IMA_BINARY_MEASUREMENTS, &len,
					       &data);
		if (rc)
			goto out;

		rc = attest_ctx_data_add(d_ctx, CTX_EVENT_LOG, len, data,
					 "ima");
	} else if (!stat(IMA_FILENAME, &st)) {
		rc = attest_ctx_data_add_file(d_ctx, CTX_EVENT_LOG,
					      IMA_FILENAME, "ima");
	}

	if (rc)
		goto out;

	if (!send_unsigned_files)
		goto out;

	rc = attest_ctx_verifier_req_add(v_ctx, "ima_cp|verify", "");
	if (rc)
		goto out;

	rc = attest_event_log_parse_verify(d_ctx, v_ctx, 1);
out:
	return 0;
}

static int build_key_policy(attest_ctx_data *d_ctx, attest_ctx_verifier *v_ctx,
			    void *tssContext, TPMI_ALG_HASH nalg,
			    TPMI_ALG_HASH halg, int *pcr_list,
			    int pcr_list_num, enum ctx_fields policy_field,
			    int kernel_event_logs, UINT16 *policy_bin_len,
			    BYTE **policy_bin)
{
	TPML_PCR_SELECTION selection = { 0 };
	TPMT_HA *pcr, digest_pcr, digest_event_log;
	attest_ctx_verifier *v_ctx_pcr;
	BYTE *policy_ptr;
	char *policy_str;
	UINT16 written;
	TPM_CC code = TPM_CC_PolicyPCR;
	int rc, i, max_len;

	max_len = sizeof(INT32) + sizeof(TPML_PCR_SELECTION) +
		  SHA512_DIGEST_SIZE;

	*policy_bin = malloc(max_len);
	if (!*policy_bin)
		return -ENOMEM;

	policy_str = malloc(max_len * 2);
	if (!policy_str) {
		free(*policy_bin);
		return -ENOMEM;
	}

	digest_pcr.hashAlg = digest_event_log.hashAlg = nalg;

	attest_ctx_verifier_init(&v_ctx_pcr);

	rc = attest_pcr_init(v_ctx_pcr);
	if (rc)
		goto out;

	selection.count = 1;
	selection.pcrSelections[0].sizeofSelect = 3;
	selection.pcrSelections[0].hash = halg;

	for (i = 0; i < pcr_list_num; i++) {
		if (pcr_list[i] == -1)
			continue;

		selection.pcrSelections[0].pcrSelect[pcr_list[i] / 8] |=
							1 << (pcr_list[i] % 8);

		if (!kernel_event_logs)
			continue;

		pcr = attest_pcr_get(v_ctx_pcr, pcr_list[i], halg);

		rc = attest_tss_pcrread(tssContext, pcr_list[i], halg,
					(uint8_t *)&pcr->digest);
		if (rc < 0)
			break;
	}

	rc = attest_pcr_calc_digest(v_ctx, &digest_event_log, &selection);
	if (rc < 0)
		goto out;

	if (kernel_event_logs) {
		rc = attest_pcr_calc_digest(v_ctx_pcr, &digest_pcr, &selection);
		if (rc < 0)
			goto out;

		rc = memcmp(&digest_pcr.digest, &digest_event_log.digest,
			    TSS_GetDigestSize(digest_pcr.hashAlg));
		if  (rc < 0) {
			printf("Mismatch between TPM PCRs and "
			       "calculated PCRs\n");
			goto out;
		}
	}

	policy_ptr = *policy_bin;
	written = 0;

	rc = TSS_TPM_CC_Marshal(&code, &written, &policy_ptr, NULL);
	if (rc) {
		rc = -EINVAL;
		goto out;
	}

	rc = TSS_TPML_PCR_SELECTION_Marshal(&selection, &written, &policy_ptr,
					    NULL);
	if (rc) {
		rc = -EINVAL;
		goto out;
	}

	memcpy(policy_ptr, (uint8_t *)&digest_event_log.digest,
	       TSS_GetDigestSize(digest_event_log.hashAlg));

	written += TSS_GetDigestSize(digest_event_log.hashAlg);

	*policy_bin_len = written;

	bin2hex(policy_str, *policy_bin, written);

	rc = attest_ctx_data_add(d_ctx, policy_field, written * 2,
				 (uint8_t *)policy_str, NULL);
out:
	attest_pcr_cleanup(v_ctx_pcr);
	attest_ctx_verifier_cleanup(v_ctx_pcr);
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
 * Add CSR to the data context
 * @param[in] key_path		path of TPM key (openssl_tpm2_engine format)
 * @param[in] d_ctx		data context
 * @param[in] certify_info_len	Length of certify info
 * @param[in] certify_info	Certify info
 * @param[in] signature_len	Signature length
 * @param[in] signature		Signature
 *
 * @returns 0 on success, a negative value on error
 */
int attest_enroll_add_csr(char *key_path, attest_ctx_data *d_ctx,
			  UINT16 certify_info_len, BYTE *certify_info,
			  UINT16 signature_len, BYTE *signature)
{
	X509_REQ *req = NULL;
	EVP_PKEY *pk = NULL;
	ENGINE *e = NULL;
	STACK_OF(X509_EXTENSION) *exts;
	const char *engine_id = "tpm2";
	size_t skae_bin_len = 0;
	BYTE *skae_bin = NULL;
	ASN1_OCTET_STRING *oct = NULL;
	X509_EXTENSION *skae_ext = NULL;
	X509_NAME_ENTRY *nameEntry = NULL;
	X509_NAME *x509Name = NULL;
	SUBJECTKEYATTESTATIONEVIDENCE *skae = NULL;
	char hostname[128];
	BYTE *req_bin = NULL;
	int req_bin_len;
	int rc = 0, i;

	rc = gethostname(hostname, sizeof(hostname));
	if (rc < 0)
		return rc;

        char *subjectEntries[] = {
		"DE",
		"Bayern",
		"Muenchen",
		"Organization",
		NULL,
		hostname,
                NULL
        };

	ENGINE_load_builtin_engines();

	if ((e = ENGINE_by_id(engine_id)) == NULL) {
		printf("Error obtaining '%s' engine\n", engine_id);
		goto out;
	}

	if (!ENGINE_init(e)) {
		printf("can't initialize that engine\n");
		goto out;
	}

	if (!ENGINE_set_default(e, ENGINE_METHOD_ALL)) {
		printf("Error assigning '%s' engine\n", engine_id);
		goto out;
	}

	pk = ENGINE_load_public_key(e, key_path, NULL, NULL);
	if (!pk) {
		printf("Cannot load the key\n");
		goto out;
	}

	req = X509_REQ_new();
	X509_REQ_set_version(req, 1);
	X509_REQ_set_pubkey(req, pk);
	x509Name = X509_NAME_new();

	for (i = 0; name_fields[i]; i++) {
		nameEntry = X509_NAME_ENTRY_create_by_NID(NULL,
				OBJ_txt2nid(name_fields[i]), MBSTRING_ASC,
				(const unsigned char *)subjectEntries[i], -1);
		if (!nameEntry)
			continue;

		rc = X509_NAME_add_entry(x509Name, nameEntry, -1, 0);
		if (rc != 1) {
			printf("Cannot set subject name\n");
			rc = -EINVAL;
			goto out;
		}

		X509_NAME_ENTRY_free(nameEntry);
	}

	X509_REQ_set_subject_name(req, x509Name);
	X509_NAME_free(x509Name);

	exts = sk_X509_EXTENSION_new_null();
	if (!exts) {
		printf("Cannot create extensions\n");
		goto out;
	}

	rc = skae_create(SKAE_VER_2_0, certify_info_len, certify_info,
			 signature_len, signature, &skae_bin_len, &skae_bin,
			 &skae);
	if (rc < 0)
		goto out;

	oct = ASN1_OCTET_STRING_new();
	if (!oct)
		goto out;

	oct->data = skae_bin;
	oct->length = skae_bin_len;

	skae_ext = X509_EXTENSION_create_by_OBJ(NULL, skae->type, 0, oct);
	sk_X509_EXTENSION_push(exts, skae_ext);
	X509_REQ_add_extensions(req, exts);
	sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
	ASN1_OCTET_STRING_free(oct);

	rc = X509_REQ_sign(req, pk, EVP_sha1());
	if (!rc) {
		rc = -EINVAL;
		goto out;
	} else {
		rc = 0;
	}

	req_bin_len = i2d_X509_REQ(req, &req_bin);
	if (req_bin_len <= 0) {
		rc = -EINVAL;
		goto out;
	}

	rc = attest_ctx_data_add(d_ctx, CTX_CSR, req_bin_len, req_bin, NULL);
out:
	if (skae)
		SUBJECTKEYATTESTATIONEVIDENCE_free(skae);

	if (req)
		X509_REQ_free(req);

	if (pk)
		EVP_PKEY_free(pk);

	if (e) {
		ENGINE_finish(e);
		ENGINE_free(e);
	}

	return rc;
}

/**
 * Add a quote
 * @param[in] d_ctx		Data context
 * @param[in] tssContext	TSS context
 * @param[in] akPrivPath	AK private part path
 * @param[in] akPubPath		AK public part path
 * @param[in] nonce_len		nonce length
 * @param[in] nonce		nonce
 * @param[in] pcr_selection	Selected PCRs
 *
 * @returns data_item pointer on success, NULL if not found
 */
int attest_enroll_add_quote(attest_ctx_data *d_ctx, TSS_CONTEXT *tssContext,
			    char *akPrivPath, char *akPubPath, int nonce_len,
			    uint8_t *nonce, TPML_PCR_SELECTION *pcr_selection)
{
	BYTE *ak_private = NULL, *ak_public = NULL, *tpms_attest = NULL;
	BYTE *tpms_attest_sig = NULL;
	size_t ak_private_len = 0, ak_public_len = 0;
	UINT16 tpms_attest_len = 0, tpms_attest_sig_len = 0;
	TPM_HANDLE ak_handle;
	int rc;

	rc = TSS_Create((TSS_CONTEXT **)&tssContext);
	if (rc < 0)
		return -EINVAL;

	rc = attest_util_read_file(akPrivPath, &ak_private_len, &ak_private);
	if (rc)
		goto out;

	rc = attest_util_read_file(akPubPath, &ak_public_len, &ak_public);
	if (rc)
		goto out;

	rc = attest_tss_load(tssContext, ak_private_len, ak_private,
			     ak_public_len, ak_public, &ak_handle);
	if (rc)
		goto out;

	rc = attest_tss_quote(tssContext, ak_handle, ak_public_len, ak_public,
			      nonce_len, nonce, pcr_selection, &tpms_attest_len,
			      &tpms_attest, &tpms_attest_sig_len,
			      &tpms_attest_sig);
	if (rc)
		goto out_flush;

	rc = attest_ctx_data_add(d_ctx, CTX_TPMS_ATTEST, tpms_attest_len,
				 tpms_attest, NULL);
	if (rc)
		goto out_flush;

	rc = attest_ctx_data_add(d_ctx, CTX_TPMS_ATTEST_SIG,
				 tpms_attest_sig_len, tpms_attest_sig, NULL);
out_flush:
	attest_tss_flushcontext(tssContext, ak_handle);
out:
	if (ak_private)
		munmap(ak_private, ak_private_len);
	if (ak_public)
		munmap(ak_public, ak_public_len);

	return rc;
}

static int write_trusted_key_blob(char *path, int append)
{
	uint8_t *bin_data;
	char *hex_data;
	size_t bin_data_len;
	int rc;

	rc = attest_util_read_file(path, &bin_data_len, &bin_data);
	if (rc < 0)
		return rc;

	hex_data = malloc(bin_data_len * 2);
	if (!hex_data) {
		rc = -ENOMEM;
		goto out;
	}

	bin2hex(hex_data, bin_data, bin_data_len);

	rc = attest_util_write_file("trusted_key.blob", bin_data_len * 2,
				    (uint8_t *)hex_data, append);
	free(hex_data);
out:
	munmap(bin_data, bin_data_len);
	return rc;
}

/**
 * Create a symmetric key from data generated by the TPM
 * @param[in] kernel_bios_log	take or not the current BIOS event log
 * @param[in] kernel_ima_log	take or not the current IMA event log
 * @param[in] pcr_alg_name	PCR algorithm name
 * @param[in] pcr_list_str	list of PCRs to use for auth policy
 *
 * @returns data_item pointer on success, NULL if not found
 */
int attest_enroll_create_sym_key(int kernel_bios_log, int kernel_ima_log,
				 char *pcr_alg_name, char *pcr_list_str)
{
	attest_ctx_data *d_ctx = NULL;
	attest_ctx_verifier *v_ctx = NULL;
	void *tssContext;
	UINT16 policy_bin_len = 0;
	BYTE *policy_bin = NULL;
	struct data_item *policy_item;
	char filename[NAME_MAX + 1];
	int pcr_list[IMPLEMENTATION_PCR];
	TPM_ALG_ID pcr_alg = PCR_ALG;
	int rc, i;

	for (i = 0; i < IMPLEMENTATION_PCR; i++)
		pcr_list[i] = -1;

	if (pcr_list_str) {
		rc = attest_util_parse_pcr_list(pcr_list_str,
					sizeof(pcr_list) / sizeof(*pcr_list),
					pcr_list);
		if (rc < 0)
			return rc;
	}

	pcr_alg = attest_pcr_bank_alg_from_name(pcr_alg_name,
						strlen(pcr_alg_name));

	rc = TSS_Create((TSS_CONTEXT **)&tssContext);
	if (rc < 0)
		return -EINVAL;

	attest_ctx_data_init(&d_ctx);
	attest_ctx_verifier_init(&v_ctx);

	rc = attest_pcr_init(v_ctx);
	if (rc < 0)
		goto out;

	rc = collect_data(d_ctx, v_ctx, kernel_bios_log, kernel_ima_log, 0);
	if (rc < 0)
		goto out;

	rc = build_key_policy(d_ctx, v_ctx, tssContext, NAME_ALG_KEY, pcr_alg,
			      pcr_list, sizeof(pcr_list) / sizeof(*pcr_list),
			      CTX_SYM_KEY_POLICY,
			      (kernel_bios_log && kernel_ima_log),
			      &policy_bin_len, &policy_bin);
	if (rc < 0)
		goto out;

	attest_pcr_cleanup(v_ctx);

	rc = attest_enroll_add_key(d_ctx, tssContext, "sym_hmac_priv.bin",
				   "sym_hmac_pub.bin", KEY_TYPE_SYM_HMAC,
				   NAME_ALG_KEY, HASH_ALG_KEY, policy_bin_len,
				   policy_bin);
	if (rc < 0)
		goto out;

	rc = write_trusted_key_blob("sym_hmac_priv.bin", 0);
	if (rc < 0)
		goto out;

	rc = write_trusted_key_blob("sym_hmac_pub.bin", 1);
	if (rc < 0)
		unlink("sym_hmac_priv.bin");

	policy_item = attest_ctx_data_get(d_ctx, CTX_SYM_KEY_POLICY);
	if (!policy_item) {
		printf("Item %s not found\n",
		       attest_ctx_data_get_field(CTX_SYM_KEY_POLICY));
		rc = -ENOENT;
		goto out;
	}

	snprintf(filename, sizeof(filename), "%s.pem",
		 attest_ctx_data_get_field(CTX_SYM_KEY_POLICY));

	rc = attest_util_write_file(filename, policy_item->len,
				    policy_item->data, 0);
out:
	TSS_Delete(tssContext);
	tssContext = NULL;

	if (policy_bin)
		free(policy_bin);

	if (tssContext)
		TSS_Delete(tssContext);

	attest_ctx_data_cleanup(d_ctx);
	attest_ctx_verifier_cleanup(v_ctx);

	return rc;
}

/**
 * Generate an AK
 *
 * @returns 0 on success, a negative value on error
 */
int attest_enroll_generate_ak(void)
{
	attest_ctx_data *d_ctx = NULL;
	void *tssContext;
	int rc;

	attest_ctx_data_init(&d_ctx);

	rc = TSS_Create((TSS_CONTEXT **)&tssContext);
	if (rc)
		return -EINVAL;

	rc = attest_enroll_add_key(d_ctx, tssContext, "akpriv.bin", "akpub.bin",
				   KEY_TYPE_AK, NAME_ALG_AK, HASH_ALG_AK, 0,
				   NULL);

	attest_ctx_data_cleanup(d_ctx);
	TSS_Delete(tssContext);
	return rc;
}

/**
 * @name Protocol API
 *  @{
 */

/**
 * Create an AK challenge request
 * @param[in] certListPath	list of CA certificates to verify EK credential
 * @param[in,out] message_out	AK challenge request to be sent to RA server
 *
 * @returns 0 on success, a negative value on error
 */
int attest_enroll_msg_ak_challenge_request(char *certListPath,
					   char **message_out)
{
	attest_ctx_data *d_ctx = NULL;
	char *certPath;
	void *tssContext;
	size_t size;
	unsigned char *data, *data_ptr;
#ifdef DEBUG
	char *message_out_stripped;
#endif
	int rc;

	attest_ctx_data_init(&d_ctx);

	rc = TSS_Create((TSS_CONTEXT **)&tssContext);
	if (rc)
		return -EINVAL;

	rc = attest_enroll_add_ek_cert(d_ctx, tssContext);
	if (rc)
		goto out;

	rc = attest_util_read_file(certListPath, &size, &data);
	if (rc < 0)
		goto out;

	data_ptr = data;

	while ((certPath = strsep((char **)&data_ptr, "\n"))) {
		if (!strlen(certPath))
			continue;

		rc = attest_ctx_data_add_file(d_ctx, CTX_EK_CA_CERT, certPath,
					      NULL);
		if (rc < 0)
			goto out_munmap;
	}

	rc = attest_enroll_add_key(d_ctx, tssContext, "akpriv.bin", "akpub.bin",
				   KEY_TYPE_AK, NAME_ALG_AK, HASH_ALG_AK, 0,
				   NULL);
	if (rc)
		goto out_munmap;

	rc = attest_ctx_data_print_json(d_ctx, message_out);
#ifdef DEBUG
	attest_ctx_data_print_json_no_value(d_ctx, &message_out_stripped);
	printf("-> %s\n", message_out_stripped);
	free(message_out_stripped);
#endif
out_munmap:
	munmap(data, size);
out:
	attest_ctx_data_cleanup(d_ctx);
	TSS_Delete(tssContext);
	return rc;
}

/**
 * Parse an AK challenge response and create an AK certificate request
 * @param[in] message_in	message containing challenge from RA server
 * @param[in,out] message_out	message with decrypted challenge
 *
 * @returns 0 on success, a negative value on error
 */
int attest_enroll_msg_ak_cert_request(char *message_in, char **message_out)
{
#ifdef DEBUG
	char *message_in_stripped, *message_out_stripped;
#endif
	attest_ctx_data *d_ctx = NULL, *d_ctx_cred;
	char hostname[128];
	void *tssContext;
	int rc;

	rc = TSS_Create((TSS_CONTEXT **)&tssContext);
	if (rc)
		return -EINVAL;

	attest_ctx_data_init(&d_ctx);
	attest_ctx_data_init(&d_ctx_cred);

	rc = attest_ctx_data_add_json_data(d_ctx, message_in,
					   strlen(message_in));
	if (rc < 0)
		goto out;
#ifdef DEBUG
	attest_ctx_data_print_json_no_value(d_ctx, &message_in_stripped);
	printf("<- %s\n", message_in_stripped);
	free(message_in_stripped);
#endif
	rc = attest_enroll_add_cred(d_ctx, d_ctx_cred, tssContext, "akpriv.bin",
				    "akpub.bin");
	if (rc < 0)
		goto out;

	rc = gethostname(hostname, sizeof(hostname));
	if (rc < 0)
		goto out;

	rc = attest_ctx_data_add_copy(d_ctx_cred, CTX_HOSTNAME,
				      strlen(hostname) + 1, (uint8_t *)hostname,
				      NULL);
	if (rc < 0)
		goto out;

	rc = attest_ctx_data_print_json(d_ctx_cred, message_out);
#ifdef DEBUG
	attest_ctx_data_print_json_no_value(d_ctx_cred, &message_out_stripped);
	printf("-> %s\n", message_out_stripped);
	free(message_out_stripped);
#endif
out:
	TSS_Delete(tssContext);
	attest_ctx_data_cleanup(d_ctx);
	attest_ctx_data_cleanup(d_ctx_cred);

	return rc;
}

/**
 * Parse an AK certificate response
 * @param[in] message_in	message containing AK certificate
 *
 * @returns 0 on success, a negative value on error
 */
int attest_enroll_msg_ak_cert_response(char *message_in)
{
#ifdef DEBUG
	char *message_in_stripped;
#endif
	attest_ctx_data *d_ctx = NULL;
	int rc;

	attest_ctx_data_init(&d_ctx);

	rc = attest_ctx_data_add_json_data(d_ctx, message_in,
					   strlen(message_in));
	if (rc < 0)
		goto out;
#ifdef DEBUG
	attest_ctx_data_print_json_no_value(d_ctx, &message_in_stripped);
	printf("<- %s\n", message_in_stripped);
	free(message_in_stripped);
#endif
	save_certs(d_ctx, CTX_AIK_CERT, CTX_PRIVACY_CA_CERT);
out:
	attest_ctx_data_cleanup(d_ctx);

	return rc;
}

/**
 * Create a TPM key certificate request
 * @param[in] kernel_bios_log	take or not the current BIOS event log
 * @param[in] kernel_ima_log	take or not the current IMA event log
 * @param[in] pcr_alg_name	PCR algorithm name
 * @param[in] pcr_list_str	String of selected PCRs
 * @param[in] send_unsigned_files	Send unsigned files to verifier
 * @param[in,out] attest_data	data necessary for key verification
 * @param[in,out] message_out	message with certificate request
 *
 * @returns 0 on success, a negative value on error
 */
int attest_enroll_msg_key_cert_request(int kernel_bios_log, int kernel_ima_log,
				       char *pcr_alg_name, char *pcr_list_str,
				       int send_unsigned_files,
				       char **attest_data, char **message_out)
{
	attest_ctx_data *d_ctx = NULL;
	attest_ctx_verifier *v_ctx = NULL;
	void *tssContext;
#ifdef DEBUG
	char *message_out_stripped;
#endif
	UINT16 certify_info_len, signature_len, policy_bin_len = 0;
	BYTE *certify_info = NULL, *signature = NULL, *policy_bin = NULL;
	char filename[NAME_MAX + 1];
	int pcr_list[IMPLEMENTATION_PCR];
	TPM_ALG_ID pcr_alg = PCR_ALG;
	int rc, i;

	for (i = 0; i < IMPLEMENTATION_PCR; i++)
		pcr_list[i] = -1;

	if (pcr_list_str) {
		rc = attest_util_parse_pcr_list(pcr_list_str,
					sizeof(pcr_list) / sizeof(*pcr_list),
					pcr_list);
		if (rc < 0)
			return rc;
	}

	pcr_alg = attest_pcr_bank_alg_from_name(pcr_alg_name,
						strlen(pcr_alg_name));

	rc = TSS_Create((TSS_CONTEXT **)&tssContext);
	if (rc < 0)
		return -EINVAL;

	attest_ctx_data_init(&d_ctx);
	attest_ctx_verifier_init(&v_ctx);

	rc = attest_pcr_init(v_ctx);
	if (rc < 0)
		goto out;

	rc = collect_data(d_ctx, v_ctx, kernel_bios_log, kernel_ima_log,
			  send_unsigned_files);
	if (rc < 0)
		goto out;

	rc = build_key_policy(d_ctx, v_ctx, tssContext, NAME_ALG_KEY, pcr_alg,
			      pcr_list, sizeof(pcr_list) / sizeof(*pcr_list),
			      CTX_TPM_KEY_POLICY,
			      (kernel_bios_log && kernel_ima_log),
			      &policy_bin_len, &policy_bin);
	if (rc < 0)
		goto out;

	attest_pcr_cleanup(v_ctx);

	rc = attest_enroll_add_key(d_ctx, tssContext, "keypriv.bin",
				   "keypub.bin", KEY_TYPE_ASYM_DEC,
				   NAME_ALG_KEY, HASH_ALG_KEY, policy_bin_len,
				   policy_bin);
	if (rc < 0)
		goto out;

	snprintf(filename, sizeof(filename), "%s.pem",
		 attest_ctx_data_get_field(CTX_PRIVACY_CA_CERT));

	rc = attest_ctx_data_add_file(d_ctx, CTX_PRIVACY_CA_CERT, filename,
				      NULL);
	if (rc < 0)
		goto out;

	snprintf(filename, sizeof(filename), "%s.pem",
		 attest_ctx_data_get_field(CTX_AIK_CERT));

	rc = attest_ctx_data_add_file(d_ctx, CTX_AIK_CERT, filename, NULL);
	if (rc < 0)
		goto out;

	snprintf(filename, sizeof(filename), "%s.pem",
		 attest_ctx_data_get_field(CTX_SYM_KEY_POLICY));

	/* this will be used to verify the symmetric key for EVM, if present */
	attest_ctx_data_add_file(d_ctx, CTX_SYM_KEY_POLICY, filename, NULL);

	rc = attest_tss_load_certify(tssContext, "akpriv.bin", "akpub.bin",
				     "keypriv.bin", "keypub.bin", TPM_ALG_RSA,
				     HASH_ALG_AK, &certify_info_len,
				     &certify_info, &signature_len, &signature);
	if (rc < 0)
		goto out;

	TSS_Delete(tssContext);
	tssContext = NULL;

	if (attest_data) {
		rc = attest_ctx_data_print_json(d_ctx, attest_data);
		if (rc < 0)
			goto out;
	}

	rc = attest_enroll_add_csr("tpm_key.pem", d_ctx, certify_info_len,
				   certify_info, signature_len, signature);
	if (rc < 0)
		goto out;

	rc = attest_ctx_data_print_json(d_ctx, message_out);
#ifdef DEBUG
	attest_ctx_data_print_json_no_value(d_ctx, &message_out_stripped);
	printf("-> %s\n", message_out_stripped);
	free(message_out_stripped);
#endif
out:
	if (certify_info)
		free(certify_info);
	if (signature)
		free(signature);
	if (policy_bin)
		free(policy_bin);

	if (tssContext)
		TSS_Delete(tssContext);

	attest_ctx_data_cleanup(d_ctx);
	attest_ctx_verifier_cleanup(v_ctx);

	return rc;
}

/**
 * Parse a TPM key certificate response
 * @param[in] message_in	message containing certificate response
 *
 * @returns 0 on success, a negative value on error
 */
int attest_enroll_msg_key_cert_response(char *message_in)
{
#ifdef DEBUG
	char *message_in_stripped;
#endif
	attest_ctx_data *d_ctx = NULL;
	int rc;

	attest_ctx_data_init(&d_ctx);

	rc = attest_ctx_data_add_json_data(d_ctx, message_in,
					   strlen(message_in));
	if (rc < 0)
		goto out;
#ifdef DEBUG
	attest_ctx_data_print_json_no_value(d_ctx, &message_in_stripped);
	printf("<- %s\n", message_in_stripped);
	free(message_in_stripped);
#endif
	save_certs(d_ctx, CTX_KEY_CERT, CTX_CA_CERT);
out:
	attest_ctx_data_cleanup(d_ctx);

	return rc;
}

/**
 * Generate a quote nonce request
 * @param[in,out] message_out	Message containing quote nonce request
 *
 * @returns 0 on success, a negative value on error
 */
int attest_enroll_msg_quote_nonce_request(char **message_out)
{
#ifdef DEBUG
	char *message_out_stripped;
#endif
	attest_ctx_data *d_ctx;
	attest_ctx_verifier *v_ctx;
	int rc;

	attest_ctx_data_init(&d_ctx);
	attest_ctx_verifier_init(&v_ctx);

	rc = attest_ctx_data_add_file(d_ctx, CTX_AIK_CERT, "aik_cert.pem",
				      NULL);
	if (rc < 0)
		goto out;

	rc = attest_ctx_data_print_json(d_ctx, message_out);
#ifdef DEBUG
	attest_ctx_data_print_json_no_value(d_ctx, &message_out_stripped);
	printf("-> %s\n", message_out_stripped);
	free(message_out_stripped);
#endif
out:
	attest_ctx_data_cleanup(d_ctx);
	attest_ctx_verifier_cleanup(v_ctx);
	return rc;
}

/**
 * Parse a quote nonce response
 * @param[in] certListPath	List of Privacy CA certificates
 * @param[in] kernel_bios_log	take or not the current BIOS event log
 * @param[in] kernel_ima_log	take or not the current IMA event log
 * @param[in] pcr_alg_name	Selected PCR bank
 * @param[in] pcr_list_str	String containing selected PCRs
 * @param[in] skip_sig_ver	skip signature verification
 * @param[in] send_unsigned_files	Send unsigned files to verifier
 * @param[in] message_in	Input message
 * @param[in,out] message_out	Output message
 *
 * @returns 0 on success, a negative value on error
 */
int attest_enroll_msg_quote_request(char *certListPath, int kernel_bios_log,
				    int kernel_ima_log, char *pcr_alg_name,
				    char *pcr_list_str, int skip_sig_ver,
				    int send_unsigned_files, char *message_in,
				    char **message_out)
{
#ifdef DEBUG
	char *message_in_stripped;
	char *message_out_stripped;
#endif
	void *tssContext;
	size_t size;
	char *certPath;
	uint8_t *data, *data_ptr, *nonce;
	attest_ctx_data *d_ctx;
	attest_ctx_verifier *v_ctx;
	int pcr_list[IMPLEMENTATION_PCR];
	TPML_PCR_SELECTION selection = { 0 };
	TPM_ALG_ID pcr_alg = PCR_ALG;
	int rc, i, nonce_len;

	attest_ctx_data_init(&d_ctx);
	attest_ctx_verifier_init(&v_ctx);

	rc = attest_pcr_init(v_ctx);
	if (rc < 0)
		goto out;

	rc = attest_ctx_data_add_json_data(d_ctx, message_in,
					   strlen(message_in));
	if (rc < 0)
		goto out;
#ifdef DEBUG
	attest_ctx_data_print_json_no_value(d_ctx, &message_in_stripped);
	printf("<- %s\n", message_in_stripped);
	free(message_in_stripped);
#endif
	rc = attest_ctx_data_json_get_by_field(message_in, CTX_NONCE,
					       &nonce_len, &nonce);
	if (rc < 0)
		goto out;

	rc = attest_util_read_file(certListPath, &size, &data);
	if (rc < 0)
		goto out;

	data_ptr = data;

	while ((certPath = strsep((char **)&data_ptr, "\n"))) {
		if (!strlen(certPath))
			continue;

		rc = attest_ctx_data_add_file(d_ctx,
						CTX_PRIVACY_CA_CERT,
						certPath, NULL);
		if (rc < 0)
			break;
	}

	munmap(data, size);

	if (rc < 0)
		goto out;

	rc = attest_ctx_data_add_file(d_ctx, CTX_AIK_CERT,
					"aik_cert.pem", NULL);
	if (rc < 0)
		goto out;

	attest_ctx_data_add_file(d_ctx, CTX_SYM_KEY_POLICY, "sym_policy.pem",
				 NULL);

	rc = TSS_Create((TSS_CONTEXT **)&tssContext);
	if (rc < 0)
		goto out;

	for (i = 0; i < IMPLEMENTATION_PCR; i++)
		pcr_list[i] = -1;

	if (pcr_list_str) {
		rc = attest_util_parse_pcr_list(pcr_list_str,
					sizeof(pcr_list) / sizeof(*pcr_list),
					pcr_list);
		if (rc < 0)
			goto out_ctx;
	}

	pcr_alg = attest_pcr_bank_alg_from_name(pcr_alg_name,
						strlen(pcr_alg_name));

	selection.count = 1;
	selection.pcrSelections[0].sizeofSelect = 3;
	selection.pcrSelections[0].hash = pcr_alg;

	for (i = 0; i < IMPLEMENTATION_PCR; i++) {
		if (pcr_list[i] == -1)
			continue;

		selection.pcrSelections[0].pcrSelect[pcr_list[i] / 8] |=
							1 << (pcr_list[i] % 8);
	}

	rc = attest_enroll_add_quote(d_ctx, tssContext, "akpriv.bin",
				     "akpub.bin", nonce_len, nonce, &selection);
	if (rc < 0)
		goto out;

	rc = collect_data(d_ctx, v_ctx, kernel_bios_log, kernel_ima_log,
			  send_unsigned_files);
	if (rc < 0)
		goto out_ctx;

	rc = attest_ctx_data_print_json(d_ctx, message_out);
#ifdef DEBUG
	attest_ctx_data_print_json_no_value(d_ctx, &message_out_stripped);
	printf("-> %s\n", message_out_stripped);
	free(message_out_stripped);
#endif
out_ctx:
	TSS_Delete(tssContext);
out:
	attest_ctx_data_cleanup(d_ctx);
	attest_ctx_verifier_cleanup(v_ctx);
	return rc;
}
/** @}*/
/** @}*/
