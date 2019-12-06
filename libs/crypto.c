/********************************************************************************/
/*										*/
/*			OpenSSL Crypto Utilities				*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: cryptoutils.c 1219 2018-05-15 21:12:32Z kgoldman $		*/
/*										*/
/* (c) Copyright IBM Corporation 2017.						*/
/*										*/
/* All rights reserved.								*/
/* 										*/
/* Redistribution and use in source and binary forms, with or without		*/
/* modification, are permitted provided that the following conditions are	*/
/* met:										*/
/* 										*/
/* Redistributions of source code must retain the above copyright notice,	*/
/* this list of conditions and the following disclaimer.			*/
/* 										*/
/* Redistributions in binary form must reproduce the above copyright		*/
/* notice, this list of conditions and the following disclaimer in the		*/
/* documentation and/or other materials provided with the distribution.		*/
/* 										*/
/* Neither the names of the IBM Corporation nor the names of its		*/
/* contributors may be used to endorse or promote products derived from		*/
/* this software without specific prior written permission.			*/
/* 										*/
/* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS		*/
/* "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT		*/
/* LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR	*/
/* A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT		*/
/* HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,	*/
/* SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT		*/
/* LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,	*/
/* DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY	*/
/* THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT		*/
/* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE	*/
/* OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.		*/
/********************************************************************************/

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
 * File: crypto.c
 *      Functions for verifying the certificates.
 */

#include <stdio.h>
#include <errno.h>

#include "crypto.h"

static int attest_crypto_verify_sig_rsa(attest_ctx_verifier *v_ctx,
					TPMT_SIGNATURE *tpmtsig,
					TPMT_HA *digest, EVP_PKEY *evpPkey,
					int nid, int nid_size)
{
	RSA *rsaPkey;
	int rc;

	current_log(v_ctx);

	rsaPkey = EVP_PKEY_get1_RSA(evpPkey);
	check_goto(!rsaPkey, -ENOENT, out, v_ctx, "EVP_PKEY_get1_RSA() error");

	rc = RSA_verify(nid, (uint8_t *)&digest->digest, nid_size,
			tpmtsig->signature.rsassa.sig.t.buffer,
			tpmtsig->signature.rsassa.sig.t.size,
			rsaPkey);

	RSA_free(rsaPkey);

	check_goto(!rc, -EINVAL, out, v_ctx, "RSA_verify() failed");
	rc = !rc;
out:
	return rc;
}

static int attest_crypto_verify_sig_ecdsa(attest_ctx_verifier *v_ctx,
					  TPMT_SIGNATURE *tpmtsig,
					  TPMT_HA *digest, EVP_PKEY *evpPkey,
					  int nid, int nid_size)
{
	EC_KEY *ecKey = NULL;
	ECDSA_SIG *ecdsaSig = NULL;
	BIGNUM *r = NULL;
	BIGNUM *s = NULL;
	int rc;

	current_log(v_ctx);

	ecKey = EVP_PKEY_get1_EC_KEY(evpPkey);
	check_goto(!ecKey, -ENOENT, out, v_ctx, "EVP_PKEY_get1_EC_KEY() error");

	r = BN_bin2bn(tpmtsig->signature.ecdsa.signatureR.t.buffer,
		      tpmtsig->signature.ecdsa.signatureR.t.size, r);
	check_goto(!r, -EINVAL, out, v_ctx, "BN_bin2bn() error");

	r = BN_bin2bn(tpmtsig->signature.ecdsa.signatureS.t.buffer,
		      tpmtsig->signature.ecdsa.signatureS.t.size, r);
	check_goto(!r, -EINVAL, out, v_ctx, "BN_bin2bn() error");

	ecdsaSig = ECDSA_SIG_new();
	check_goto(!ecdsaSig, -ENOMEM, out, v_ctx, "ECDSA_SIG_new() error");
#if OPENSSL_VERSION_NUMBER < 0x10100000
	ecdsaSig->r = r;
	ecdsaSig->s = s;
#else
	rc = ECDSA_SIG_set0(ecdsaSig, r, s);
	check_goto(rc != 1, -EINVAL, out, v_ctx, "ECDSA_SIG_set0() error");
#endif
	rc = ECDSA_do_verify((uint8_t *)&digest->digest, nid_size,
			     ecdsaSig, ecKey);
	check_goto(rc != 1, -EINVAL, out, v_ctx, "ECDSA_do_verify() error");
	rc = !rc;
out:
	BN_free(s);
	BN_free(r);
	EC_KEY_free(ecKey);
	ECDSA_SIG_free(ecdsaSig);
	return rc;
}

int attest_crypto_verify_sig(attest_ctx_verifier *v_ctx,
			     TPMT_SIGNATURE *tpmtsig, TPMT_HA *digest,
			     X509 *x509)
{
	const EVP_MD *md;
	EVP_PKEY *evpPkey = NULL;
	char buf[256];
	int rc = -EINVAL, err, hash_nid = NID_undef;

	current_log(v_ctx);

	evpPkey = X509_get_pubkey(x509);
	check_goto(!evpPkey, -ENOENT, out, v_ctx, "X509_get_pubkey() error");

	if (tpmtsig->signature.any.hashAlg == TPM_ALG_SHA1)
		hash_nid = NID_sha1;
	else if (tpmtsig->signature.any.hashAlg == TPM_ALG_SHA256)
		hash_nid = NID_sha256;
	else if (tpmtsig->signature.any.hashAlg == TPM_ALG_SHA384)
		hash_nid = NID_sha384;
	else if (tpmtsig->signature.any.hashAlg == TPM_ALG_SHA512)
		hash_nid = NID_sha512;

	check_goto(hash_nid == NID_undef, -ENOENT, out, v_ctx,
		   "unsupported hash algorithm");

	md = EVP_get_digestbynid(hash_nid);

	if (tpmtsig->sigAlg == TPM_ALG_RSASSA)
		rc = attest_crypto_verify_sig_rsa(v_ctx, tpmtsig, digest,
						  evpPkey, hash_nid,
						  EVP_MD_size(md));
	else if (tpmtsig->sigAlg == TPM_ALG_ECDSA)
		rc = attest_crypto_verify_sig_ecdsa(v_ctx, tpmtsig, digest,
						    evpPkey, hash_nid,
						    EVP_MD_size(md));
	else
		rc = -ENOTSUP;

	if (rc) {
		err = ERR_get_error();
		ERR_error_string(err, buf);
	}

	if (evpPkey)
		EVP_PKEY_free(evpPkey);

	check_goto(rc, rc, out, v_ctx, buf);
out:
	return rc;
}

int attest_crypto_verify_cert(attest_ctx_data *d_ctx,
			      attest_ctx_verifier *v_ctx,
			      enum ctx_fields cert, enum ctx_fields ca,
			      X509 **x509)
{
	struct data_item *cert_item, *ca_cert_item;
	X509 *aik_cert = NULL, *ca_cert;
	X509_STORE *ca_store = NULL;
	X509_STORE_CTX *verifyCtx = NULL;
	struct list_head *head;
	int rc, err;
	BIO *bio;

	current_log(v_ctx);

	cert_item = attest_ctx_data_get(d_ctx, cert);
	check_goto(!cert_item, -ENOENT, out, v_ctx,
		   "AIK certificate not provided");

	bio = BIO_new_mem_buf((void*)cert_item->data, cert_item->len);
	check_goto(!bio, -ENOMEM, out, v_ctx, "BIO_new_mem_buf() error");
	aik_cert = PEM_read_bio_X509(bio, NULL, 0, NULL);
	BIO_free(bio);

	check_goto(!aik_cert, -EINVAL, out, v_ctx,
		   "PEM_read_bio_X509() error: invalid AIK");

	ca_store  = X509_STORE_new();
	check_goto(!ca_store, -ENOMEM, out, v_ctx, "X509_STORE_new() error");

	head = &d_ctx->ctx_data[ca];

	list_for_each_entry(ca_cert_item, head, list) {
		bio = BIO_new_mem_buf((void*)ca_cert_item->data,
				      ca_cert_item->len);
		check_goto(!bio, -ENOMEM, out, v_ctx,
			   "BIO_new_mem_buf() error");

		ca_cert = PEM_read_bio_X509(bio, NULL, 0, NULL);
		BIO_free(bio);
		check_goto(!ca_cert, -EINVAL, out, v_ctx,
			   "PEM_read_bio_X509() error: invalid CA cert");

		X509_STORE_add_cert(ca_store, ca_cert);
		X509_free(ca_cert);
	}

	verifyCtx = X509_STORE_CTX_new();
	check_goto(!verifyCtx, -ENOMEM, out, v_ctx,
		   "X509_STORE_CTX_new() error");

	rc = X509_STORE_CTX_init(verifyCtx, ca_store, aik_cert, NULL);
	check_goto(rc != 1, -EINVAL, out, v_ctx, "X509_STORE_CTX_init() error");

	rc = X509_verify_cert(verifyCtx);

	if (rc != 1)
		err = X509_STORE_CTX_get_error(verifyCtx);

	check_goto(rc != 1, -EINVAL, out, v_ctx,
		   X509_verify_cert_error_string(err));

	*x509 = aik_cert;
	rc = 0;
out:
	if (ca_store != NULL)
		X509_STORE_free(ca_store);

	if (verifyCtx != NULL) {
		X509_STORE_CTX_cleanup(verifyCtx);
		X509_STORE_CTX_free(verifyCtx);
	}

	if (rc)
		X509_free(aik_cert);

	return rc;
}
