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
 * File: enroll_server.h
 *      Header of enroll_server.c
 */

#ifndef _ENROLL_SERVER_H
#define _ENROLL_SERVER_H

#include <inttypes.h>

#include <ibmtss/tss.h>
#include <ibmtss/tssmarshal.h>
#include <ibmtss/Unmarshal_fp.h>

#include <ibmtss/tsscryptoh.h>
#include <ibmtss/tssresponsecode.h>

#include "ctx.h"

int attest_enroll_hmac(attest_ctx_verifier *v_ctx, int akpub_len, BYTE *akpub,
		       int credential_len, BYTE *credential,
		       unsigned int *hmac_len, BYTE *hmac);
int attest_enroll_make_credential(attest_ctx_data *d_ctx_in,
				  attest_ctx_data *d_ctx_out,
				  attest_ctx_verifier *v_ctx);
int attest_enroll_make_cert(attest_ctx_data *d_ctx_in,
			    attest_ctx_data *d_ctx_out,
			    attest_ctx_verifier *v_ctx, char *pcaKeyPath,
			    char *pcaKeyPassword, char *pcaCertPath);
int attest_enroll_process_csr(attest_ctx_data *d_ctx_in,
			      attest_ctx_verifier *v_ctx, char *reqPath,
			      char **csr_str);

int attest_enroll_msg_make_credential(uint8_t *hmac_key, int hmac_key_len,
				     char *pcaKeyPath, char *pcaKeyPassword,
				     char *pcaCertPath, char *message_in,
				     char **message_out);
int attest_enroll_msg_make_cert(uint8_t *hmac_key, int hmac_key_len,
				char *pcaKeyPath, char *pcaKeyPassword,
				char *pcaCertPath, char *message_in,
				char **message_out);
int attest_enroll_msg_process_csr(int pcr_mask_len, uint8_t *pcr_mask,
				  char *reqPath, uint16_t verifier_flags,
				  char *message_in, char **csr_str);
int attest_enroll_sign_csr(char *caKeyPath, char *caKeyPassword,
			   char *caCertPath, char *csr_str,
			   char **cert_str);
int attest_enroll_msg_return_cert(char *cert_str, char *ca_cert_str,
				  char **message_out);
int attest_enroll_msg_gen_quote_nonce(int hmac_key_len, uint8_t *hmac_key,
				      char *message_in, char **message_out);
int attest_enroll_msg_process_quote(int hmac_key_len, uint8_t *hmac_key,
				    int pcr_mask_len, uint8_t *pcr_mask,
				    char *reqPath, uint16_t verifier_flags,
				    char *message_in, char **message_out);
#endif /*_ENROLL_SERVER_H*/
