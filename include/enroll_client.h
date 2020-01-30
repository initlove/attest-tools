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
 * File: enroll_client.h
 *      Header of enroll_client.c
 */

#ifndef _ENROLL_CLIENT_H
#define _ENROLL_CLIENT_H

#include <ibmtss/tss.h>
#include <ibmtss/tssmarshal.h>
#include <ibmtss/Unmarshal_fp.h>
#include <openssl/evp.h>

#include "ctx.h"
#include "tss.h"

int attest_enroll_add_ek_cert(attest_ctx_data *d_ctx, TSS_CONTEXT *tssContext);
int attest_enroll_add_key(attest_ctx_data *d_ctx, TSS_CONTEXT *tssContext,
			  char *keyPrivPath, char *keyPubPath,
			  enum key_types type, TPMI_ALG_HASH nalg,
			  TPMI_ALG_HASH halg, UINT16 policy_bin_len,
			  BYTE *policy_bin);
int attest_enroll_add_cred(attest_ctx_data *d_ctx, attest_ctx_data *d_ctx_cred,
			   TSS_CONTEXT *tssContext, char *akPrivPath,
			   char *akPubPath);
int attest_enroll_add_csr(char *key_path, attest_ctx_data *d_ctx,
			  UINT16 certify_info_len, BYTE *certify_info,
			  UINT16 signature_len, BYTE *signature);
int attest_enroll_add_quote(attest_ctx_data *d_ctx, TSS_CONTEXT *tssContext,
			    char *akPrivPath, char *akPubPath, int nonce_len,
			    uint8_t *nonce, TPML_PCR_SELECTION *pcr_selection);
int attest_enroll_create_sym_key(int kernel_bios_log, int kernel_ima_log,
				 char *pcr_alg_name, char *pcr_list_str);

int attest_enroll_msg_ak_challenge_request(char *certListPath,
					   char **message_out);
int attest_enroll_msg_ak_cert_request(char *message_in, char **message_out);
int attest_enroll_msg_ak_cert_response(char *message_in);
int attest_enroll_msg_key_cert_request(int kernel_bios_log, int kernel_ima_log,
				       char *pcr_alg_name, char *pcr_list_str,
				       char **attest_data, char **message_out);
int attest_enroll_msg_key_cert_response(char *message_in);
int attest_enroll_msg_quote_nonce_request(char **message_out);
int attest_enroll_msg_quote_request(char *certListPath, int kernel_bios_log,
				    int kernel_ima_log, char *pcr_alg_name,
				    char *pcr_list_str, int skip_sig_ver,
				    char *message_in, char **message_out);
#endif /*ENROLL_CLIENT_H*/
