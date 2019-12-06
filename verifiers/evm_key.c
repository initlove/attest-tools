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
 * File: evm_key.c
 *      Verifier of EVM key.
 */

#include <errno.h>
#include <string.h>

#include "verifier.h"
#include "util.h"
#include <event_log/ima.h>

#define EVM_KEY_ID "evm_key|verify"
#define SYM_KEY_ID "trusted_key.blob"

int verify(attest_ctx_data *d_ctx, attest_ctx_verifier *v_ctx)
{
	TPM2B_NAME name;
	struct event_log_entry *key_entry = NULL;
	struct event_log *ima_log;
	struct verifier_struct *verifier;
	struct verification_log *log;
	struct data_item *sym_key;
	TPM_ALG_ID nameAlg;
	UINT32 req_mask = (TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT |
			   TPMA_OBJECT_SENSITIVEDATAORIGIN);
	uint8_t pcr_mask_bin[3];
	uint8_t *sym_key_bin = NULL;
	int rc = 0, req_len;

	log = attest_ctx_verifier_add_log(v_ctx, "verify EVM key");

	verifier = attest_ctx_verifier_lookup(v_ctx, EVM_KEY_ID);
	check_goto(!verifier->req, -ENOENT, out, v_ctx,
		   "requirement not provided");

	req_len = strlen(verifier->req);
	check_goto((req_len > 6 || (req_len % 2)), -EINVAL, out, v_ctx,
		   "invalid requirement");

	rc = hex2bin(pcr_mask_bin, verifier->req, req_len / 2);
	check_goto(rc, rc, out, v_ctx, "invalid requirement");

	ima_log = attest_event_log_get(v_ctx, "ima");
	check_goto(!ima_log, -ENOENT, out, v_ctx,
		   "IMA event log not provided");

	sym_key = ima_lookup_data_item(d_ctx, ima_log, SYM_KEY_ID, &key_entry);
	check_goto(!sym_key, -ENOENT, out, v_ctx, "Symmetric key not provided");

	sym_key_bin = malloc(sym_key->len / 2);
	check_goto(!sym_key_bin, -ENOMEM, out, v_ctx, "out of memory");

	rc = hex2bin(sym_key_bin, (const char *)sym_key->data,
		     sym_key->len / 2);
	check_goto(rc, rc, out, v_ctx, "invalid symmetric key");

	rc = attest_verifier_check_tpm2b_public(d_ctx, v_ctx, sym_key->len / 2,
						sym_key_bin, 1, req_mask,
						CTX_SYM_KEY_POLICY, &nameAlg,
						&name);
	check_goto(rc, rc, out, v_ctx,
		   "attest_verifier_check_tpm2b_public() error: %d", rc);

	rc = attest_verifier_check_key_policy(d_ctx, v_ctx, nameAlg, 0,
					      CTX_SYM_KEY_POLICY,
					      sizeof(pcr_mask_bin),
					      pcr_mask_bin);
	check_goto(rc, rc, out, v_ctx,
		   "attest_verifier_check_key_policy() error: %d", rc);

	if (key_entry)
		key_entry->flags |= LOG_ENTRY_PROCESSED;
out:
	free(sym_key_bin);

	attest_ctx_verifier_end_log(v_ctx, log, rc);
	return rc;
}

int num_func = 1;

struct verifier_struct func_array[1] = {{.id = EVM_KEY_ID, .func = verify}};
