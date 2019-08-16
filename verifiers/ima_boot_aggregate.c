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
 * File: ima_boot_aggregate.c
 *      Verifier of IMA boot aggregate.
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>

#include "ctx.h"
#include "event_log/ima.h"

#define IMA_BOOT_AGGREGATE_ID "ima_boot_aggregate|verify"

int verify(attest_ctx_data *d_ctx, attest_ctx_verifier *v_ctx)
{
	unsigned char buffer[IMPLEMENTATION_PCR * SHA_DIGEST_LENGTH];
	unsigned char *buffer_ptr = buffer;
	const unsigned char *digest_ptr;
	const char *algo_ptr;
	uint32_t algo_len, digest_len;
	struct verification_log *log;
	struct event_log_entry *boot_aggregate_entry;
	struct ima_log_entry *ima_log_entry;
	struct event_log *ima_log;
	INT32 size = sizeof(buffer);
	UINT16 written = 0;
	TPMT_HA digest, *pcr;
	int rc, i;

	log = attest_ctx_verifier_add_log(v_ctx, "verify IMA boot aggregate");

	for (i = 0; i < 8; i++) {
		pcr = attest_pcr_get(v_ctx, i, TPM_ALG_SHA1);
		if (!pcr)
			goto out;

		rc = TSS_Array_Marshal((uint8_t *)&pcr->digest,
				       SHA_DIGEST_LENGTH, &written,
				       &buffer_ptr, &size);
		check_goto(rc, -EINVAL, out, v_ctx,
			   "TSS_Array_Marshal() error: %d", rc);
	}

	digest.hashAlg = TPM_ALG_SHA1;

	rc = TSS_Hash_Generate(&digest, written, buffer, 0, NULL);
	check_goto(rc, -EINVAL, out, v_ctx,
		   "TSS_Hash_Generate() error: %d", rc);

	ima_log = attest_event_log_get(v_ctx, "ima");
	check_goto(!ima_log, -ENOENT, out, v_ctx,
		   "IMA event log not provided");

	boot_aggregate_entry = list_first_entry(&ima_log->logs,
						struct event_log_entry, list);

	ima_log_entry = (struct ima_log_entry *)boot_aggregate_entry->log;
	rc = ima_template_get_digest(ima_log_entry, &algo_len, &algo_ptr,
				     &digest_len, &digest_ptr);
	check_goto(rc, rc, out, v_ctx, "event data digest not found");

	check_goto(algo_len != 4 || strncmp(algo_ptr, "sha1", algo_len),
		   -ENOTSUP, out, v_ctx,
		   "expected SHA1 algorithm for boot aggregate");

	boot_aggregate_entry->flags |= LOG_ENTRY_PROCESSED;

	rc = memcmp((uint8_t *)&digest.digest, digest_ptr, SHA_DIGEST_LENGTH);
	check_goto(rc, rc, out, v_ctx, "calculated digest != provided digest");
out:
	attest_ctx_verifier_end_log(v_ctx, log, rc);
	return rc;
}

int num_func = 1;

struct verifier_struct func_array[1] = {{.id = IMA_BOOT_AGGREGATE_ID,
					 .func = verify}};
