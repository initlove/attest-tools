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
 * File: ima_sig.c
 *      Verifier of IMA signatures.
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>

#include "ctx.h"
#include "event_log/ima.h"
#include <digest_lists/crypto.h>

#define IMA_SIG_ID "ima_sig|verify"
#define IMA_CERT_ID "x509_ima.der"

int verify(attest_ctx_data *d_ctx, attest_ctx_verifier *v_ctx)
{
	struct data_item *ima_cert_item;
	struct event_log_entry *cur_log_entry, *key_entry = NULL;
	struct ima_log_entry *ima_log_entry;
	struct event_log *ima_log;
	struct verifier_struct *verifier;
	struct verification_log *log;
	struct key_struct *key;
	LIST_HEAD(head);
	enum hash_algo algo;
	const u8 *sig_ptr, *digest_ptr;
	const char *algo_ptr, *eventname_ptr;
	u32 sig_len, digest_len, algo_len, eventname_len;
	X509 *cert = NULL;
	X509_NAME *name = NULL;
	const unsigned char *ptr;
	char issuer[256];
	int rc = 0;

	log = attest_ctx_verifier_add_log(v_ctx, "verify IMA signatures");

	verifier = attest_ctx_verifier_lookup(v_ctx, IMA_SIG_ID);

	check_goto(!verifier->req, -ENOENT, out, v_ctx,
		   "requirement not provided");

	ima_log = attest_event_log_get(v_ctx, "ima");
	check_goto(!ima_log, -ENOENT, out, v_ctx,
		   "IMA event log not provided");

	ima_cert_item = ima_lookup_data_item(d_ctx, ima_log, IMA_CERT_ID,
					     &key_entry);
	if (ima_cert_item) {
		ptr = ima_cert_item->data;
		cert = d2i_X509(NULL, &ptr, ima_cert_item->len);

		check_goto(!cert, -ENOENT, out, v_ctx,
			"IMA certificate cannot be parsed");
		name = X509_get_issuer_name(cert);
		check_goto(!name, -ENOENT, out, v_ctx,
			"IMA certificate cannot be parsed");

		X509_NAME_oneline(name, issuer, sizeof(issuer));
		check_goto(strcmp(issuer, verifier->req),  -EINVAL, out, v_ctx,
			"IMA certificate issuer requirement not satisfied");

		key = new_key(&head, -1, ima_cert_item->mapped_file, NULL,
			      false);
		check_goto(!key, -ENOENT, out, v_ctx,
			"IMA public key cannot be retrieved");
	}

        list_for_each_entry(cur_log_entry, &ima_log->logs, list) {
		ima_log_entry = (struct ima_log_entry *)cur_log_entry->log;

		rc = ima_template_get_digest(ima_log_entry, &algo_len,
					     &algo_ptr, &digest_len, &digest_ptr);
		if (rc < 0)
			continue;

		rc = ima_template_get_eventname(ima_log_entry, &eventname_len,
						&eventname_ptr);
		if (rc < 0)
			continue;

		if (!strcmp(eventname_ptr, "boot_aggregate"))
			continue;

		for (algo = 0; algo < HASH_ALGO__LAST; algo++)
			if (!strncmp(hash_algo_name[algo], algo_ptr, algo_len))
				break;

		check_goto(algo == HASH_ALGO__LAST, -ENOENT, out, v_ctx,
			   "Unknown hash algorithm");

		rc = ima_template_get_field(ima_log_entry, FIELD_SIG, &sig_len,
					    &sig_ptr);
		if (rc < 0 || ! sig_len)
			continue;

		check_goto(!ima_cert_item, -ENOENT, out, v_ctx,
			   "IMA certificate not provided");

		rc = verify_sig(&head, -1, (u8 *)sig_ptr, sig_len,
				(u8 *)digest_ptr, algo);
		if (rc < 0)
			continue;

		cur_log_entry->flags |= LOG_ENTRY_PROCESSED;
	}

	if (key_entry)
		key_entry->flags |= LOG_ENTRY_PROCESSED;
out:
	X509_free(cert);
	free_keys(&head);
	attest_ctx_verifier_end_log(v_ctx, log, rc);
	return rc;
}

int num_func = 1;

struct verifier_struct func_array[1] = {{.id = IMA_SIG_ID, .func = verify}};
