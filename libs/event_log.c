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
 * File: event_log.c
 *      Event log functions.
 */

/**
 * @defgroup event-log-api Event Log API
 * @ingroup developer-api
 * @brief
 * Event log API allows developers of verification modules to access entries
 * of the parsed event log.
 */

/**
 * @addtogroup event-log-api
 *  @{
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <dlfcn.h>

#include "event_log.h"

/**
 * Get an event log with a given label
 * @param[in] v_ctx	verifier context
 * @param[in] id	event log label
 *
 * @returns event log on success, NULL if not found
 */
struct event_log *attest_event_log_get(attest_ctx_verifier *v_ctx,
				       const char *id)
{
	struct event_log *log;

	list_for_each_entry(log, &v_ctx->event_logs, list) {
		if (strcmp(log->id, id))
			continue;

		if (list_empty(&log->logs))
			return NULL;

		return log;
	}

	return NULL;
}

/**
 * Verify event log data
 * @param[in] v_ctx	verifier context
 * @param[in] digest_len	length of expected digest
 * @param[in] digest	expected digest
 * @param[in] data_len	length of data to verify
 * @param[in] data	data to verify
 * @param[in] algID	digest algorithm
 *
 * @returns 0 on success, a negative value on error
 */
int attest_event_log_verify_digest(attest_ctx_verifier *v_ctx,
				   uint32_t digest_len, uint8_t *digest,
				   uint32_t data_len, uint8_t *data,
				   TPM_ALG_ID algID)
{
	TPMT_HA d;
	int rc;

	current_log(v_ctx);

	check_goto(digest_len != TSS_GetDigestSize(algID), -EINVAL, out, v_ctx,
		   "digest length mismatch");

	d.hashAlg = algID;

	rc = TSS_Hash_Generate(&d, data_len, data, 0, NULL); 
	check_goto(rc, -EINVAL, out, v_ctx, "TSS_Hash_Generate() error: %d");
	rc = memcmp((uint8_t *)&d.digest, digest, digest_len);
	/* FIXME: uncomment when BIOS log is verified correctly */
	//check_goto(rc, rc, out, v_ctx, "digest mismatch");
out:
	return rc;
}

static int attest_event_log_parse(attest_ctx_verifier *v_ctx,
				  parse_log_func parse_func, const char *log_id,
				  int len, unsigned char *data,
				  struct list_head *head)
{
	struct event_log_entry *new_log_entry;
	unsigned char *data_ptr = data;
	uint32_t data_len = len;
	void *first_parsed_log = NULL;
	int rc = 0, i = 0;

	current_log(v_ctx);

	while (data_len > 0) {
		new_log_entry = calloc(1, sizeof(*new_log_entry));
		check_goto(!new_log_entry, -ENOMEM, out, v_ctx,
			   "out of memory");

		rc = parse_func(v_ctx, &data_len, &data_ptr,
				&new_log_entry->log, &first_parsed_log);
		if (rc)
			free(new_log_entry);

		check_goto(rc, rc, out, v_ctx,
			   "error parsing entry #%d of log %s", i++, log_id);

		list_add_tail(&new_log_entry->list, head);
	}
out:
	free(first_parsed_log);
	return rc;
}

static void attest_event_log_free_event_logs(attest_ctx_verifier *v_ctx)
{
	struct event_log *log, *temp_log;
	struct event_log_entry *e, *temp_e;

	list_for_each_entry_safe(log, temp_log, &v_ctx->event_logs, list) {
		list_for_each_entry_safe(e, temp_e, &log->logs, list) {
			list_del(&e->list);
			free(e->log);
			free(e);
		}

		list_del(&log->list);
		free(log);
	}
}

static int attest_event_log_parse_data(attest_ctx_data *d_ctx,
				       attest_ctx_verifier *v_ctx)
{
	struct event_log *new_log = NULL;
	struct verification_log *log;
	char library_name[MAX_PATH_LENGTH];
	parse_log_func parse_func;
	struct data_item *item;
	void *handle = NULL;
	int rc = 0;

	log = attest_ctx_verifier_add_log(v_ctx, "parse event log");

	list_for_each_entry(item, &d_ctx->ctx_data[CTX_EVENT_LOG], list) {
		check_goto(!item->label, -EINVAL, out, v_ctx,
			   "missing log type");

		snprintf(library_name, sizeof(library_name),
			 "libeventlog_%s.so", item->label);
		handle = dlopen(library_name, RTLD_LAZY);
		check_goto(!handle, -ENOENT, out, v_ctx,
			   "event log library not found");

		parse_func = dlsym(handle, "attest_event_log_parse");
		check_goto(!parse_func, -ENOENT, out, v_ctx,
			   "event log parser not found");

		new_log = malloc(sizeof(*new_log));
		check_goto(!new_log, -ENOMEM, out, v_ctx,
			   "out of memory");

		INIT_LIST_HEAD(&new_log->logs);

		new_log->id = item->label;
		list_add_tail(&new_log->list, &v_ctx->event_logs);

		rc = attest_event_log_parse(v_ctx, parse_func, item->label,
					    item->len, item->data,
					    &new_log->logs);
		check_goto(rc, rc, out, v_ctx,
			   "%s parser returned an error", item->label);

		dlclose(handle);
		handle = NULL;
	}
out:
	if (handle)
		dlclose(handle);

	if (rc)
		attest_event_log_free_event_logs(v_ctx);

	attest_ctx_verifier_end_log(v_ctx, log, rc);
	return rc;
}

static int attest_event_log_verify_entries(attest_ctx_data *d_ctx,
					   attest_ctx_verifier *v_ctx)
{
	struct verifier_struct *verifier;
	struct event_log *event_log;
	struct event_log_entry *log_entry;
	struct verification_log *log;
	int rc = 0, i = 0;

	log = attest_ctx_verifier_add_log(v_ctx, "verify event logs");

	list_for_each_entry(verifier, &v_ctx->verifiers, list) {
		rc = verifier->func(d_ctx, v_ctx);
		check_goto(rc, rc, out, v_ctx,
			   "verifier %s returned an error\n", verifier->id);
	}

	list_for_each_entry(event_log, &v_ctx->event_logs, list)
		list_for_each_entry(log_entry, &event_log->logs, list)
			check_goto(!(log_entry->flags & LOG_ENTRY_PROCESSED),
				   -ENOENT, out, v_ctx,
				   "event log %s: log entry #%d not processed",
				   event_log->id, i++);
out:
	attest_ctx_verifier_end_log(v_ctx, log, rc);
	return rc;
}

/// @private
int attest_event_log_parse_verify(attest_ctx_data *d_ctx,
				  attest_ctx_verifier *v_ctx, int verify)
{
	int rc;

	rc = attest_event_log_parse_data(d_ctx, v_ctx);
	if (rc)
		goto out;

	if (verify) {
		rc = attest_event_log_verify_entries(d_ctx, v_ctx);
		if (rc)
			goto out;
	}
out:
	attest_event_log_free_event_logs(v_ctx);

	return rc;
}
/** @}*/
