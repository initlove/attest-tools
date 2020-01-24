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
 * File: ima.c
 *      Parser of the IMA event log.
 */

/**
 * @defgroup ima-event-log-api IMA Event Log API
 * @ingroup event-log-api
 * @brief
 * Functions to access data in a IMA event log entry
 */

/**
 * \addtogroup ima-event-log-api
 *  @{
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>

#include "event_log/ima.h"

static struct ima_template_desc supported_templates[] = {
	{.name = "ima", .num_fields = 2, .fields = {FIELD_DIGEST, FIELD_NAME}},
	{.name = "ima-ng", .num_fields = 2,
	 .fields = {FIELD_DIGEST_NG, FIELD_NAME_NG}},
	{.name = "ima-sig", .num_fields = 3,
	 .fields = {FIELD_DIGEST_NG, FIELD_NAME_NG, FIELD_SIG}},
};

static struct ima_template_desc *lookup_template_desc(int len, const char *name)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(supported_templates); i++) {
		if (strlen(supported_templates[i].name) == len &&
		    !strncmp(supported_templates[i].name, name, len))
			return supported_templates + i;
	}

	return NULL;
}

static int ima_template_field_index(struct ima_template_desc *desc,
			     enum template_fields field)
{
	int i;

	for (i = 0; i < desc->num_fields; i++)
		if (desc->fields[i] == field)
			return i;

	return -1;
}

/**
 * Get template field data
 * @param[in] log_entry	IMA log entry
 * @param[in] field	field identifier
 * @param[in,out] data_len	length of template field data
 * @param[in,out] data_ptr	pointer to template field data
 *
 * @returns 0 on success, a negative value on error
 */
int ima_template_get_field(struct ima_log_entry *log_entry,
			   enum template_fields field, uint32_t *data_len,
			   const unsigned char **data_ptr)
{
	int index;

	index = ima_template_field_index(log_entry->desc, field);
	if (index < 0)
		return -ENOENT;

	*data_len = *log_entry->template_data[index].len;
	*data_ptr = log_entry->template_data[index].data;
	return 0;
}

/**
 * Get file digest from an IMA log entry
 * @param[in] log_entry	IMA log entry
 * @param[in,out] algo_len	length of file digest algorithm
 * @param[in,out] algo_ptr	pointer to file digest algorithm
 * @param[in,out] digest_len	length of file digest
 * @param[in,out] digest_ptr	pointer to file digest
 *
 * @returns 0 on success, a negative value on error
 */
int ima_template_get_digest(struct ima_log_entry *log_entry, uint32_t *algo_len,
			    const char **algo_ptr, uint32_t *digest_len,
			    const unsigned char **digest_ptr)
{
	enum template_fields field;
	const unsigned char *digest;
	uint32_t ima_digest_len;
	int rc;

	field = FIELD_DIGEST_NG;
	if (!strcmp(log_entry->desc->name, "ima"))
		field = FIELD_DIGEST;

	rc = ima_template_get_field(log_entry, field, &ima_digest_len, &digest);
	if (rc)
		return rc;

	*algo_len = 0;
	*algo_ptr = NULL;

	if (field == FIELD_DIGEST_NG) {
		*algo_len = strchr((char *)digest, ':') - (char *)digest;
		*algo_ptr = (char *)digest;

		*digest_len = ima_digest_len - *algo_len - 2;
		*digest_ptr = digest + *algo_len + 2;
	} else {
		*digest_len = SHA_DIGEST_LENGTH;
		*digest_ptr = digest;
	}

	return 0;
}

/**
 * Get file path from an IMA log entry
 * @param[in] log_entry	IMA log entry
 * @param[in,out] eventname_len	length of file path
 * @param[in,out] eventname_ptr	pointer to file path
 *
 * @returns 0 on success, a negative value on error
 */
int ima_template_get_eventname(struct ima_log_entry *log_entry,
			uint32_t *eventname_len, const char **eventname_ptr)
{
	enum template_fields field;

	field = FIELD_NAME_NG;
	if (!strcmp(log_entry->desc->name, "ima"))
		field = FIELD_NAME;

	return ima_template_get_field(log_entry, field,
		      eventname_len, (const unsigned char **)eventname_ptr);
}

/**
 * Get data item to verify an IMA log entry
 * @param[in] ctx	data context
 * @param[in] ima_log	IMA event_log
 * @param[in] label	data label
 * @param[in,out] log_entry	IMA log entry reporting data item read
 *
 * @returns data item on success, NULL if not found
 */
struct data_item *ima_lookup_data_item(attest_ctx_data *ctx,
			struct event_log *ima_log, const char *label,
			struct event_log_entry **log_entry)
{
	struct event_log_entry *cur_log_entry;
	struct ima_log_entry *ima_log_entry;
	const char *algo_ptr, *eventname_ptr;
	const unsigned char *digest_ptr;
	char algo[CRYPTO_MAX_ALG_NAME + 1];
	uint32_t algo_len, digest_len, eventname_len;
	struct data_item *item;
	int rc;

	list_for_each_entry(cur_log_entry, &ima_log->logs, list) {
		ima_log_entry = (struct ima_log_entry *)cur_log_entry->log;

		rc = ima_template_get_digest(ima_log_entry, &algo_len,
					&algo_ptr, &digest_len, &digest_ptr);
		if (rc)
			return NULL;

		rc = ima_template_get_eventname(ima_log_entry,
						&eventname_len, &eventname_ptr);
		if (rc)
			return NULL;

		if (strcmp(basename(eventname_ptr), label))
			continue;

		memcpy(algo, algo_ptr, algo_len);
		algo[algo_len] = '\0';

		item = attest_ctx_data_lookup_by_digest(ctx, algo, digest_ptr);
		if (!item)
			continue;

		*log_entry = cur_log_entry;

		return item;
	}

	return NULL;
}

/// @private
int attest_event_log_parse(attest_ctx_verifier *v_ctx, uint32_t *remaining_len,
			   unsigned char **data, void **parsed_log,
			   void **first_parsed_log)
{
	struct ima_template_desc *desc;
	struct ima_log_entry *log_entry;
	struct ima_template_entry *ima_entry;
	unsigned char *ima_data, *saved_ima_data;
	uint32_t *ima_data_len, saved_ima_data_len;
	char *template;
	TPMT_HA digest;
	int rc = -ENOMEM, i, violation = 0;
	uint8_t zero[SHA_DIGEST_LENGTH] = { 0 };
	uint8_t one[SHA512_DIGEST_LENGTH];

	struct {
		unsigned char digest[SHA_DIGEST_LENGTH];
		unsigned char eventname[TCG_EVENT_NAME_LEN_MAX + 1];
	} __attribute__((packed)) ima_template_data;

	check_set_ptr(*remaining_len, *data,
		      sizeof(ima_entry->header), typeof(*ima_entry), ima_entry);
	check_set_ptr(*remaining_len, *data,
		      ima_entry->header.name_len, char, template);

	if (!memcmp(ima_entry->header.digest, zero, SHA_DIGEST_LENGTH)) {
		memset(one, 0xff, sizeof(one));
		violation = 1;
	}

	desc = lookup_template_desc(ima_entry->header.name_len, template);
	if (!desc)
		return -ENOTSUP;

	log_entry = malloc(sizeof(*log_entry) +
			   desc->num_fields * sizeof(*log_entry->template_data));
	if (!log_entry) {
		rc = -ENOMEM;
		goto out;
	}

	log_entry->desc = desc;

	if (strcmp(desc->name, "ima")) {
		check_set_ptr(*remaining_len, *data, sizeof(*ima_data_len),
			      typeof(*ima_data_len), ima_data_len);
		check_set_ptr(*remaining_len, *data, *ima_data_len,
			      typeof(*ima_data), ima_data);
	} else {
		ima_data_len = remaining_len;
		ima_data = *data;
	}

	saved_ima_data_len = *ima_data_len;
	saved_ima_data = ima_data;

	for (i = 0; i < desc->num_fields; i++) {
		struct ima_field_data *t = log_entry->template_data + i;
		uint32_t len = SHA_DIGEST_LENGTH;

		if (desc->fields[i] != FIELD_DIGEST) {
			check_set_ptr(saved_ima_data_len, saved_ima_data,
				      sizeof(*t->len), typeof(*t->len), t->len);
			len = *t->len;
		}

		check_set_ptr(saved_ima_data_len, saved_ima_data,
			      len, typeof(*t->data), t->data);

		if (desc->fields[i] == FIELD_DIGEST ||
		    desc->fields[i] == FIELD_NAME)
			memcpy(ima_template_data.digest, t->data, len);
	}

	if (!strcmp(desc->name, "ima")) {
		*ima_data_len = sizeof(ima_template_data);
		ima_data = (unsigned char *)&ima_template_data;
	}

	if (!violation) {
		rc = attest_event_log_verify_digest(v_ctx, SHA_DIGEST_LENGTH,
					ima_entry->header.digest, *ima_data_len,
					ima_data, TPM_ALG_SHA1);
		if (rc)
			goto out;
	}

	rc = attest_pcr_extend(v_ctx, ima_entry->header.pcr, TPM_ALG_SHA1,
			       (violation && v_ctx->ima_violations) ?
			       one : ima_entry->header.digest);
	if (rc)
		goto out;

	for (i = 0; i < PCR_BANK__LAST; i++) {
		if (attest_pcr_bank_alg(i) == TPM_ALG_SHA1)
			continue;

		digest.hashAlg = attest_pcr_bank_alg(i);

		rc = TSS_Hash_Generate(&digest, *ima_data_len, ima_data, 0,
				       NULL);
		if (rc) {
			rc = -EINVAL;
			break;
		}

		rc = attest_pcr_extend(v_ctx, ima_entry->header.pcr,
				       digest.hashAlg,
				       (violation && v_ctx->ima_violations) ?
				       one : (uint8_t *)&digest.digest);
		if (rc < 0)
			break;
	}
out:
	if (!rc)
		*parsed_log = log_entry;
	else
		free(log_entry);

	return rc;
}
/** @}*/
