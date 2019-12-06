/*
 * Copyright (C) 2016 IBM Corporation
 * Copyright (C) 2018-2019 Huawei Technologies Duesseldorf GmbH
 *
 * Authors:
 *     Roberto Sassu <roberto.sassu@huawei.com>
 *     Nayna Jain <nayna@linux.vnet.ibm.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 *
 * File: bios.c
 *      Parser of the BIOS event log.
 */

/**
 * @defgroup bios-event-log-api BIOS Event Log API
 * @ingroup event-log-api
 * @brief
 * Functions to access data in a BIOS event log entry
 */

/**
 * \addtogroup bios-event-log-api
 *  @{
 */

#include <stdio.h>
#include <errno.h>
#include <string.h>

#include "event_log/bios.h"

static int attest_event_log_check_extend(attest_ctx_verifier *v_ctx,
					 int pcr, TPM_ALG_ID algID,
					 u32 digest_size, u8 *digest,
					 u32 event_size, u8 *event)
{
	/* FIXME: for some log entries, data should be normalized */
	attest_event_log_verify_digest(v_ctx, digest_size, digest, 
				       event_size, event, algID);

	return attest_pcr_extend(v_ctx, pcr, algID, digest);
}

static int attest_event_log_parse_v2(attest_ctx_verifier *v_ctx,
				     uint32_t *remaining_len,
				     unsigned char **data,
				     struct tcg_pcr_event2_head *event,
				     struct tcg_pcr_event *event_header)
{
	struct tcg_efi_specid_event_head *efispecid;
	struct tcg_event_field *event_field;
	void *marker;
	void *marker_start;
	struct tpm_digest_ptr *digest_array = NULL;
	u32 halg_size;
	size_t size;
	u16 halg;
	int i;
	int j;
	int rc = 0;

	marker = event;
	marker_start = marker;
	marker = marker + sizeof(event->pcr_idx) + sizeof(event->event_type)
		+ sizeof(event->count);

	efispecid = (struct tcg_efi_specid_event_head *)event_header->event;

	/* Check if event is malformed. */
	if (event->count > efispecid->num_algs)
		return 0;

	digest_array = calloc(event->count, sizeof(*digest_array));
	if (!digest_array)
		return -ENOMEM;

	for (i = 0; i < event->count; i++) {
		halg_size = sizeof(event->digests[i].alg_id);
		memcpy(&halg, marker, halg_size);
		marker = marker + halg_size;
		for (j = 0; j < efispecid->num_algs; j++) {
			if (halg == efispecid->digest_sizes[j].alg_id) {
				digest_array[i].alg_id = halg;
				digest_array[i].digest_size =
					efispecid->digest_sizes[j].digest_size;
				digest_array[i].digest_ptr = marker;
				marker +=
					efispecid->digest_sizes[j].digest_size;
				break;
			}
		}
		/* Algorithm without known length. Such event is unparseable. */
		if (j == efispecid->num_algs) {
			rc = -ENOENT;
			goto out;
		}
	}

	event_field = (struct tcg_event_field *)marker;
	marker = marker + sizeof(event_field->event_size)
		+ event_field->event_size;
	size = marker - marker_start;

	for (i = 0; i < event->count; i++) {
		rc = attest_event_log_check_extend(v_ctx, event->pcr_idx,
						   digest_array[i].alg_id,
						   digest_array[i].digest_size,
						   digest_array[i].digest_ptr,
					           event_field->event_size,
						   event_field->event);
		if (rc < 0)
			goto out;
	}

	if ((event->event_type == 0) && (event_field->event_size == 0))
		return -EINVAL;

	*data += size;
	*remaining_len -= size;
out:
	free(digest_array);
	return rc;
}

static int attest_event_log_parse_v1(attest_ctx_verifier *v_ctx,
				     uint32_t *remaining_len,
				     unsigned char **data,
				     struct tcg_pcr_event **event_header)
{
	struct tcg_pcr_event *bios_entry;
	unsigned char *log_data;

	check_set_ptr(*remaining_len, *data, sizeof(*bios_entry),
		      typeof(*bios_entry), bios_entry);

	check_set_ptr(*remaining_len, *data, bios_entry->event_size,
		      typeof(*log_data), log_data);

	if (bios_entry->event_type == NO_ACTION) {
		*event_header = bios_entry;
		return 0;
	}

	return attest_event_log_check_extend(v_ctx, bios_entry->pcr_idx,
					     TPM_ALG_SHA1, SHA_DIGEST_LENGTH,
					     bios_entry->digest,
				             bios_entry->event_size,
					     bios_entry->event);
}

/// @private
int attest_event_log_parse(attest_ctx_verifier *v_ctx,
			   uint32_t *remaining_len, unsigned char **data,
			   void **parsed_log, void **first_parsed_log)
{
	struct bios_log_entry *log_entry, *first_log_entry;
	struct tcg_pcr_event *event_header = NULL;
	int rc;

	log_entry = malloc(sizeof(*log_entry));
	if (!log_entry)
		return -ENOMEM;

	log_entry->entry = *data;

	if (*first_parsed_log) {
		first_log_entry = (struct bios_log_entry *)*first_parsed_log;

		rc = attest_event_log_parse_v2(v_ctx, remaining_len, data,
				log_entry->entry, first_log_entry->entry);
	} else {
		rc = attest_event_log_parse_v1(v_ctx, remaining_len, data,
					       &event_header);
		if (!rc && event_header) {
			first_log_entry = malloc(sizeof(*first_log_entry));
			if (!first_log_entry) {
				rc = -ENOMEM;
				goto out;
			}

			first_log_entry->entry = event_header;
			*first_parsed_log = first_log_entry;
		}
	}
out:
	if (!rc)
		*parsed_log = log_entry;
	else
		free(log_entry);

	return rc;
}
/** @}*/
