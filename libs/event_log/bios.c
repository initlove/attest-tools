/** @defgroup bios-event-log-api BIOS Event Log API
 *  @ingroup event-log-api
 *  Event Log API
 */

/**
 * \addtogroup bios-event-log-api
 *  @{
 */

#include <stdio.h>
#include <errno.h>

#include "event_log/bios.h"

/// @private
int attest_event_log_parse(attest_ctx_verifier *v_ctx,
			   uint32_t *remaining_len, unsigned char **data,
			   void **parsed_log)
{
	struct bios_template_entry *bios_entry;
	struct bios_log_entry *log_entry;
	unsigned char *log_data;
	int rc;

	log_entry = malloc(sizeof(*log_entry));
	if (!log_entry)
		return -ENOMEM;

	bios_entry = log_entry->entry;

	check_set_ptr(*remaining_len, *data, sizeof(bios_entry->header),
		      typeof(*bios_entry), bios_entry);
	check_set_ptr(*remaining_len, *data,
		      bios_entry->header.len, typeof(*log_data), log_data);

	/* FIXME: for some log entries, data should be normalized */
	attest_event_log_verify_digest(v_ctx, SHA_DIGEST_LENGTH,
			bios_entry->header.digest, bios_entry->header.len,
			log_data, TPM_ALG_SHA1);

	rc = attest_pcr_extend(v_ctx, bios_entry->header.pcr, TPM_ALG_SHA1,
			       bios_entry->header.digest);
	if (!rc)
		*parsed_log = log_entry;

	return rc;
}
/** @}*/
