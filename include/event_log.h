#ifndef _EVENT_LOG_H
#define _EVENT_LOG_H

#include <stdint.h>
#include <openssl/sha.h>

#include "pcr.h"

#define TCG_EVENT_NAME_LEN_MAX	255

#define check_set_ptr(cur_len, source_ptr, req_len, dest_ptr_type, dest_ptr) { \
	if (cur_len < req_len) \
		return -EINVAL; \
	dest_ptr = (dest_ptr_type *)source_ptr; \
	source_ptr += req_len; \
	cur_len -= req_len; \
}

/** @ingroup event-log-api
 * Prototype of the function to parse a given event log
 *
 * @param[in] v_ctx	verifier context
 * @param[in,out] remaining_len	length of data not parsed
 * @param[in,out] data	pointer to parsed data
 * @param[in,out] parsed_log	library-specific structure of a parsed log entry
 *
 * @returns 0 on success, a negative value on error
 */
typedef int (*parse_log_func)(attest_ctx_verifier *v_ctx,
			      uint32_t *remaining_len, unsigned char **data,
			      void **parsed_log);

struct event_log {
	struct list_head list;
	struct list_head logs;
	const char *id;
};

#define LOG_ENTRY_PROCESSED 0x0001
struct event_log_entry {
	struct list_head list;
	uint16_t flags;
	void *log;
};

struct event_log *attest_event_log_get(attest_ctx_verifier *v_ctx,
				       const char *id);
int attest_event_log_verify_digest(attest_ctx_verifier *v_ctx,
				   uint32_t digest_len, uint8_t *digest,
				   uint32_t data_len, uint8_t *data,
				   TPM_ALG_ID algID);
/// @private
int attest_event_log_verify(attest_ctx_data *d_ctx, attest_ctx_verifier *v_ctx);

#endif /*_EVENT_LOG_H*/
