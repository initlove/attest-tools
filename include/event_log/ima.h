/**
 * \addtogroup ima-event-log-api
 *  @{
 */

#ifndef _EVENT_LOG_IMA_H
#define _EVENT_LOG_IMA_H

#include "event_log.h"

#define IMA_TEMPLATE_FIELD_ID_MAX_LEN	16
#define IMA_TEMPLATE_NUM_FIELDS_MAX	15

#define IMA_TEMPLATE_IMA_NAME "ima"
#define IMA_TEMPLATE_IMA_FMT "d|n"

#define CRYPTO_MAX_ALG_NAME 128

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*(x)))

struct ima_field_data {
	const uint8_t *data;
	uint32_t *len;
};

enum template_fields { FIELD_DIGEST, FIELD_DIGEST_NG,
		       FIELD_NAME, FIELD_NAME_NG,
		       FIELD_SIG, FIELD__LAST };

struct ima_template_desc {
	const char *name;
	uint32_t num_fields;
	enum template_fields fields[IMA_TEMPLATE_NUM_FIELDS_MAX];
};

struct ima_template_entry {
	struct {
		uint32_t pcr;
		uint8_t digest[SHA_DIGEST_LENGTH];
		uint32_t name_len;
	} __attribute__((packed)) header;
	unsigned char data[0];
};

struct ima_log_entry {
	struct ima_template_entry *entry;
	struct ima_template_desc *desc;
	struct ima_field_data template_data[0];
};

int ima_template_get_field(struct ima_log_entry *log_entry,
			   enum template_fields field, uint32_t *data_len,
			   const unsigned char **data_ptr);
int ima_template_get_digest(struct ima_log_entry *log_entry, uint32_t *algo_len,
			    const char **algo_ptr, uint32_t *digest_len,
			    const unsigned char **digest_ptr);
int ima_template_get_eventname(struct ima_log_entry *log_entry,
			uint32_t *eventname_len, const char **eventname_ptr);
struct data_item *ima_lookup_data_item(attest_ctx_data *ctx,
			struct event_log *ima_log, const char *label,
			struct event_log_entry **log_entry);

#endif /*_EVENT_LOG_IMA_H*/
/** @}*/
