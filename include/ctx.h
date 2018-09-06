#ifndef _CTX_H
#define _CTX_H

#include "list.h"
#include "stdint.h"

#define MAX_PATH_LENGTH 2048

enum ctx_fields { CTX_PRIVACY_CA_CERT, CTX_AIK_CERT, CTX_TPM_KEY,
		  CTX_TPM_KEY_TEMPLATE, CTX_TPM_KEY_POLICY, CTX_EVENT_LOG,
		  CTX_AUX_DATA, CTX__LAST };

enum data_formats { DATA_FMT_BASE64, DATA_FMT_URI, DATA_FMT__LAST };

struct data_item {
	struct list_head list;
	char *mapped_file;
	size_t len;
	unsigned char *data;
	char *label;
};

typedef struct {
	struct list_head ctx_data[CTX__LAST];
	char *data_dir;
	uint8_t init;
} attest_ctx_data;

typedef struct {
	struct list_head event_logs;
	struct list_head verifiers;
	struct list_head logs;
	void *pcr;
	uint16_t pcr_algo;
	uint8_t init;
} attest_ctx_verifier;

/** @ingroup verifier-api
 * Prototype of the function to verify event logs
 * @param[in] d_ctx	data context
 * @param[in] v_ctx	verifier context
 *
 * @returns 0 on success, a negative value on error
 */
typedef int (*verifier_func)(attest_ctx_data *d_ctx,
			     attest_ctx_verifier *v_ctx);

struct verifier_struct {
	struct list_head list;
	const char *id;
	void *handle;
	verifier_func func;
	char *req;
};

struct verification_log {
	struct list_head list;
	const char *operation;
	const char *result;
	char *reason;
};

extern struct verification_log unknown_log;

#define check_goto(condition, new_rc, label, ctx, ...) \
{ \
	if (condition) { \
		attest_ctx_verifier_set_log(log, __VA_ARGS__); \
		rc = new_rc; \
		goto label; \
	} \
}

#define current_log(ctx) \
	struct verification_log *log = attest_ctx_verifier_get_log(ctx);

#define attest_ctx_data_get(ctx, index) !list_empty(&ctx->ctx_data[index]) ? \
	list_first_entry(&ctx->ctx_data[index], struct data_item, list) : NULL

const char *attest_ctx_data_get_field(enum ctx_fields field);
const char *attest_ctx_data_get_format(enum data_formats fmt);
enum ctx_fields attest_ctx_data_lookup_field(const char *field);
enum data_formats attest_ctx_data_lookup_format(const char *fmt, int fmt_len);

int attest_ctx_data_add(attest_ctx_data *ctx, enum ctx_fields field,
			size_t len, unsigned char *data, const char *label);
int attest_ctx_data_add_file(attest_ctx_data *ctx, enum ctx_fields field,
			     char *path, const char *label);
int attest_ctx_data_add_string(attest_ctx_data *ctx, enum ctx_fields field,
			     const char *string, const char *label);
int attest_ctx_data_new_string(enum data_formats fmt, size_t data_len,
			       unsigned char *data, char **string);
struct data_item *attest_ctx_data_lookup_by_label(attest_ctx_data *ctx,
						  const char *label);
struct data_item *attest_ctx_data_lookup_by_digest(attest_ctx_data *ctx,
				const char *algo, const uint8_t *digest);
int attest_ctx_data_init(attest_ctx_data **ctx);
void attest_ctx_data_cleanup(attest_ctx_data *ctx);

struct verifier_struct *attest_ctx_verifier_lookup(attest_ctx_verifier *ctx,
						   const char *id);
int attest_ctx_verifier_req_add(attest_ctx_verifier *ctx,
				const char *verifier_str, const char *req);
struct verification_log *attest_ctx_verifier_add_log(attest_ctx_verifier *ctx,
						     const char *operation);
struct verification_log *attest_ctx_verifier_get_log(attest_ctx_verifier *ctx);
void attest_ctx_verifier_set_log(struct verification_log *log,
				 const char *fmt, ...);
void attest_ctx_verifier_end_log(attest_ctx_verifier *ctx,
				 struct verification_log *log, int result);
int attest_ctx_verifier_init(attest_ctx_verifier **ctx);
void attest_ctx_verifier_cleanup(attest_ctx_verifier *ctx);

#endif /*_CTX_H*/
