#ifndef _CTX_JSON_H
#define _CTX_JSON_H

#include "ctx.h"

#include <json-c/json.h>

#define JSON_REQS_OBJECT_KEY "reqs"
#define JSON_LOGS_OBJECT_KEY "logs"

struct json_object *attest_ctx_parse_json_file(const char *path);
int attest_ctx_data_add_json_file(attest_ctx_data *ctx, const char *path);
int attest_ctx_verifier_req_add_json_file(attest_ctx_verifier *ctx,
					  const char *req_string);
char *attest_ctx_verifier_req_print_json(attest_ctx_verifier *ctx);
char *attest_ctx_verifier_result_print_json(attest_ctx_verifier *ctx);

#endif /*_CTX_JSON_H*/
