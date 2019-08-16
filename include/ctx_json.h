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
 * File: ctx_json.h
 *      Header of ctx_json.c.
 */

#ifndef _CTX_JSON_H
#define _CTX_JSON_H

#include "ctx.h"

#include <json-c/json.h>

#define JSON_REQS_OBJECT_KEY "reqs"
#define JSON_LOGS_OBJECT_KEY "logs"

struct json_object *attest_ctx_parse_json_data(const char *data, size_t len);
struct json_object *attest_ctx_parse_json_file(const char *path);
int attest_ctx_data_add_json_data(attest_ctx_data *ctx, const char *data,
				  size_t len);
int attest_ctx_data_add_json_file(attest_ctx_data *ctx, const char *path);
int attest_ctx_data_print_json(attest_ctx_data *ctx, char **json_str);
int attest_ctx_verifier_req_add_json_file(attest_ctx_verifier *ctx,
					  const char *req_string);
char *attest_ctx_verifier_req_print_json(attest_ctx_verifier *ctx);
char *attest_ctx_verifier_result_print_json(attest_ctx_verifier *ctx);
char *attest_ctx_verifier_output_print_json(attest_ctx_verifier *ctx);

#endif /*_CTX_JSON_H*/
