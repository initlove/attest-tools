/*
 * Copyright (C) 2019 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 *
 * File: dummy.c
 *      Dummy verifier.
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>

#include "ctx.h"
#include "event_log/ima.h"

#define DUMMY_ID "dummy|verify"

int verify(attest_ctx_data *d_ctx, attest_ctx_verifier *v_ctx)
{
	struct verification_log *log;
	struct event_log *event_log;
	struct event_log_entry *log_entry;
	int rc = 0;

	log = attest_ctx_verifier_add_log(v_ctx, "dummy verification");

	list_for_each_entry(event_log, &v_ctx->event_logs, list)
		list_for_each_entry(log_entry, &event_log->logs, list)
			log_entry->flags |= LOG_ENTRY_PROCESSED;

	attest_ctx_verifier_end_log(v_ctx, log, rc);
	return rc;
}

int num_func = 1;

struct verifier_struct func_array[1] = {{.id = DUMMY_ID, .func = verify}};
