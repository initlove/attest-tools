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
 * File: bios.c
 *      Verifier of BIOS event log.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include "ctx.h"
#include "event_log/bios.h"

#define BIOS_ID "bios|verify"

int verify(attest_ctx_data *d_ctx, attest_ctx_verifier *v_ctx)
{
	struct verifier_struct *verifier;
	struct event_log *bios_log;
	struct event_log_entry *log_entry;
	struct verification_log *log;
	int rc = 0;

	log = attest_ctx_verifier_add_log(v_ctx, "verify BIOS event log");

	verifier = attest_ctx_verifier_lookup(v_ctx, BIOS_ID);
	check_goto(!verifier->req, -ENOENT, out, v_ctx,
		   "requirement not provided");

	check_goto(strcmp(verifier->req, "always-true"), -ENOTSUP, out, v_ctx,
		   "requirement %s not supported", verifier->req);

	bios_log = attest_event_log_get(v_ctx, "bios");
	check_goto(!bios_log, -ENOENT, out, v_ctx,
		   "BIOS event log not provided");

	list_for_each_entry(log_entry, &bios_log->logs, list)
		log_entry->flags |= LOG_ENTRY_PROCESSED;
out:
	attest_ctx_verifier_end_log(v_ctx, log, rc);
	return rc;
}

int num_func = 1;

struct verifier_struct func_array[1] = {{.id = BIOS_ID, .func = verify}};
