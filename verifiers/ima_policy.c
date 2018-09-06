#include <stdio.h>
#include <string.h>
#include <errno.h>

#include "ctx.h"
#include "event_log/ima.h"

#define IMA_POLICY_ID "ima_policy|verify"
#define POLICY_ID "ima-policy"

enum ima_policies {IMA_EXEC, IMA_STANDARD, IMA__LAST};

const char *ima_policies_str[IMA__LAST] = {
	[IMA_EXEC] = "exec-policy",
	[IMA_STANDARD] = "standard-policy",
};

const char *known_policies[IMA__LAST] = {
	[IMA_EXEC] = "measure func=BPRM_CHECK mask=MAY_EXEC\n\
measure func=MMAP_CHECK mask=MAY_EXEC\n",
	[IMA_STANDARD] = "",
};

static enum ima_policies lookup_ima_policy(const char *str)
{
	int i;

	for (i = 0; i < IMA__LAST; i++) {
		if (!strcmp(str, ima_policies_str[i]))
			return i;
	}

	return IMA__LAST;
}

int verify(attest_ctx_data *d_ctx, attest_ctx_verifier *v_ctx)
{
	struct data_item *policy;
	enum ima_policies policy_type;
	struct verifier_struct *verifier;
	struct verification_log *log;
	struct event_log *ima_log;
	struct event_log_entry *log_entry;
	int rc;

	log = attest_ctx_verifier_add_log(v_ctx, "verify IMA policy");

	verifier = attest_ctx_verifier_lookup(v_ctx, IMA_POLICY_ID);
	check_goto(!verifier->req, -ENOENT, out, v_ctx,
		   "requirement not provided");

	ima_log = attest_event_log_get(v_ctx, "ima");
	check_goto(!ima_log, -ENOENT, out, v_ctx, "IMA event log not provided");

	policy = ima_lookup_data_item(d_ctx, ima_log, POLICY_ID, &log_entry);
	check_goto(!policy, -ENOENT, out, v_ctx, "policy not provided");

	policy_type = lookup_ima_policy(verifier->req);
	check_goto(policy_type == IMA__LAST, -ENOENT, out, v_ctx,
		   "policy not found");

	rc = !(policy->len == strlen(known_policies[policy_type]) &&
	       !memcmp(policy->data, known_policies[policy_type], policy->len));
	check_goto(rc, rc, out, v_ctx, "found policy != requested policy");
	log_entry->flags |= LOG_ENTRY_PROCESSED;
out:
	attest_ctx_verifier_end_log(v_ctx, log, rc);
	return rc;
}

int num_func = 1;

struct verifier_struct func_array[1] = {{.id = IMA_POLICY_ID, .func = verify}};
