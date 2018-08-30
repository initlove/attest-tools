#include <stdio.h>
#include <string.h>
#include <errno.h>

#include "ctx.h"
#include "event_log/ima.h"

#define IMA_DIGEST_LISTS_ID "ima_digest_lists|verify"
#define PARSER_METADATA_ID "parser_metadata"
#define METADATA_ID "metadata"
#define KEYRING_ID "pubring.gpg"

extern int parse_metadata;
extern char *digest_lists_dir_path;

ssize_t ima_parse_digest_list_metadata(loff_t size, void *buf);
int ima_digest_list_create_key(uint8_t *payload, uint32_t len);
int ima_init_gpgme(char *gpg_homedir, char *keyring_path, char *trusted_ids);
void ima_free_gpgme_ctx(void);

int verify_ima_digest_lists(attest_ctx_data *d_ctx, attest_ctx_verifier *v_ctx);

static int parse(loff_t size, void *datap)
{
	loff_t cur_size;

	while (size > 0) {
		cur_size = ima_parse_digest_list_metadata(size, datap);
		if (cur_size < 0)
			return -EINVAL;

		size -= cur_size;
		datap += cur_size;
	}

	return 0;
}

int verify(attest_ctx_data *d_ctx, attest_ctx_verifier *v_ctx)
{
	struct data_item *keyring, *parser_metadata, *metadata;
	struct event_log_entry *log_entry;
	struct event_log *ima_log;
	struct verifier_struct *verifier;
	struct verification_log *log;
	int rc;

	log = attest_ctx_verifier_add_log(v_ctx, "verify IMA digest lists");

	verifier = attest_ctx_verifier_lookup(v_ctx, IMA_DIGEST_LISTS_ID);

	check_goto(!verifier->req, -ENOENT, out, v_ctx,
		   "requirement not provided");

	rc = ima_init_gpgme(NULL, NULL, verifier->req);
	check_goto(rc, -EINVAL, out, v_ctx, "GPG initialization failed");

	ima_log = attest_event_log_get(v_ctx, "ima");
	check_goto(!ima_log, -ENOENT, out_free, v_ctx,
		   "IMA event log not provided");

	keyring = attest_ctx_data_lookup_by_label(d_ctx, KEYRING_ID);
	if (keyring) {
		rc = ima_digest_list_create_key(keyring->data, keyring->len);
		check_goto(rc, rc, out_free, v_ctx, "PGP keyring not added");
	}

	parse_metadata = 1;
	digest_lists_dir_path = d_ctx->data_dir;

	parser_metadata = ima_lookup_data_item(d_ctx, ima_log,
					       PARSER_METADATA_ID, &log_entry);
	check_goto(!parser_metadata, rc, out_free, v_ctx,
		   "parser metadata not provided");

	rc = parse(parser_metadata->len, parser_metadata->data);
	check_goto(rc, rc, out_free, v_ctx, "digest list verification failed");
	log_entry->flags |= LOG_ENTRY_PROCESSED;

	metadata = ima_lookup_data_item(d_ctx, ima_log, METADATA_ID,
					&log_entry);
	check_goto(!metadata, rc, out_free, v_ctx, "metadata not provided");
	rc = parse(metadata->len, metadata->data);
	check_goto(rc, rc, out_free, v_ctx, "digest list verification failed");
	log_entry->flags |= LOG_ENTRY_PROCESSED;
out_free:
	ima_free_gpgme_ctx();
out:
	attest_ctx_verifier_end_log(v_ctx, log, rc);
	return rc;
}

int num_func = 1;

struct verifier_struct func_array[1] = {{.id = IMA_DIGEST_LISTS_ID,
					 .func = verify}};
