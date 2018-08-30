lib_LTLIBRARIES=libverifier_ima_boot_aggregate.la

libverifier_ima_boot_aggregate_la_LDFLAGS= -no-undefined -avoid-version
libverifier_ima_boot_aggregate_la_LIBADD=${DEPS_LIBS} $(top_srcdir)/libs/event_log/libeventlog_ima.la
libverifier_ima_boot_aggregate_la_SOURCES=ima_boot_aggregate.c
libverifier_ima_boot_aggregate_la_CFLAGS=${DEPS_CFLAGS} -g -Werror \
					 -I$(top_srcdir)/include

if DIGESTLISTS
lib_LTLIBRARIES+=libverifier_ima_digest_lists.la
libverifier_ima_digest_lists_la_LDFLAGS= -no-undefined -avoid-version
libverifier_ima_digest_lists_la_LIBADD=${DEPS_LIBS} -ldigestlists \
				$(top_srcdir)/libs/event_log/libeventlog_ima.la
libverifier_ima_digest_lists_la_SOURCES=ima_digest_lists.c
libverifier_ima_digest_lists_la_CFLAGS=${DEPS_CFLAGS} -g -Werror \
				       -I$(top_srcdir)/include
endif
