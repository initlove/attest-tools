lib_LTLIBRARIES=libverifier_ima_boot_aggregate.la \
		libverifier_ima_policy.la \
		libverifier_bios.la \
		libverifier_ima_cp.la \
		libverifier_evm_key.la \
		libverifier_dummy.la

libverifier_ima_boot_aggregate_la_LDFLAGS=-no-undefined -avoid-version
libverifier_ima_boot_aggregate_la_LIBADD=${DEPS_LIBS} \
				$(top_srcdir)/libs/event_log/libeventlog_ima.la
libverifier_ima_boot_aggregate_la_SOURCES=ima_boot_aggregate.c
libverifier_ima_boot_aggregate_la_CFLAGS=${DEPS_CFLAGS} -g -Werror \
					 -I$(top_srcdir)/include

if DIGESTLISTS
lib_LTLIBRARIES+=libverifier_ima_sig.la
libverifier_ima_sig_la_LDFLAGS=-no-undefined -avoid-version
libverifier_ima_sig_la_LIBADD=${DEPS_LIBS} -ldigestlist-base \
			      $(top_srcdir)/libs/event_log/libeventlog_ima.la
libverifier_ima_sig_la_SOURCES=ima_sig.c
libverifier_ima_sig_la_CFLAGS=${DEPS_CFLAGS} -g -Werror -I$(top_srcdir)/include
endif

libverifier_ima_policy_la_LDFLAGS=-no-undefined -avoid-version
libverifier_ima_policy_la_LIBADD=${DEPS_LIBS} \
				 $(top_srcdir)/libs/event_log/libeventlog_ima.la
libverifier_ima_policy_la_SOURCES=ima_policy.c
libverifier_ima_policy_la_CFLAGS=${DEPS_CFLAGS} -g -Werror \
				 -I$(top_srcdir)/include

libverifier_bios_la_LDFLAGS=-no-undefined -avoid-version
libverifier_bios_la_LIBADD=${DEPS_LIBS} \
			   $(top_srcdir)/libs/event_log/libeventlog_bios.la
libverifier_bios_la_SOURCES=bios.c
libverifier_bios_la_CFLAGS=${DEPS_CFLAGS} -g -Werror -I$(top_srcdir)/include

libverifier_ima_cp_la_LDFLAGS=-no-undefined -avoid-version
libverifier_ima_cp_la_LIBADD=${DEPS_LIBS} \
			   $(top_srcdir)/libs/event_log/libeventlog_ima.la
libverifier_ima_cp_la_SOURCES=ima_cp.c
libverifier_ima_cp_la_CFLAGS=${DEPS_CFLAGS} -g -Werror -I$(top_srcdir)/include

libverifier_evm_key_la_LDFLAGS=-no-undefined -avoid-version
libverifier_evm_key_la_LIBADD=${DEPS_LIBS} \
			   $(top_srcdir)/libs/event_log/libeventlog_ima.la
libverifier_evm_key_la_SOURCES=evm_key.c
libverifier_evm_key_la_CFLAGS=${DEPS_CFLAGS} -g -Werror -I$(top_srcdir)/include

libverifier_dummy_la_LDFLAGS=-no-undefined -avoid-version
libverifier_dummy_la_SOURCES=dummy.c
libverifier_dummy_la_CFLAGS=${DEPS_CFLAGS} -g -Werror -I$(top_srcdir)/include
