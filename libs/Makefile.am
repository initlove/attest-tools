lib_LTLIBRARIES=libattest.la libskae.la libenroll_client.la libenroll_server.la

libattest_la_LDFLAGS= -no-undefined -avoid-version
libattest_la_LIBADD=${DEPS_LIBS} -libmtssutils
libattest_la_SOURCES=util.c ctx.c ctx_json.c pcr.c crypto.c event_log.c \
		     tss.c verifier.c ../openssl_tpm2_engine/tpm2-common.c
libattest_la_CFLAGS=${DEPS_CFLAGS} -I$(top_srcdir)/include \
		    -I$(top_srcdir)/openssl_tpm2_engine

libskae_la_LDFLAGS= -no-undefined -avoid-version
libskae_la_LIBADD=${DEPS_LIBS} libattest.la
libskae_la_SOURCES=skae.c
libskae_la_CFLAGS=${DEPS_CFLAGS} -I$(top_srcdir)/include \
		    -I$(top_srcdir)/openssl_tpm2_engine

libenroll_client_la_LDFLAGS= -no-undefined -avoid-version
libenroll_client_la_LIBADD=${DEPS_LIBS} libskae.la
libenroll_client_la_SOURCES=enroll_client.c
libenroll_client_la_CFLAGS=${DEPS_CFLAGS} -I$(top_srcdir)/include \
			   -I$(top_srcdir)/openssl_tpm2_engine

libenroll_server_la_LDFLAGS= -no-undefined -avoid-version
libenroll_server_la_LIBADD=${DEPS_LIBS} libskae.la
libenroll_server_la_SOURCES=enroll_server.c
libenroll_server_la_CFLAGS=${DEPS_CFLAGS} -I$(top_srcdir)/include

SUBDIRS = event_log
