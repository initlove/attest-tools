lib_LTLIBRARIES=libattest.la libskae.la libenroll.la libclient.la

libattest_la_LDFLAGS= -no-undefined -avoid-version
libattest_la_LIBADD=${DEPS_LIBS}
libattest_la_SOURCES=util.c ctx.c ctx_json.c pcr.c crypto.c event_log.c \
		     verifier.c ../openssl_tpm2_engine/tpm2-common.c
libattest_la_CFLAGS=${DEPS_CFLAGS} -I$(top_srcdir)/include \
		    -I$(top_srcdir)/openssl_tpm2_engine

libskae_la_LDFLAGS= -no-undefined -avoid-version
libskae_la_LIBADD=${DEPS_LIBS} libattest.la
libskae_la_SOURCES=skae.c
libskae_la_CFLAGS=${DEPS_CFLAGS} -I$(top_srcdir)/include \
		    -I$(top_srcdir)/openssl_tpm2_engine

libenroll_la_LDFLAGS= -no-undefined -avoid-version
libenroll_la_LIBADD=${DEPS_LIBS} -ltpms -ltssutils -lcrypto -ljson-c
libenroll_la_SOURCES=util.c ctx.c ctx_json.c crypto.c enroll.c
libenroll_la_CFLAGS=${DEPS_CFLAGS} -I$(top_srcdir)/include

libclient_la_LDFLAGS= -no-undefined -avoid-version
libclient_la_LIBADD=${DEPS_LIBS} -ltssutils
libclient_la_SOURCES=util.c ctx.c ctx_json.c crypto.c tss.c
libclient_la_CFLAGS=${DEPS_CFLAGS} -I$(top_srcdir)/include

SUBDIRS = event_log
