lib_LTLIBRARIES=libeventlog_bios.la libeventlog_ima.la

libeventlog_bios_la_LDFLAGS= -no-undefined -avoid-version
libeventlog_bios_la_LIBADD=${DEPS_LIBS} -lcrypto
libeventlog_bios_la_SOURCES=bios.c
libeventlog_bios_la_CFLAGS=${DEPS_CFLAGS} -Werror -I$(top_srcdir)/include

libeventlog_ima_la_LDFLAGS= -no-undefined -avoid-version
libeventlog_ima_la_LIBADD=${DEPS_LIBS} -lcrypto
libeventlog_ima_la_SOURCES=ima.c
libeventlog_ima_la_CFLAGS=${DEPS_CFLAGS} -Werror -I$(top_srcdir)/include
