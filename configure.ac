#
# configure.in for the attest-tools project
#

AC_INIT(attest-tools, 0.1.0, <roberto.sassu@huawei.com>)
AM_INIT_AUTOMAKE([-Wall foreign subdir-objects])

AC_USE_SYSTEM_EXTENSIONS
AM_PROG_AR
AC_DISABLE_STATIC
AC_PROG_CC_STDC
AM_PROG_CC_C_O
AC_SYS_LARGEFILE
AC_PROG_LIBTOOL

# Debugging support
AC_ARG_ENABLE(debug,
		AC_HELP_STRING([--enable-debug], [turn on all debugging flags [default is off]]),
		[enable_debug="yes"
		 AC_MSG_RESULT([*** Enabling debugging at user request ***])],)

# If the user has not set CFLAGS, do something appropriate
test_CFLAGS=${CFLAGS+set}
if test "$test_CFLAGS" != set; then
	if test "x$enable_debug" == "xyes"; then
		CFLAGS="-O0 -g -DDEBUG"
	else
		CFLAGS="-O2"
	fi
fi

AC_SEARCH_LIBS([SHA256_Init], [crypto], [],
	       AC_MSG_ERROR([Unable to find the OpenSSL library]))
AC_SEARCH_LIBS([curl_easy_setopt], [curl], [],
	       AC_MSG_ERROR([Unable to find the curl library]))

# Checks for header files.
AC_CHECK_HEADERS([fcntl.h stdlib.h string.h unistd.h])
AC_CHECK_HEADER([openssl/evp.h])
AC_CHECK_HEADER([curl/curl.h])

CFLAGS="$CFLAGS -Wall"
AC_SUBST(CFLAGS)

AC_OUTPUT([Makefile libs/Makefile])
