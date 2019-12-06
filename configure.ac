#
# configure.in for the attest-tools project
#

AC_INIT(attest-tools, 0.2.0, <roberto.sassu@huawei.com>)
AM_INIT_AUTOMAKE([-Wall foreign subdir-objects])

# Enable debug.
AC_ARG_ENABLE([debug], [  --enable-debug    Turn on debugging],
	      [debug=${enableval}], [debug=no])

if test -z "$CFLAGS"; then
  if test "$debug" == yes; then
    CFLAGS="-O0 -g"
  else
    CFLAGS="-O2"
  fi
fi

if test "$debug" == yes; then
  CFLAGS="$CFLAGS -DDEBUG"
fi

AC_USE_SYSTEM_EXTENSIONS
AM_PROG_AR
AC_DISABLE_STATIC
AC_PROG_CC_STDC
AM_PROG_CC_C_O
AC_SYS_LARGEFILE
AC_PROG_LIBTOOL

# Debugging support
AC_ARG_ENABLE(debug,
		AC_HELP_STRING([--enable-debug],
		[turn on all debugging flags [default is off]]),
		[enable_debug="yes"
		 AC_MSG_RESULT([*** Enabling debugging at user request ***])],)

AC_SEARCH_LIBS([SHA256_Init], [crypto], [],
	       AC_MSG_ERROR([Unable to find the OpenSSL library]))
AC_SEARCH_LIBS([curl_easy_setopt], [curl], [],
	       AC_MSG_ERROR([Unable to find the curl library]))
AC_SEARCH_LIBS([json_object_new_object], [json-c], [],
	       AC_MSG_ERROR([Unable to find the json-c library]))
AC_SEARCH_LIBS([TSS_Create], [ibmtss], [],
	       AC_MSG_ERROR([Unable to find the TSS2 utils library]))

# Checks for header files.
AC_CHECK_HEADERS([fcntl.h stdlib.h string.h unistd.h])
AC_CHECK_HEADER([openssl/evp.h])
AC_CHECK_HEADER([json-c/json.h])
AC_CHECK_HEADER([tss2/tss.h],[AC_DEFINE(TSS_INCLUDE,tss2)],
		AC_CHECK_HEADER([ibmtss/tss.h],[AC_DEFINE(TSS_INCLUDE,ibmtss)],
				AC_MSG_ERROR([No TSS2 include directory found]),
				[# define TPM_POSIX]), [# define TPM_POSIX])
AC_CHECK_LIB([digestlist-base], [new_key],[digestlists=true],[],[])
AM_CONDITIONAL([DIGESTLISTS], [test x$digestlists = xtrue])

CFLAGS="$CFLAGS -Wall -Werror -DTPM_POSIX"

AC_SUBST(CFLAGS)

AC_SUBST(TSS_INCLUDE)
AC_OUTPUT([Makefile libs/Makefile libs/event_log/Makefile
	   verifiers/Makefile src/Makefile scripts/Makefile])

	   cat <<EOF

CFLAGS:				${CFLAGS}

EOF
