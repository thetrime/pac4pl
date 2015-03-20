#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([pac4pl], [0.1], [])
AC_CONFIG_SRCDIR([c/pac4pl.c])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC

# Checks for libraries.

# Checks for header files.
AC_CHECK_HEADERS([netinet/in.h string.h sys/socket.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([select strdup])

case "$SWIARCH" in
    *-win32|*-win64)
        LDFLAGS="$LDFLAGS -ldhcpcsvc -liphlpapi -lws2_32"
        ;;
    *darwin*)
	LDFLAGS="$LDFLAGS -framework CoreFoundation -framework SystemConfiguration"
	;;   
    *linux*)
	CFLAGS="$CFLAGS -std=c99 -D_GNU_SOURCE -D_POSIX_C_SOURCE -D_DARWIN_C_SOURCE -D_XOPEN_SOURCE"
	;;
esac

AC_PATH_PROG(PKG_CONFIG, pkg-config, no)

PKG_CHECK_MODULES(GCONF, gconf-2.0, [have_gconf=yes], [have_gconf=no])
if test x$have_gconf = xyes ; then
   	CFLAGS="$CFLAGS $GCONF_CFLAGS"
   	LDFLAGS="$LDFLAGS $GCONF_LIBS"
        AC_DEFINE([HAVE_GCONF], [1], [Define if we support gconf])
fi

PKG_CHECK_MODULES(GSETTINGS, gio-2.0, have_gsettings=yes, have_gsettings=no)
if test x$have_gsettings = xyes ; then
   	CFLAGS="$CFLAGS $GSETTINGS_CFLAGS"
   	LDFLAGS="$LDFLAGS $GSETTINGS_LIBS"
        AC_DEFINE([HAVE_GSETTINGS], [1], [Define if we support gsettings])
fi
AC_OUTPUT(Makefile)


