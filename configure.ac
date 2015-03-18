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

AC_ARG_WITH(libpac, [  --with-libpac=DIR     libpac directory], [
    if test "$withval" = "no"; then
       AC_MSG_ERROR([libpac is not optional])
    elif test "$withval" != "yes"; then
        CFLAGS="$CFLAGS -I$withval/include"
	LDFLAGS="$LDFLAGS -L$withval/lib"
    fi    
    ], [ac_libpac_path=default])
AC_CHECK_LIB(pac, pac_find_proxy, [], [AC_MSG_ERROR([unable to find libpac])])


case "$SWIARCH" in
    *-win32|*-win64)
        ;;
    *darwin*)
	LDFLAGS="$LDFLAGS -framework CoreFoundation -framework SystemConfiguration"
	;;
esac

AC_OUTPUT(Makefile)
