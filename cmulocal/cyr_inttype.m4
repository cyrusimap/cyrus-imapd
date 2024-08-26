# SYNOPSIS
#
#   CYR_INTTYPE([TYPE-NAME], [BUILD-PREREQS])
#
# DESCRIPTION
#
#   Figures out the underlying integer type of TYPE-NAME and the appropriate
#   printf format string and strtol-like parse function to use for it.
#
#   BUILD-PREREQS is whatever C code is required for this type to be defined.
#   This is probably a #include statement!
#
#   Sets three cache variables:
#
#   * $cyr_cv_type_foo    => the underlying integer type for the type "foo"
#   * $cyr_cv_format_foo  => the format string to use for type "foo"
#   * $cyr_cv_parse_foo   => the strtol-like parse function to use for type "foo"
#
#   Example:
#
#       CYR_INTTYPE([time_t], [#include <time.h>])
#       AC_DEFINE_UNQUOTED([TIME_T_FMT], ["$cyr_cv_format_time_t"], [...])
#       AC_DEFINE_UNQUOTED([strtotimet(a,b,c)], [$cyr_cv_parse_time_t(a,b,c)], [...])
#
AC_DEFUN([CYR_INTTYPE],[
    dnl First, figure out what type of integer it is, by exploiting the
    dnl behaviour that redefining a variable name as the same type is only
    dnl a warning, but redefining it as a different type is an error.
    AC_CACHE_CHECK(
        [underlying integer type of `$1'],
        [AS_TR_SH([cyr_cv_type_$1])],
        [
            AC_LANG_PUSH([C])
            saved_CFLAGS=$CFLAGS
            CFLAGS=-Wno-error
            saved_CPPFLAGS=$CPPFLAGS
            CPPFLAGS=-Wno-error
            found=no
            for t in "int" "long int" "long long int" \
                    "unsigned int" "unsigned long int" "unsigned long long int"
            do
                AC_COMPILE_IFELSE(
                    [AC_LANG_PROGRAM([$2], [extern $1 foo; extern $t foo;])],
                    [AS_TR_SH([cyr_cv_type_$1])=$t; found=yes; break]
                )
            done
            AS_IF([test "x$found" != "xyes"],
                  [eval AS_TR_SH([cyr_cv_type_$1])=unknown])
            CFLAGS=$saved_CFLAGS
            CPPFLAGS=$saved_CPPFLAGS
            AC_LANG_POP([C])
        ]
    )
    AS_IF([test "x$AS_TR_SH([cyr_cv_type_$1])" = "xunknown"],
          [AC_MSG_ERROR([Unable to determine underlying integer type of `$1'])])

    dnl Then, a quick table lookup to turn the known types into the
    dnl appropriate format string.
    AC_CACHE_CHECK(
        [printf format string for `$1'],
        [AS_TR_SH([cyr_cv_format_$1])],
        [
            AS_CASE([$AS_TR_SH([cyr_cv_type_$1])],
                ["int"], [eval AS_TR_SH([cyr_cv_format_$1])=%d],
                ["long int"], [eval AS_TR_SH([cyr_cv_format_$1])=%ld],
                ["long long int"], [eval AS_TR_SH([cyr_cv_format_$1])=%lld],
                ["unsigned int"], [eval AS_TR_SH([cyr_cv_format_$1])=%u],
                ["unsigned long int"], [eval AS_TR_SH([cyr_cv_format_$1])=%lu],
                ["unsigned long long int"], [eval AS_TR_SH([cyr_cv_format_$1])=%llu],
                [eval AS_TR_SH([cyr_cv_format_$1])=unknown]
            )
        ]
    )
    AS_IF([test "x$AS_TR_SH([cyr_cv_format_$1])" = "xunknown"],
          [AC_MSG_ERROR([Unable to determine printf format string for `$1'])])

    dnl And another quick table lookup to turn the known types into the
    dnl appropriate strtol-like parse function
    dnl Note that this cheats a little for int/unsigned int
    AC_CACHE_CHECK(
        [strtol-like parse function for `$1'],
        [AS_TR_SH([cyr_cv_parse_$1])],
        [
            AS_CASE([$AS_TR_SH([cyr_cv_type_$1])],
                ["int"], [eval AS_TR_SH([cyr_cv_parse_$1])=strtol],
                ["long int"], [eval AS_TR_SH([cyr_cv_parse_$1])=strtol],
                ["long long int"], [eval AS_TR_SH([cyr_cv_parse_$1])=strtoll],
                ["unsigned int"], [eval AS_TR_SH([cyr_cv_parse_$1])=strtoul],
                ["unsigned long int"], [eval AS_TR_SH([cyr_cv_parse_$1])=strtoul],
                ["unsigned long long int"], [eval AS_TR_SH([cyr_cv_parse_$1])=strtoull],
                [eval AS_TR_SH([cyr_cv_parse_$1])=unknown]
            )
        ]
    )
    AS_IF([test "x$AS_TR_SH([cyr_cv_parse_$1])" = "xunknown"],
          [AC_MSG_ERROR([Unable to determine strtol-like parse function for `$1'])])
])
