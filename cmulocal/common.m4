AC_DEFUN([CMU_FIND_LIB_SUBDIR],
[dnl
AC_ARG_WITH([lib-subdir], AC_HELP_STRING([--with-lib-subdir=DIR],[Find libraries in DIR instead of lib]))
AC_CHECK_SIZEOF(long)
AC_CACHE_CHECK([what directory libraries are found in], [ac_cv_cmu_lib_subdir],
[test "X$with_lib_subdir" = "Xyes" && with_lib_subdir=
test "X$with_lib_subdir" = "Xno" && with_lib_subdir=
if test "X$with_lib_subdir" = "X" ; then
  ac_cv_cmu_lib_subdir=lib
  if test $ac_cv_sizeof_long -eq 4 ; then
    test -d /usr/lib32 && ac_cv_cmu_lib_subdir=lib32
  fi
  if test $ac_cv_sizeof_long -eq 8 ; then
    test -d /usr/lib64 && ac_cv_cmu_lib_subdir=lib64
  fi
else
  ac_cv_cmu_lib_subdir=$with_lib_subdir
fi])
AC_SUBST(CMU_LIB_SUBDIR, $ac_cv_cmu_lib_subdir)
])
