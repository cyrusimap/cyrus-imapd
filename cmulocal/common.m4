AC_DEFUN(CMU_TEST_LIBPATH, [
changequote(<<, >>)
define(<<CMU_AC_CV_FOUND>>, translit(ac_cv_found_$2_lib, [ *], [_p]))
changequote([, ])
if test "$CMU_AC_CV_FOUND" = "yes"; then
  if test \! -f "$1/lib$2.a" -a \! -f "$i/lib$2.so" -a \! -f "$i/lib$2.sl"; then
    CMU_AC_CV_FOUND=no
  fi
fi
])