/* cyr_qsort_r.h - Cyrus compatibility header for qsort_r
 *
 * Always use the QSORT_R_COMPAR_ARGS macro to declare the
 * comparison function, e.g.
 *
 *     int mysort QSORT_R_COMPAR_ARGS(const void *pa,
 *                                    const void *pb,
 *                                    void *arg)
 *     {
 *          ... your code here ...
 *     }
 *
 */
#ifndef INCLUDED_CYR_QSORT_R_H
#define INCLUDED_CYR_QSORT_R_H

#include <stdlib.h>

#if defined(_GNU_SOURCE) && defined (__GLIBC__) && \
        ((__GLIBC__ > 2) || ((__GLIBC__ == 2) && (__GLIBC_MINOR__ >=0)))
#define HAVE_GLIBC_QSORT_R
#endif

#if defined(__NEWLIB__) && \
        ((__NEWLIB__ > 2) || ((__NEWLIB__ == 2) && (__NEWLIB_MINOR__ >= 2)))
#if defined(_GNU_SOURCE)
#define HAVE_GLIBC_QSORT_R
#else
#define HAVE_BSD_QSORT_R
#endif
#endif

#if !defined(HAVE_GLIBC_QSORT_R) && \
        (defined(__FreeBSD__) || defined(__DragonFly__) || defined(__APPLE__))
#define HAVE_BSD_QSORT_R
#endif

#ifdef HAVE_BSD_QSORT_R
#define QSORT_R_COMPAR_ARGS(a,b,c) (c,a,b)
#define cyr_qsort_r(base, nmemb, size, compar, thunk) qsort_r(base, nmemb, size, thunk, compar)
#else
#define QSORT_R_COMPAR_ARGS(a,b,c) (a,b,c)
#  if defined(HAVE_GLIBC_QSORT_R)
#define cyr_qsort_r(base, nmemb, size, compar, thunk) qsort_r(base, nmemb, size, compar, thunk)
#  elif defined(__GNUC__)
extern void cyr_qsort_r(void *base, size_t nmemb, size_t size,
                        int (*compar)(const void *, const void *, void *),
                        void *thunk);
#  else
#    error No qsort_r support
#  endif
#endif

#endif /* INCLUDED_CYR_QSORT_R_H */
