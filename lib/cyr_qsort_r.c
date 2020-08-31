#include "cyr_qsort_r.h"

#ifndef cyr_qsort_r

#ifdef HAVE_FUNCTION_NESTING

EXPORTED void cyr_qsort_r(void *base, size_t nmemb, size_t size,
                          int (*compar)(const void *, const void *, void *),
                          void *thunk)
{
    int compar_func(const void *a, const void *b)
    {
        return compar(a, b, thunk);
    }
    qsort(base, nmemb, size, compar_func);
}

#else

// NOTE: this is kinda ugly, but it's OK if you're not multithreaded

static void *qsort_r_thunk;
static int (*qsort_r_compar)(const void *, const void *, void *);
static int qsort_r_compar_func(const void *a, const void *b)
{
    return qsort_r_compar(a, b, qsort_r_thunk);
}

EXPORTED void cyr_qsort_r(void *base, size_t nmemb, size_t size,
                          int (*compar)(const void *, const void *, void *),
                          void *thunk)
{
    qsort_r_thunk = thunk;
    qsort_r_compar = compar;
    qsort(base, nmemb, size, qsort_r_compar_func);
    qsort_r_thunk = NULL;
    qsort_r_compar = NULL;
}

#endif /* HAVE_FUNCTION_NESTING */

#endif /* cyr_qsort_r */
