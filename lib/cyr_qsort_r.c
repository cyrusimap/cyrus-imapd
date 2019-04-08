#include "cyr_qsort_r.h"

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
