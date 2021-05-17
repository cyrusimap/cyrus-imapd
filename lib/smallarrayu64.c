#include <assert.h>
#include <config.h>
#include <string.h>

#include "smallarrayu64.h"
#include "xmalloc.h"

EXPORTED smallarrayu64_t *smallarrayu64_new(void)
{
    return xzmalloc(sizeof(smallarrayu64_t));
}

EXPORTED void smallarrayu64_fini(smallarrayu64_t *sa)
{
    if (!sa) return;
    arrayu64_fini(&sa->spillover);
    sa->count = 0;
    sa->use_spillover = 0;
}

EXPORTED void smallarrayu64_free(smallarrayu64_t *sa)
{
    if (!sa) return;
    smallarrayu64_fini(sa);
    free(sa);
}

EXPORTED int smallarrayu64_append(smallarrayu64_t *sa, uint64_t num)
{
    if (sa->count < SMALLARRAYU64_ALLOC && !sa->use_spillover) {
        if (num <= UINT8_MAX) {
            sa->data[sa->count++] = num;
            if (sa->count == SMALLARRAYU64_ALLOC) {
                sa->use_spillover = 1;
            }
            return sa->count;
        }
        /* can't store num in preallocated data */
        sa->use_spillover = 1;
    }
    return arrayu64_append(&sa->spillover, num);
}

EXPORTED size_t smallarrayu64_size(smallarrayu64_t *sa)
{
    return sa->count + arrayu64_size(&sa->spillover);
}

static inline int adjust_index_ro(const smallarrayu64_t *sa, int idx)
{
    size_t count = sa->count + arrayu64_size(&sa->spillover);
    if (idx >= 0 && (unsigned) idx >= count)
        return -1;
    else if (idx < 0)
        idx += count;
    return idx;
}

EXPORTED uint64_t smallarrayu64_nth(smallarrayu64_t *sa, int idx)
{
    if ((idx = adjust_index_ro(sa, idx)) < 0)
        return 0;
    if ((size_t)idx < sa->count) {
        return sa->data[idx];
    }
    else {
        return arrayu64_nth(&sa->spillover, idx - sa->count);
    }
}
