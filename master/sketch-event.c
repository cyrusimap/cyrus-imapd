#include <stdint.h>
#include <stdlib.h>

#include "lib/strarray.h"

struct event_sched1 {
    uint64_t minute;
    uint32_t dow_hour;
    uint32_t hasmonth_dom;
};

#define EV_DOW_MASK         (0x7f000000)
#define EV_DOW_SHIFT        (24)
#define EV_HOUR_MASK        (0x00ffffff)
#define EV_HOUR_SHIFT       (0)

/* hasmonth is more like "is month more restricted than 'every month'",
 * which means it will be 1 when month has no bits set or some bits set,
 * and 0 when month has _all_ bits set
 */
#define EV_HASMONTH_MASK    (0x80000000)
#define EV_HASHMONTH_SHIFT  (31)
#define EV_DOM_MASK         (0x7fffffff)
#define EV_DOM_SHIFT        (0)

struct event_sched2 {
    uint32_t month;
};

struct event_details {
    char *name;
    strarray_t *exec;
};

#if 0
static struct event_sched1 *event_sched1;
static struct event_sched2 *event_sched2;
static struct event_details *event_details;
static size_t n_events;
#endif
