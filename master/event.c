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

uint64_t parse_cron_word(const char *word, unsigned max_value)
{
    /* max_value and zero are equivalent

        minute: 0==60, uses bits 0-59 (60 bits)
        hour:   0==24, uses bits 0-23 (24 bits)
        dom:    0==31, uses bits 0-30 (31 bits)
        month:  0==12, uses bits 0-11 (12 bits)
        dow:    0==7,  uses bits 0-6   (7 bits)

        minute and hour are naturally specified from 0,
        but dom and month are naturally specified from 1,
        any interesting consequences?
        => think about whether we want january=0 or december=12=0
        => think about whether we want first day of month to be 0, or
           last day of month to be 0
    */

    /* flex/bison parser?

    word : list
         | month_name
         | weekday_name
         ;

    list : range
         | list COMMA range
         ;

    range : ASTERISK
          | number
          | number HYPHEN number
          | range SLASH number
          ;

    number : NUMBER+;

    might be able to do all the bit fiddling from a bison parser, if we treat
    the set-of-bits as the semantic value of everything here
    */
    return 0;
}
