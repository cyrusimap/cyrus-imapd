/* partlist.h - Partition/backend selection functions
 *
 * Copyright (c) 1994-2010 Carnegie Mellon University.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The name "Carnegie Mellon University" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For permission or any legal
 *    details, please contact
 *      Carnegie Mellon University
 *      Center for Technology Transfer and Enterprise Creation
 *      4615 Forbes Avenue
 *      Suite 302
 *      Pittsburgh, PA  15213
 *      (412) 268-7393, fax: (412) 268-7395
 *      innovation@andrew.cmu.edu
 *
 * 4. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by Computing Services
 *     at Carnegie Mellon University (http://www.cmu.edu/computing/)."
 *
 * CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
 * FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "config.h"

typedef struct partitem
{
    /** Item name */
    char *item;
    /** Item value */
    char *value;
    /** Item underlying id (filesystem id) */
    unsigned long id;
    /** Item available space (KiB) */
    uint64_t available;
    /** Item total space (KiB) */
    uint64_t total;
    /** Item selection data */
    double quota;
} partitem_t;

typedef enum partmode {
    /** Random */
    PART_SELECT_MODE_RANDOM,
    /** Most free space. */
    PART_SELECT_MODE_FREESPACE_MOST,
    /** Most free space (percent). */
    PART_SELECT_MODE_FREESPACE_PERCENT_MOST,
    /** Weighted free space (percent) */
    PART_SELECT_MODE_FREESPACE_PERCENT_WEIGHTED,
    /** Weighted free space (percent) delta */
    PART_SELECT_MODE_FREESPACE_PERCENT_WEIGHTED_DELTA
} partmode_t;

struct partlist;

/**
 * \brief Item data callback.
 *
 * @param inout part_list   items list structure
 * @param in    idx         item index
 */
typedef void (*cb_part_filldata)(struct partlist *part_list, int idx);

typedef struct partlist
{
    /** Data callback */
    cb_part_filldata filldata;
    /** Number of items */
    int size;
    /** Items */
    partitem_t *items;
    /** Mode */
    partmode_t mode;
    /** Whether to actually use random mode */
    int force_random;
    /** Usage limit */
    int soft_usage_limit;
    /** Reinit limit */
    int reinit;
    /** Reinit counter */
    int reinit_counter;
} partlist_t;

/**
 * \brief Gets enumerated mode from string.
 */
extern partmode_t partlist_getmode(const char *mode);

/**
 * \brief Initializes items list.
 *
 * @param inout part_list   items list structure
 * @param in filldata       items data callback, NULL for default (physical partitions)
 * @param in key_prefix     key prefix for items to search for in configuration
 * @param in key_value      key value, to be used if list of items is stored in one option
 * @param in excluded       excluded items list
 * @param in mode           items mode
 * @param in soft_usage_limit usage limit
 * @param in reinit         reinit items data after given amount of operations
 */
extern void partlist_initialize(partlist_t *part_list,
                                cb_part_filldata filldata,
                                const char *key_prefix,
                                const char *key_value,
                                const char *excluded,
                                partmode_t mode,
                                int soft_usage_limit,
                                int reinit);

/**
 * \brief Frees items list.
 *
 * @param inout part_list   items list structure
 */
extern void partlist_free(partlist_t *part_list);

/**
 * \brief Selects item value from list.
 *
 * @param inout part_list   items list structure
 * @return selected item value, according to requested mode, or NULL if none found
 */
extern const char *partlist_select_value(partlist_t *part_list);

/**
 * \brief Iterate items in list
 *
 * @param inout part_list   items list structure
 * @param in proc           callback function, called for each item
 * @param in rock           argument to pass through to callback function
 * @return return value from callback function
 */
typedef int (*partlist_foreach_cb)(partitem_t *part_item, void *rock);
extern int partlist_foreach(partlist_t *part_list,
                            partlist_foreach_cb proc,
                            void *rock);
/**
 * \brief Selects local partitions.
 *
 * @return selected partition, according to requested mode, or NULL if none found
 */
const char *partlist_local_select(void);

/**
 * \brief Finds partition with most freespace (bytes or percents).
 *
 * @param out available  number of KiB available on partition
 * @param out total      total number of KiB on partition
 * @param out tavailable number of KiB available on server
 * @param out ttotal     total number of KiB on server
 * @return partition, or NULL if none found
 */
const char *partlist_local_find_freespace_most(int percent,
                                               uint64_t *available,
                                               uint64_t *total,
                                               uint64_t *tavailable,
                                               uint64_t *ttotal);

/**
 * \brief Frees local partition data.
 */
extern void partlist_local_done(void);
