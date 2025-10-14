/* prometheus.h -- Aggregate statistics for prometheus
 *
 * Copyright (c) 1994-2017 Carnegie Mellon University.  All rights reserved.
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

#ifndef INCLUDE_IMAP_PROMETHEUS_H
#define INCLUDE_IMAP_PROMETHEUS_H

#include <config.h>
#include <stddef.h>
#include <stdint.h>

#include "lib/mappedfile.h"
#include "lib/util.h"

#include "imap/promdata.h"

#define FNAME_PROM_SERVICE_REPORT "service.txt"
#define FNAME_PROM_MASTER_REPORT "master.txt"
#define FNAME_PROM_USAGE_REPORT "usage.txt"
#define FNAME_PROM_DONEPROCS "doneprocs"
#define FNAME_PROM_STATS_DIR "/stats"

extern const char *prometheus_stats_dir(void);

#define prometheus_increment(metric_id) prometheus_apply_delta(metric_id, 1)

#define prometheus_decrement(metric_id) prometheus_apply_delta(metric_id, -1)

extern void prometheus_apply_delta(enum prom_metric_id metric_id, double delta);

extern int prometheus_text_report(struct buf *buf, const char **mimetype);

extern enum prom_metric_id prometheus_lookup_label(
    enum prom_labelled_metric metric,
    const char *value);

#endif
