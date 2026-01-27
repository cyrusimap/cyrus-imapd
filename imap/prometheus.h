/* prometheus.h - Aggregate statistics for prometheus */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

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

#define prometheus_increment(metric_id) \
    prometheus_apply_delta(metric_id, 1)

#define prometheus_decrement(metric_id) \
    prometheus_apply_delta(metric_id, -1)

extern void prometheus_apply_delta(enum prom_metric_id metric_id,
                                   double delta);

extern int prometheus_text_report(struct buf *buf, const char **mimetype);

extern enum prom_metric_id prometheus_lookup_label(enum prom_labelled_metric metric,
                                                   const char *value);

#endif
