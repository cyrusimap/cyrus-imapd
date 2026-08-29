/* idclass.h -- per-host residue classes for minted identifiers
 *
 * Copyright (c) 1994-2026 Carnegie Mellon University.  All rights reserved.
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

#ifndef INCLUDED_IDCLASS_H
#define INCLUDED_IDCLASS_H

#include <stdint.h>

#include "util.h"

/**
 * @file idclass.h
 *
 * Per-host residue classes for minted identifiers.
 *
 * Every identifier this host mints is congruent to @a base modulo
 * @a modulus.  Two hosts with different bases cannot mint the same value
 * even while split-brained, so a later merge has no clashes to resolve.
 *
 * A base of 0 with a modulus of 1 is the historical behaviour: plain
 * increment.
 */

/**
 * The next modseq in the class.
 *
 * @param val the modseq to advance past
 * @param base residue this host mints in
 * @param modulus size of the class
 * @return a modseq strictly greater than @a val
 */
extern modseq_t idclass_modseq_next(modseq_t val,
                                    uint32_t base, uint32_t modulus);

/**
 * The next uidvalidity in the class.
 *
 * @param val the uidvalidity to advance past
 * @param base residue this host mints in
 * @param modulus size of the class
 * @return a uidvalidity strictly greater than @a val, leaving the class
 *         rather than wrapping if the range is nearly exhausted
 */
extern uint32_t idclass_uidvalidity_next(uint32_t val,
                                         uint32_t base, uint32_t modulus);

/**
 * Move a nanosecond count onto the class without advancing it.  Idempotent,
 * so re-aligning an already aligned value is harmless.
 *
 * @param nsec the count to align, or anything outside UTIME_SAFE_NSEC
 * @param base residue this host mints in
 * @param modulus size of the class
 * @return a count within UTIME_SAFE_NSEC (1..999999999); zero means
 *         UTIME_OMIT when the spool file is stamped, so it is never produced
 */
extern long idclass_nsec_align(long nsec, uint32_t base, uint32_t modulus);

/**
 * The next nanosecond count in the class.
 *
 * @param nsec the count to advance past
 * @param base residue this host mints in
 * @param modulus size of the class
 * @return the next count within UTIME_SAFE_NSEC, wrapping to the bottom of
 *         the class rather than running out of the range
 */
extern long idclass_nsec_next(long nsec, uint32_t base, uint32_t modulus);

/** @see idclass_modseq_next, using the configured class */
extern modseq_t modseq_next(modseq_t val);

/** @see idclass_uidvalidity_next, using the configured class */
extern uint32_t uidvalidity_next(uint32_t val);

/** @see idclass_nsec_align, using the configured class */
extern long nsec_align(long nsec);

/** @see idclass_nsec_next, using the configured class */
extern long nsec_next(long nsec);

/**
 * The class configured by modseq_base and modseq_modulus, for the
 * replication handshake.  An invalid pair reads back as 0/1.
 *
 * @param[out] basep residue this host mints in
 * @param[out] modulusp size of the class
 */
extern void idclass_config(uint32_t *basep, uint32_t *modulusp);

/**
 * Validate modseq_base and modseq_modulus.
 *
 * @return an error string, or NULL if the configured pair is valid
 */
extern const char *idclass_config_error(void);

#endif /* INCLUDED_IDCLASS_H */
