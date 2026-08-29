/* idclass.c -- per-host residue classes for minted identifiers
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

#include <config.h>

#include <stdint.h>

#include "idclass.h"
#include "libconfig.h"
#include "imapopts.h"

#define NSEC_MAX 999999999

/* zero is UTIME_OMIT, so class 0's lowest legal member is `modulus` */
static long nsec_class_floor(uint32_t base, uint32_t modulus)
{
    return base >= 1 ? (long) base : (long) modulus;
}

EXPORTED modseq_t idclass_modseq_next(modseq_t val,
                                      uint32_t base, uint32_t modulus)
{
    if (modulus <= 1) return val + 1;

    modseq_t next = val - (val % modulus) + base;
    if (next <= val) next += modulus;

    return next;
}

EXPORTED uint32_t idclass_uidvalidity_next(uint32_t val,
                                           uint32_t base, uint32_t modulus)
{
    if (modulus <= 1) return val + 1;

    uint32_t next = val - (val % modulus) + base;
    if (next <= val) {
        /* refuse to wrap: going backwards is worse than leaving the class */
        if (next > UINT32_MAX - modulus) return val + 1;
        next += modulus;
    }

    return next;
}

EXPORTED long idclass_nsec_align(long nsec, uint32_t base, uint32_t modulus)
{
    if (modulus <= 1) return nsec;
    if (nsec < 0 || nsec > NSEC_MAX) nsec = 0;

    long next = nsec - (nsec % (long) modulus) + (long) base;
    if (next > NSEC_MAX) next -= modulus;
    if (next < 1) next = nsec_class_floor(base, modulus);

    return next;
}

EXPORTED long idclass_nsec_next(long nsec, uint32_t base, uint32_t modulus)
{
    if (modulus <= 1) return nsec >= NSEC_MAX ? 1 : nsec + 1;

    long next = nsec + (long) modulus;
    if (next > NSEC_MAX) next = nsec_class_floor(base, modulus);

    return next;
}

EXPORTED void idclass_config(uint32_t *basep, uint32_t *modulusp)
{
    int modulus = config_getint(IMAPOPT_MODSEQ_MODULUS);
    int base = config_getint(IMAPOPT_MODSEQ_BASE);

    /* cyrus_init() rejects an invalid pair, but be defensive: a bad pair
     * must degrade to the historical behaviour, never to a wrong value */
    if (modulus < 1 || base < 0 || base >= modulus) {
        modulus = 1;
        base = 0;
    }

    *basep = base;
    *modulusp = modulus;
}

EXPORTED const char *idclass_config_error(void)
{
    int modulus = config_getint(IMAPOPT_MODSEQ_MODULUS);
    int base = config_getint(IMAPOPT_MODSEQ_BASE);

    if (modulus < 1)
        return "modseq_modulus must be at least 1";
    if (base < 0)
        return "modseq_base must not be negative";
    if (base >= modulus)
        return "modseq_base must be less than modseq_modulus";

    return NULL;
}

EXPORTED modseq_t modseq_next(modseq_t val)
{
    uint32_t base, modulus;
    idclass_config(&base, &modulus);
    return idclass_modseq_next(val, base, modulus);
}

EXPORTED uint32_t uidvalidity_next(uint32_t val)
{
    uint32_t base, modulus;
    idclass_config(&base, &modulus);
    return idclass_uidvalidity_next(val, base, modulus);
}

EXPORTED long nsec_align(long nsec)
{
    uint32_t base, modulus;
    idclass_config(&base, &modulus);
    return idclass_nsec_align(nsec, base, modulus);
}

EXPORTED long nsec_next(long nsec)
{
    uint32_t base, modulus;
    idclass_config(&base, &modulus);
    return idclass_nsec_next(nsec, base, modulus);
}
