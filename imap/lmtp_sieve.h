/* lmtp_sieve.h -- Sieve implementation for lmtpd */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef LMTP_SIEVE_H
#define LMTP_SIEVE_H

#include "lmtpd.h"
#include "conversations.h"
#include "sieve/sieve_interface.h"

#ifdef WITH_DAV
#include "carddav_db.h"
#else
struct carddav_db { };
#endif

struct sieve_interp_ctx {
    const char *userid;
    struct conversations_state *cstate;
    struct carddav_db *carddavdb;
};

sieve_interp_t *setup_sieve(struct sieve_interp_ctx *ctx);
int run_sieve(const mbname_t *mbname,
              sieve_interp_t *interp, deliver_data_t *mydata);
void sieve_srs_init(void);
void sieve_srs_free(void);

#endif /* LMTP_SIEVE_H */
