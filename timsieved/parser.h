/* parser.h */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef PARSER_H
#define PARSER_H

#include "prot.h"
#include "imap/global.h" /* for saslprops_t */

int parser(struct protstream *sieved_out,
           struct protstream *sieved_in, struct saslprops_t *saslprops);


#endif /* PARSER_H */
