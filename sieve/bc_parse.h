/* bc_parse.h -- sieve bytecode - pass 1 of the decompiler */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef BC_PARSE_H
#define BC_PARSE_H

#include "bytecode.h"
#include "tree.h"


extern int bc_header_parse(bytecode_input_t *bc, int *version, int *requires);

extern int bc_action_parse(bytecode_input_t *bc, int pos, int version,
                           commandlist_t *cmd);
extern int bc_test_parse(bytecode_input_t *bc, int pos, int version,
                         test_t *test);

#endif
