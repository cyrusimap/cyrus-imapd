/*
 * grammar.h
 *
 *  Created on: Nov 6, 2014
 *      Author: James Cassell
 */

#ifndef SIEVE_GRAMMAR_H_
#define SIEVE_GRAMMAR_H_

#include "varlist.h"

int is_identifier(char *s);
char *parse_string(const char *s, variable_list_t *vars);

#endif /* SIEVE_GRAMMAR_H_ */
