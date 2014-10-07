/*
 * flags.h
 *
 *  Created on: Oct 6, 2014
 *      Author: James Cassell
 */

#ifndef FLAGS_H_
#define FLAGS_H_

#include "strarray.h"

static int verify_flag(char *s);
EXPORTED int verify_flaglist(strarray_t *sl);

#endif /* FLAGS_H_ */
