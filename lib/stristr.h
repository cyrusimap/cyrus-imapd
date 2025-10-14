/* stristr.h -- locate a substring case-insensitively
 */

#ifndef INCLUDED_STRISTR_H
#define INCLUDED_STRISTR_H

#include <stddef.h>

extern char *stristr(const char *haystack, const char *needle);
extern char *strinstr(const char *haystack,
                      size_t haystack_len,
                      const char *needle);

#endif /* INCLUDED_STRISTR_H */
