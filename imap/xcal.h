/* xcal.h -- Routines for converting iCalendar to/from xCal
 *
 * Copyright (c) 1994-2013 Carnegie Mellon University.  All rights reserved.
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
 *
 */

#include <config.h>

#include <libical/ical.h>

#include "util.h"

#ifndef HAVE_VPOLL
/* Allow us to compile without #ifdef HAVE_VPOLL everywhere */
#define ICAL_POLLPROPERTIES_PROPERTY  ICAL_NO_PROPERTY
#endif

#define XML_NS_ICALENDAR	"urn:ietf:params:xml:ns:icalendar-2.0"

extern const char *icalproperty_value_kind_as_string(icalproperty *prop);
extern const char *icaltime_as_iso_string(const struct icaltimetype tt);
extern const char *icalvalue_utcoffset_as_iso_string(const icalvalue* value);
extern void icalrecurrencetype_add_as_xxx(struct icalrecurrencetype *recur,
					  void *obj,
					  void (*add_int)(void *, const char *,
							  int),
					  void (*add_str)(void *, const char *,
							  const char *));
extern struct icalrecurrencetype *
icalrecur_add_rule(struct icalrecurrencetype **rt,
		   const char *rpart, void *data,
		   int (*get_int)(void *),
		   const char* (*get_str)(void *));

extern char *icalcomponent_as_xcal_string(icalcomponent* comp);
extern icalcomponent *xcal_string_as_icalcomponent(const char *str);
extern const char *begin_xcal(struct buf *buf);
extern void end_xcal(struct buf *buf);

/* libxml2 replacement functions for those missing in older versions */
#if (LIBXML_VERSION < 20800)
#include <libxml/tree.h>

extern xmlChar *xmlBufferDetach(xmlBufferPtr buf);

#if (LIBXML_VERSION < 20703)
extern xmlNodePtr xmlFirstElementChild(xmlNodePtr parent);
extern xmlNodePtr xmlNextElementSibling(xmlNodePtr node);
#endif /* < 2.7.3 */
#endif /* < 2.8.0 */
