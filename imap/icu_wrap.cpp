/* icu_wrap.c --  C++ hiding wrapper API for ICU
 *
 * Copyright (c) 1994-2019 Carnegie Mellon University.  All rights reserved.
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

extern "C" {
#include "config.h"
#include "string.h"
#include "xmalloc.h"
};


#include <unicode/ucnv.h>
#include <unicode/unistr.h>
#include <unicode/timezone.h>

extern "C" EXPORTED char *icu_getIDForWindowsID(const char *id)
{
    UErrorCode status = U_ZERO_ERROR;

    UConverter *utf8cnv = ucnv_open("utf-8", &status);
    if (U_FAILURE(status)) return NULL;
    icu::UnicodeString uWinID {id, -1, utf8cnv, status};
    ucnv_close(utf8cnv);

    icu::UnicodeString uID;
    icu::TimeZone::getIDForWindowsID(uWinID, NULL, uID, status);

    std::string str;
    uID.toUTF8String(str);
    if (!str.empty()) return xstrdup(str.c_str());

    if (!strcasecmp(id, "Mid-Atlantic Standard Time")) {
        /* ICU doesn't map this ID */
        return xstrdup("Atlantic/South_Georgia");
    }

    return NULL;
}
