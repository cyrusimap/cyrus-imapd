/* icu_wrap.c --  C++ hiding wrapper API for ICU */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

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
