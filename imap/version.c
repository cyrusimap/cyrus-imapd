/* version.c - versioning functions */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#include <config.h>

#include <sasl/sasl.h>
#include <sys/utsname.h>

#include <string.h>
#include "version.h"
#include "map.h"
#include "cyr_lock.h"
#include "nonblock.h"
#include "idle.h"

#ifdef USE_SIEVE
#include "sieve/sieve_interface.h"
#endif

static char id_resp_command[MAXIDVALUELEN];
static char id_resp_arguments[MAXIDVALUELEN] = "";

/*
 * Grab the command line args for the ID response.
 */
EXPORTED void id_getcmdline(int argc, char **argv)
{
    snprintf(id_resp_command, MAXIDVALUELEN, "%s", *argv);
    while (--argc > 0) {
        snprintf(id_resp_arguments + strlen(id_resp_arguments),
                 MAXIDVALUELEN - strlen(id_resp_arguments),
                 "%s%s", *++argv, (argc > 1) ? " " : "");
    }
}

/*
 * Output the ID response.
 * We do NOT close the parameter list so other stuff can be added later.
 */
EXPORTED void id_response(struct protstream *pout)
{
    struct utsname os;
    const char *sasl_imp;
    int sasl_ver;
    char env_buf[MAXIDVALUELEN+1];

    prot_printf(pout, "* ID ("
                "\"name\" \"Cyrus IMAPD\""
                " \"version\" \"%s\""
                " \"vendor\" \"Project Cyrus\""
                " \"support-url\" \"https://www.cyrusimap.org\"",
                CYRUS_VERSION);

    /* add the os info */
    if (uname(&os) != -1)
        prot_printf(pout,
                    " \"os\" \"%s\""
                    " \"os-version\" \"%s\"",
                    os.sysname, os.release);

#ifdef ID_SAVE_CMDLINE
    /* add the command line info */
    prot_printf(pout, " \"command\" \"%s\"", id_resp_command);
    if (strlen(id_resp_arguments)) {
        prot_printf(pout, " \"arguments\" \"%s\"", id_resp_arguments);
    } else {
        prot_printf(pout, " \"arguments\" NIL");
    }
#endif

    /* SASL information */
    snprintf(env_buf, MAXIDVALUELEN,"Built w/Cyrus SASL %d.%d.%d",
             SASL_VERSION_MAJOR, SASL_VERSION_MINOR, SASL_VERSION_STEP);

    sasl_version(&sasl_imp, &sasl_ver);
    snprintf(env_buf + strlen(env_buf), MAXIDVALUELEN - strlen(env_buf),
             "; Running w/%s %d.%d.%d", sasl_imp,
             (sasl_ver & 0xFF000000) >> 24,
             (sasl_ver & 0x00FF0000) >> 16,
             (sasl_ver & 0x0000FFFF));

    /* add the environment info */
#ifdef DB_VERSION_STRING
    snprintf(env_buf + strlen(env_buf), MAXIDVALUELEN - strlen(env_buf),
             "; Built w/%s", DB_VERSION_STRING);
    snprintf(env_buf + strlen(env_buf), MAXIDVALUELEN - strlen(env_buf),
             "; Running w/%s", db_version(NULL, NULL, NULL));
#endif
    snprintf(env_buf + strlen(env_buf), MAXIDVALUELEN - strlen(env_buf),
             "; Built w/%s", OPENSSL_VERSION_TEXT);
    snprintf(env_buf + strlen(env_buf), MAXIDVALUELEN - strlen(env_buf),
             "; Running w/%s", SSLeay_version(SSLEAY_VERSION));
#ifdef EGD_SOCKET
    snprintf(env_buf + strlen(env_buf), MAXIDVALUELEN - strlen(env_buf),
             " (with EGD)");
#endif
#ifdef HAVE_ZLIB
    snprintf(env_buf + strlen(env_buf), MAXIDVALUELEN - strlen(env_buf),
             "; Built w/zlib %s", ZLIB_VERSION);
    snprintf(env_buf + strlen(env_buf), MAXIDVALUELEN - strlen(env_buf),
             "; Running w/zlib %s", zlibVersion());
#endif
#ifdef USE_SIEVE
    snprintf(env_buf + strlen(env_buf), MAXIDVALUELEN - strlen(env_buf),
             "; %s", SIEVE_VERSION);
#endif
#ifdef HAVE_LIBWRAP
    snprintf(env_buf + strlen(env_buf), MAXIDVALUELEN - strlen(env_buf),
             "; TCP Wrappers");
#endif
    snprintf(env_buf + strlen(env_buf), MAXIDVALUELEN - strlen(env_buf),
             "; mmap = %s", map_method_desc);
    snprintf(env_buf + strlen(env_buf), MAXIDVALUELEN - strlen(env_buf),
             "; lock = %s", lock_method_desc);
    snprintf(env_buf + strlen(env_buf), MAXIDVALUELEN - strlen(env_buf),
             "; nonblock = %s", nonblock_method_desc);
    if (idle_method_desc)
        snprintf(env_buf + strlen(env_buf), MAXIDVALUELEN - strlen(env_buf),
                 "; idle = %s", idle_method_desc);

    prot_printf(pout, " \"environment\" \"%s\"", env_buf);
}
