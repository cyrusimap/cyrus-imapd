/* backend.c -- IMAP server proxy for Cyrus Murder
 *
 * Copyright (c) 1994-2008 Carnegie Mellon University.  All rights reserved.
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

#include <config.h>

#include <stdio.h>
#include <string.h>
#include <signal.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <fcntl.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sysexits.h>
#include <syslog.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>

#include <sasl/sasl.h>
#include <sasl/saslutil.h>

#include "backend.h"
#include "global.h"
#include "iptostring.h"
#include "nonblock.h"
#include "tok.h"
#include "util.h"
#include "xmalloc.h"
#include "xstrlcpy.h"
#include "xstrlcat.h"

#ifndef AI_V4MAPPED
#define AI_V4MAPPED	0
#endif

#ifndef AI_ADDRCONFIG
#define AI_ADDRCONFIG	0
#endif

#ifndef AI_MASK
#define AI_MASK	(AI_V4MAPPED | AI_ADDRCONFIG)
#endif

enum {
    AUTO_CAPA_BANNER = -1,
    AUTO_CAPA_NO = 0,
};

static void forget_capabilities(struct backend *s)
{
    int i;

    for (i = 0 ; i < s->num_cap_params ; i++)
        free(s->cap_params[i].params);
    s->capability = 0;
    free(s->cap_params);
    s->cap_params = NULL;
    s->num_cap_params = 0;
}

static char *append_word(char *w1, const char *w2)
{
    int len1 = strlen(w1);
    int len2 = strlen(w2);
    w1 = xrealloc(w1, len1 + len2 + 2);
    w1[len1] = ' ';
    strcpy(w1+len1+1, w2);
    return w1;
}

/*
 * Save the capability.  Updates @s->capability so that the CAPA() macro
 * will find the flag.  Saves the @param string if not NULL.
 */
static void save_capability(struct backend *s,
                            const struct capa_t *c,
                            const char *param)
{
    int i;

    if (s->prot->type != TYPE_STD) return;

    s->capability |= c->flag;

    if (param) {
        /* find the matching cap_params entry */
        for (i = 0 ; i < s->num_cap_params ; i++)
            if (s->cap_params[i].capa == c->flag)
                break;

        if (i == s->num_cap_params) {
            /* not found, expand the array and add a params */
            s->num_cap_params++;
            s->cap_params = xrealloc(s->cap_params,
                     sizeof(*s->cap_params) * s->num_cap_params);

            s->cap_params[i].capa = c->flag;
            s->cap_params[i].params = xstrdup(param);
        } else {
            /* append to the existing params */
            s->cap_params[i].params = append_word(s->cap_params[i].params, param);
        }
    }
}

/*
 * We have been given a @name and optionally a @value by the server,
 * check to see if the protocol_t knows about this specific capability.
 * If known, save the capability.
 */
static int match_capability(struct backend *s,
                            const char *name, const char *value)
{
    const struct capa_t *c;
    const char *cend;

    if (s->prot->type != TYPE_STD) return 0;

    for (c = s->prot->u.std.capa_cmd.capa; c->str; c++) {
        cend = strchr(c->str, '=');

        if (cend) {
            /* c->str is of the form NAME=VALUE, we want to match
             * @name against the the NAME part and @value against
             * the VALUE part */
            if (strlen(name) == (unsigned)(cend - c->str) &&
                !strncasecmp(name, c->str, (int)(cend - c->str)) &&
                value &&
                !strcasecmp(value, cend+1)) {
                save_capability(s, c, NULL);
                return 1;   /* full match, stop calling me with this @name */
            }
        } else {
            /* c->str is a bare NAME, just try to match it against @name */
            if (!strcasecmp(c->str, name)) {
                save_capability(s, c, value);
                return 2;   /* partial match, keep calling with new @value
                             * for this @name */
            }
        }
    }

    return 0;   /* no match, stop calling me with this @name */
}

/*
 * Given a line buffer @buf, find the IMAP response code named by @code,
 * isolate it and return the start of it, or NULL if not found.
 */
static char *find_response_code(char *buf, const char *code)
{
    char *start;
    char *end;
    int codelen = strlen(code);

    /* Try to find the first response code */
    start = strchr(buf, '[');
    if (!start)
        return NULL;    /* no response codes */

    start++;
    for (;;) {
        while (*start && Uisspace(*start))
            start++;
        if (!*start)
            break;      /* nothing to see here */
        /* response codes are delineated by [] */
        if (!(end = strchr(start, ']')))
            break;      /* unbalanced [response code] */
        if (!strncasecmp(start, code, codelen) && Uisspace(start[codelen])) {
            *end = '\0';
            start += codelen+1;
            return start;
        } else {
            start = end+1;
        }
    }

    return NULL;
}

/* Tokenize on whitespace, for parse_capability */
static char *ws_tok(char *buf)
{
    return strtok(buf, " \t\r\n");
}

/* Tokenize on whitespace OR dash, for parse_capability */
static char *dash_tok(char *buf)
{
    return strtok(buf, " \t\r\n-");
}

/* Tokenize on alternate "quoted-words", for parse_capability.
 * Note that we probably don't need the general case with escapes. */
static char *quote_tok(char *buf)
{
    char *p;
    static const char sep[] = "\"";

    p = strtok(buf, sep);
    if (p)
        strtok(NULL, sep);
    return p;
}


/*
 * Parse a line of text from the wire which might contain
 * capabilities, using various details in the capa_cmd field of
 * the protocol_t to decode capabilities.  Only capabilities
 * explicitly named in an entry in the capa_cmd.capa[] array
 * are detected; any others present on the wire are ignored.
 * All string matches are case-insensitive.  Entries are
 * matched thus:
 *
 * { "NAME", FLAG }
 *      If a capability named NAME is present on the wire,
 *      the corresponding FLAG will be set where the CAPA()
 *      macro will test it.  Furthermore, if any parameters
 *      are present on the wire they will be saved where
 *      the backend_get_cap_params() function will find them.
 *      If multiple parameters are present on the wire, all
 *      of them will be saved, separated by space characters.
 *
 * { "NAME=VALUE", FLAG }
 *      If a capability named NAME is present on the wire,
 *      *and* a parameter which matches VALUE is also present,
 *      the corresponding FLAG will be set where the CAPA()
 *      macro will test it.  VALUE is not saved anywhere and
 *      backend_get_cap_params() will not return it.
 *
 * Returns: 1 if any capabilities were found in the string,
 *          0 otherwise.
 */
static int parse_capability(struct backend *s, const char *str)
{
    char *buf;
    char *word;
    char *param;
    int matches = 0;
    char *(*tok)(char *) = ws_tok;
    static const char code[] = "CAPABILITY";

    if (s->prot->type != TYPE_STD) return 0;

    /* save the buffer, we're going to be destructively parsing it */
    buf = xstrdupsafe(str);

    if ((s->prot->u.std.capa_cmd.formatflags & CAPAF_ONE_PER_LINE)) {
        /*
         * POP3, LMTP and sync protocol style: one capability per line.
         */
        if ((s->prot->u.std.capa_cmd.formatflags & CAPAF_QUOTE_WORDS))
            tok = quote_tok;

        if ((s->prot->u.std.capa_cmd.formatflags & CAPAF_DASH_STUFFING))
            word = dash_tok(buf);
        else
            word = tok(buf);

        /* Ignore the first word of the line.  Used for LMTP and POP3 */
        if (word && (s->prot->u.std.capa_cmd.formatflags & CAPAF_SKIP_FIRST_WORD))
            word = tok(NULL);

        if (!word)
            goto out;
        /* @word is the capability name. Any remaining atoms are parameters */
        param = tok(NULL);

        if (!param) {
            /* no parameters */
            matches |= match_capability(s, word, NULL);
        } else {
            /* 1 or more parameters */
            for ( ; param ; param = tok(NULL)) {
                int r = match_capability(s, word, param);
                matches |= r;
                if (r != 2)
                    break;
            }
        }

    } else {
        /*
         * IMAP style: one humongous line with a list of atoms
         * of the form NAME or NAME=PARAM, preceded by the atom
         * CAPABILITY, and either surrounded by [] or being an
         * untagged response like "* CAPABILITY ...atoms... CRLF"
         */
        char *start;

        if ((start = find_response_code(buf, code))) {
            /* The line is probably a PREAUTH or OK response, possibly
             * containing a CAPABILITY response code, and possibly
             * containing some other response codes we don't care about. */
            word = tok(start);
        } else {
            /* The line is probably an untagged response to a CAPABILITY
             * command.  Tokenize until we find the CAPABILITY atom */
            for (word = tok(buf) ;
                 word && strcasecmp(word, code) ;
                 word = tok(NULL))
                ;
            if (word)
                word = tok(NULL);   /* skip the CAPABILITY atom itself */
        }

        /* `word' now points to the first capability; parse it and
         * each remaining word as a NAME or NAME=VALUE capability */
        for ( ; word ; word = tok(NULL)) {
            param = strchr(word, '=');
            if (param)
                *param++ = '\0';
            matches |= match_capability(s, word, param);
        }
    }

out:
    free(buf);
    return !!matches;
}

static void post_parse_capability(struct backend *s)
{
    if (s->prot->type != TYPE_STD) return;

    if (s->prot->u.std.capa_cmd.postcapability)
        s->prot->u.std.capa_cmd.postcapability(s);
}

/*
 * Get capabilities from the server, and parse them according to
 * details in the protocol_t, so that the CAPA() macro and perhaps
 * the backend_get_cap_params() function will notice them.  Any
 * capabilities previously parsed are forgotten.
 *
 * The server might give us capabilities for free just because we
 * connected (or did a STARTTLS or logged in); in this case, call
 * with a non-zero value for @automatic.  Otherwise, we send a
 * protocol-specific command to the server to tickle it into
 * disgorging some capabilities.
 *
 * Returns: 1 if any capabilities were found, 0 otherwise.
 */
static int ask_capability(struct backend *s, int dobanner, int automatic)
{
    struct protstream *pout = s->out, *pin = s->in;
    const struct protocol_t *prot = s->prot;
    int matches = 0;
    char str[2047];
    const char *resp;

    if (prot->type != TYPE_STD) return 0;

    resp = (automatic == AUTO_CAPA_BANNER) ?
        prot->u.std.banner.resp : prot->u.std.capa_cmd.resp;

    if (!automatic) {
        /* no capability command */
        if (!prot->u.std.capa_cmd.cmd) return -1;

        /* request capabilities of server */
        prot_printf(pout, "%s", prot->u.std.capa_cmd.cmd);
        if (prot->u.std.capa_cmd.arg)
            prot_printf(pout, " %s", prot->u.std.capa_cmd.arg);
        prot_printf(pout, "\r\n");
        prot_flush(pout);
    }

    forget_capabilities(s);

    do {
        if (prot_fgets(str, sizeof(str), pin) == NULL) break;

        matches |= parse_capability(s, str);

        if (!resp) {
            /* multiline response with no distinct end (IMAP banner) */
            prot_NONBLOCK(pin);
        }

        if (dobanner) {

            // This routine would always take the last line, which for
            // starttls against backends would amount to a tagged
            // "ok completed" response.

            // Banner is always untagged
            if (!strncmp(str, "* ", 2)) {

                // The last untagged response however is a new set
                // of capabilities, and not the banner.
                //
                // Banner also has "server ready" some place
                if (strstr(str, "server ready")) {
                    xstrncpy(s->banner, str, sizeof(s->banner));
                }
            }
        }

        /* look for the end of the capabilities */
    } while (!resp || strncasecmp(str, resp, strlen(resp)));

    prot_BLOCK(pin);
    post_parse_capability(s);
    return matches;
}

/*
 * Return the parameters reported by the server for the given
 * capability.  @capa must be a single capability flag, as given in the
 * protocol_t.  Return value is a string, comprising all the parameters
 * for the given capability, in their original string form, in the order
 * seen on the wire, separated by a single space character.  If the
 * capability was not reported by the server, or was reported with no
 * parameters, NULL is returned.
 */
EXPORTED char *backend_get_cap_params(const struct backend *s, unsigned long capa)
{
    int i;

    if (!(s->capability & capa))
        return NULL;

    for (i = 0 ; i < s->num_cap_params ; i++) {
        if (s->cap_params[i].capa == capa) {
            return xstrdup(s->cap_params[i].params);
        }
    }

    return NULL;
}

#ifdef HAVE_ZLIB
static int do_compress(struct backend *s, struct simple_cmd_t *compress_cmd)
{
    char buf[1024];

    /* send compress command */
    prot_printf(s->out, "%s\r\n", compress_cmd->cmd);
    prot_flush(s->out);

    /* check response */
    if (!prot_fgets(buf, sizeof(buf), s->in) ||
        strncmp(buf, compress_cmd->ok, strlen(compress_cmd->ok)))
        return -1;

    prot_setcompress(s->in);
    prot_setcompress(s->out);

    return 0;
}
#else
static int do_compress(struct backend *s __attribute__((unused)),
                       struct simple_cmd_t *compress_cmd __attribute__((unused)))
{
    return -1;
}
#endif /* HAVE_ZLIB */

#ifdef HAVE_SSL
EXPORTED int backend_starttls(  struct backend *s,
                                struct tls_cmd_t *tls_cmd,
                                const char *c_cert_file,
                                const char *c_key_file)
{
    char *auth_id = NULL;
    int *layerp = NULL;
    int r = 0;
    int auto_capa = 0;

    if (tls_cmd) {
        char buf[2048];
        /* send starttls command */
        prot_printf(s->out, "%s\r\n", tls_cmd->cmd);
        prot_flush(s->out);

        /* check response */
        if (!prot_fgets(buf, sizeof(buf), s->in) ||
            strncmp(buf, tls_cmd->ok, strlen(tls_cmd->ok)))
            return -1;

        auto_capa = tls_cmd->auto_capa;
    }

    r = tls_init_clientengine(5, c_cert_file, c_key_file);
    if (r == -1) return -1;

    /* SASL and openssl have different ideas about whether ssf is signed */
    layerp = (int *) &s->ext_ssf;
    r = tls_start_clienttls(s->in->fd, s->out->fd, layerp, &auth_id,
                            &s->tlsconn, &s->tlssess);
    if (r == -1) return -1;

    if (s->saslconn) {
        r = sasl_setprop(s->saslconn, SASL_SSF_EXTERNAL, &s->ext_ssf);
        if (r == SASL_OK)
            r = sasl_setprop(s->saslconn, SASL_AUTH_EXTERNAL, auth_id);
        if (auth_id) free(auth_id);
        if (r != SASL_OK) return -1;
    }

    prot_settls(s->in,  s->tlsconn);
    prot_settls(s->out, s->tlsconn);

    ask_capability(s, /*dobanner*/1, auto_capa);

    return 0;
}
#else
EXPORTED int backend_starttls(  struct backend *s __attribute__((unused)),
                                struct tls_cmd_t *tls_cmd __attribute__((unused)),
                                const char *c_cert_file __attribute__((unused)),
                                const char *c_key_file __attribute__((unused)))
{
    return -1;
}
#endif /* HAVE_SSL */

EXPORTED char *intersect_mechlists( char *config, char *server )
{
    char *newmechlist = xzmalloc( strlen( config ) + 1 );
    char *cmech = NULL, *smech = NULL, *s;
    int count = 0;
    char csave, ssave;

    do {
        if ( isalnum( *config ) || *config == '_' || *config == '-' ) {
            if ( cmech == NULL ) {
                cmech = config;
            }
        } else {
            if ( cmech != NULL ) {
                csave = *config;
                *config = '\0';

                s = server;
                do {
                    if ( isalnum( *s ) || *s == '_' || *s == '-' ) {
                        if ( smech == NULL ) {
                            smech = s;
                        }
                    } else {
                        if ( smech != NULL ) {
                            ssave = *s;
                            *s = '\0';

                            if ( strcasecmp( cmech, smech ) == 0 ) {
                                if ( count > 0 ) {
                                    strcat( newmechlist, " " );
                                }
                                strcat( newmechlist, cmech );
                                count++;

                                *s = ssave;
                                smech = NULL;
                                break;
                            }

                            *s = ssave;
                            smech = NULL;
                        }
                    }
                } while ( *s++ );

                *config = csave;
                cmech = NULL;
            }
        }
    } while ( *config++ );

    if ( count == 0 ) {
        free( newmechlist );
        return( NULL );
    }
    return( newmechlist );
}

static int backend_authenticate(struct backend *s, const char *userid,
                                sasl_callback_t *cb, const char **status)
{
    struct protocol_t *prot = s->prot;
    int r;
    char *mechlist;
    sasl_security_properties_t secprops =
        { 0, 0xFF, PROT_BUFSIZE, 0, NULL, NULL }; /* default secprops */
    struct sockaddr_storage saddr_l, saddr_r;
    char remoteip[60], localip[60];
    socklen_t addrsize;
    char buf[2048], optstr[128], *p;
    const char *mech_conf, *pass;
    if (prot->type != TYPE_STD) return SASL_FAIL;

    /* set the IP addresses */
    addrsize = sizeof(struct sockaddr_storage);
    if (getpeername(s->sock, (struct sockaddr *)&saddr_r, &addrsize) != 0)
        return SASL_FAIL;
    if (iptostring((struct sockaddr *)&saddr_r, addrsize, remoteip, 60) != 0)
        return SASL_FAIL;

    addrsize = sizeof(struct sockaddr_storage);
    if (getsockname(s->sock, (struct sockaddr *)&saddr_l, &addrsize)!=0)
        return SASL_FAIL;
    if (iptostring((struct sockaddr *)&saddr_l, addrsize, localip, 60) != 0)
        return SASL_FAIL;

    s->sasl_cb = NULL;
    if (!cb) {
        strlcpy(optstr, s->hostname, sizeof(optstr));
        p = strchr(optstr, '.');
        if (p) *p = '\0';
        strlcat(optstr, "_password", sizeof(optstr));
        pass = config_getoverflowstring(optstr, NULL);
        if(!pass) pass = config_getstring(IMAPOPT_PROXY_PASSWORD);
        cb = mysasl_callbacks(userid,
                              config_getstring(IMAPOPT_PROXY_AUTHNAME),
                              config_getstring(IMAPOPT_PROXY_REALM),
                              pass);
        s->sasl_cb = cb;
    }

    /* Require proxying if we have an "interesting" userid (authzid) */
    r = sasl_client_new(prot->sasl_service, s->hostname, localip, remoteip, cb,
                        (userid  && *userid ? SASL_NEED_PROXY : 0) |
                        (prot->u.std.sasl_cmd.parse_success ? SASL_SUCCESS_DATA : 0),
                        &s->saslconn);
    if (r != SASL_OK) {
        free_callbacks(s->sasl_cb);
        s->sasl_cb = NULL;
        return r;
    }

    r = sasl_setprop(s->saslconn, SASL_SEC_PROPS, &secprops);
    if (r != SASL_OK) {
        free_callbacks(s->sasl_cb);
        s->sasl_cb = NULL;
        return r;
    }

    /* Get SASL mechanism list.  We can force a particular
       mechanism using a <shorthost>_mechs option */
    strcpy(buf, s->hostname);
    p = strchr(buf, '.');
    if (p) *p = '\0';
    strcat(buf, "_mechs");
    mech_conf = config_getoverflowstring(buf, NULL);

    if (!mech_conf)
        mech_conf = config_getstring(IMAPOPT_FORCE_SASL_CLIENT_MECH);

#ifdef HAVE_SSL
    strlcpy(optstr, s->hostname, sizeof(optstr));
    p = strchr(optstr, '.');
    if (p) *p = '\0';

    strlcat(optstr, "_client_cert", sizeof(optstr));
    const char *c_cert_file = config_getoverflowstring(optstr, NULL);

    if (!c_cert_file) {
        c_cert_file = config_getstring(IMAPOPT_TLS_CLIENT_CERT);
    }

    strlcpy(optstr, s->hostname, sizeof(optstr));
    p = strchr(optstr, '.');
    if (p) *p = '\0';

    strlcat(optstr, "_client_key", sizeof(optstr));

    const char *c_key_file = config_getoverflowstring(optstr, NULL);
    if (!c_key_file) {
        c_key_file = config_getstring(IMAPOPT_TLS_CLIENT_KEY);
    }
#else
    const char *c_cert_file = NULL;
    const char *c_key_file = NULL;
#endif

    mechlist = backend_get_cap_params(s, CAPA_AUTH);

    do {
        /* If we have a mech_conf, use it */
        if (mech_conf && mechlist) {
            char *conf = xstrdup(mech_conf);
            char *newmechlist = intersect_mechlists( conf, mechlist );

            if ( newmechlist == NULL ) {
                syslog( LOG_INFO, "%s did not offer %s", s->hostname,
                        mech_conf );
            }

            free(conf);
            free(mechlist);
            mechlist = newmechlist;
        }

        if (mechlist) {
            /* we now do the actual SASL exchange */
            saslclient(s->saslconn, &prot->u.std.sasl_cmd, mechlist,
                       s->in, s->out, &r, status);

            /* garbage collect */
            free(mechlist);
            mechlist = NULL;
        }
        else r = SASL_NOMECH;

        /* If we don't have a usable mech, do TLS and try again */
    } while (r == SASL_NOMECH && CAPA(s, CAPA_STARTTLS) &&
             backend_starttls(s, &prot->u.std.tls_cmd, c_cert_file, c_key_file) != -1 &&
             (mechlist = backend_get_cap_params(s, CAPA_AUTH)));

    if (r == SASL_OK) {
        prot_setsasl(s->in, s->saslconn);
        prot_setsasl(s->out, s->saslconn);
    }

    if (mechlist) free(mechlist);

    return r;
}

static int backend_login(struct backend *ret, const char *userid,
                         sasl_callback_t *cb, const char **auth_status,
                         int noauth)
{
    int r = 0;
    int ask = 1; /* should we explicitly ask for capabilities? */
    char buf[2047];
    struct protocol_t *prot = ret->prot;

    if (prot->type != TYPE_STD) return -1;

    if (prot->u.std.banner.auto_capa) {
        /* try to get the capabilities from the banner */
        r = ask_capability(ret, /*dobanner*/1, AUTO_CAPA_BANNER);
        if (r) {
            /* found capabilities in banner -> don't ask */
            ask = 0;
        }
    }
    else {
        do { /* read the initial greeting */
            if (!prot_fgets(buf, sizeof(buf), ret->in)) {
                syslog(LOG_ERR,
                       "backend_login(): couldn't read initial greeting: %s",
                       ret->in->error ? ret->in->error : "(null)");
                return -1;
            }
        } while (strncasecmp(buf, prot->u.std.banner.resp,
                             strlen(prot->u.std.banner.resp)));
        xstrncpy(ret->banner, buf, sizeof(ret->banner));
    }

    if (ask) {
        /* get the capabilities */
        ask_capability(ret, /*dobanner*/0, AUTO_CAPA_NO);
    }

    /* now need to authenticate to backend server,
       unless we're doing LMTP/CSYNC on a UNIX socket (deliver/sync_client) */
    if (!noauth) {
        char *old_mechlist = backend_get_cap_params(ret, CAPA_AUTH);
        const char *my_status = NULL;

        if ((r = backend_authenticate(ret, userid, cb, &my_status))) {
            syslog(LOG_ERR, "couldn't authenticate to backend server: %s",
                   sasl_errstring(r, NULL, NULL));
            free(old_mechlist);
            return -1;
        }
        else {
            const void *ssf;

            sasl_getprop(ret->saslconn, SASL_SSF, &ssf);
            if (*((sasl_ssf_t *) ssf)) {
                /* if we have a SASL security layer, compare SASL mech lists
                   before/after AUTH to check for a MITM attack */
                char *new_mechlist;
                int auto_capa = (prot->u.std.sasl_cmd.auto_capa == AUTO_CAPA_AUTH_SSF);

                if (!strcmp(prot->service, "sieve")) {
                    /* XXX  Hack to handle ManageSieve servers.
                     * No way to tell from protocol if server will
                     * automatically send capabilities, so we treat it
                     * as optional.
                     */
                    char ch;

                    /* wait and probe for possible auto-capability response */
                    usleep(250000);
                    prot_NONBLOCK(ret->in);
                    if ((ch = prot_getc(ret->in)) != EOF) {
                        prot_ungetc(ch, ret->in);
                    } else {
                        auto_capa = AUTO_CAPA_AUTH_NO;
                    }
                    prot_BLOCK(ret->in);
                }

                ask_capability(ret, /*dobanner*/0, auto_capa);
                new_mechlist = backend_get_cap_params(ret, CAPA_AUTH);
                if (new_mechlist &&
                    old_mechlist &&
                    strcmp(new_mechlist, old_mechlist)) {
                    syslog(LOG_ERR, "possible MITM attack:"
                           "list of available SASL mechanisms changed");

                    if (new_mechlist) free(new_mechlist);
                    if (old_mechlist) free(old_mechlist);
                    return -1;
                }
                free(new_mechlist);
            }
            else if (prot->u.std.sasl_cmd.auto_capa == AUTO_CAPA_AUTH_OK) {
                /* try to get the capabilities from the AUTH success response */
                forget_capabilities(ret);
                parse_capability(ret, my_status);
                post_parse_capability(ret);
            }

            if (!(strcmp(prot->service, "imap") &&
                 (strcmp(prot->service, "pop3")))) {
                char rsessionid[MAX_SESSIONID_SIZE];
                parse_sessionid(my_status, rsessionid);
                syslog(LOG_NOTICE, "auditlog: proxy %s sessionid=<%s> remote=<%s>", userid, session_id(), rsessionid);
            }
        }

        if (auth_status) *auth_status = my_status;
        free(old_mechlist);
    }

    /* start compression if requested and both client/server support it */
    if (config_getswitch(IMAPOPT_PROXY_COMPRESS) &&
        CAPA(ret, CAPA_COMPRESS) &&
        prot->u.std.compress_cmd.cmd) {
        r = do_compress(ret, &prot->u.std.compress_cmd);
        if (r) {
            syslog(LOG_NOTICE, "couldn't enable compression on backend server: %s", error_message(r));
            r = 0; /* not a fail-level error */
        }
    }

    return 0;
}

static int backend_client_bind(const int sock, const struct addrinfo *dest)
{
    const char *client_bind_name = config_getstring(IMAPOPT_CLIENT_BIND_NAME);
    struct addrinfo hints = {0}, *res0 = NULL, *iter;
    int r;

    if (!client_bind_name) client_bind_name = config_servername;

    hints.ai_family = dest->ai_family;
    hints.ai_socktype = dest->ai_socktype;
    hints.ai_protocol = dest->ai_protocol;
    hints.ai_flags = AI_MASK & (AI_V4MAPPED | AI_ADDRCONFIG);

    r = getaddrinfo(client_bind_name, NULL, &hints, &res0);
    if (r && config_debug) {
        syslog(LOG_DEBUG, "%s: getaddrinfo(%s) failed: %s",
               __func__, client_bind_name, gai_strerror(r));
    }

    for (iter = res0; iter != NULL; iter = iter->ai_next) {
        r = bind(sock, iter->ai_addr, iter->ai_addrlen);
        if (!r) break;  /* found a good one */

        if (config_debug) {
            char bind_addr[1024] = {0};
            int saved_errno = errno;

            getnameinfo(iter->ai_addr, iter->ai_addrlen,
                        bind_addr, sizeof(bind_addr),
                        NULL, 0,
                        NI_NUMERICHOST);

            errno = saved_errno;
            syslog(LOG_DEBUG, "%s: bind(%s) failed: %m", __func__, bind_addr);
        }
    }

    if (r || !iter) {
        syslog(LOG_ERR, "client bind failed: no suitable address found for %s",
               client_bind_name);
        r = r ? r : -1;
    }

    if (res0 != NULL) freeaddrinfo(res0);

    return r;
}

EXPORTED struct backend *backend_connect_pipe(int infd, int outfd,
                                              struct protocol_t *prot,
                                              int do_tls, int logfd)

{
    struct backend *ret = xzmalloc(sizeof(struct backend));
    int r;

    ret->in = prot_new(infd, 0);
    ret->out = prot_new(outfd, 1);
    ret->sock = -1;
    prot_settimeout(ret->in, config_getduration(IMAPOPT_CLIENT_TIMEOUT, 's'));
    prot_setflushonread(ret->in, ret->out);
    ret->prot = prot;

    /* use literal+ to send literals */
    prot_setisclient(ret->in, 1);
    prot_setisclient(ret->out, 1);

    /* Start TLS if required */
    if (do_tls) {
        r = backend_starttls(ret, NULL, NULL, NULL);
        if (r) goto error;
    }

    /* Login to the server. Not really, but let's handshake. */
    if (prot->type == TYPE_SPEC)
        r = prot->u.spec.login(ret, NULL, NULL, NULL, /*noauth*/1);
    else
        r = backend_login(ret, NULL, NULL, NULL, /*noauth*/1);

    if (r) goto error;

    /* Set up logging */
    if (logfd >= 0) {
        prot_setlog(ret->in, logfd);
        prot_setlog(ret->out, logfd);
    }
    else prot_settimeout(ret->in, 0);

    return ret;

error:
    backend_disconnect(ret);
    ret->sock = -1;
    free(ret);
    return NULL;
}

EXPORTED struct backend *backend_connect(struct backend *ret_backend, const char *server,
                                struct protocol_t *prot, const char *userid,
                                sasl_callback_t *cb, const char **auth_status,
                                int logfd)

{
    /* need to (re)establish connection to server or create one */
    int sock = -1;
    int r;
    int err = -1;
    int do_client_bind = 0;
    int do_tls = 0;
    int noauth = 0;
    struct addrinfo hints, *res0 = NULL, *res;
    struct sockaddr_un sunsock;
    struct backend *ret;

    if (!ret_backend) {
        ret = xzmalloc(sizeof(struct backend));
        strlcpy(ret->hostname, server, sizeof(ret->hostname));
        ret->timeout = NULL;
    }
    else
        ret = ret_backend;

    if (server[0] == '/') { /* unix socket */
        res0 = &hints;
        memset(res0, 0, sizeof(struct addrinfo));
        res0->ai_family = PF_UNIX;
        res0->ai_socktype = SOCK_STREAM;

        res0->ai_addr = (struct sockaddr *) &sunsock;
        res0->ai_addrlen = sizeof(sunsock.sun_family) + strlen(server) + 1;
#ifdef SIN6_LEN
        res0->ai_addrlen += sizeof(sunsock.sun_len);
        sunsock.sun_len = res0->ai_addrlen;
#endif
        sunsock.sun_family = AF_UNIX;
        strlcpy(sunsock.sun_path, server, sizeof(sunsock.sun_path));

        if (!strcmp(prot->sasl_service, "lmtp") ||
            !strcmp(prot->sasl_service, "csync")) {
            noauth = 1;
        }
    }
    else { /* inet socket */
        char host[1024], *p;
        const char *service = prot->service;

        /* Parse server string for possible port and options */
        strlcpy(host, server, sizeof(host));
        if ((p = strchr(host, ':'))) {
            *p++ = '\0';
            service = p;

            if ((p = strchr(service, '/'))) {
                tok_t tok;
                const char *opt;

                *p++ = '\0';
                tok_initm(&tok, p, "/", 0);
                while ((opt = tok_next(&tok))) {
                    if (!strcmp(opt, "tls")) do_tls = 1;
                    else if (!strcmp(opt, "noauth")) noauth = 1;
                }
                tok_fini(&tok);
            }
        }

        memset(&hints, 0, sizeof(hints));
        hints.ai_family = PF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        err = getaddrinfo(host, service, &hints, &res0);
        if (err) {
            syslog(LOG_ERR, "getaddrinfo(%s) failed: %s",
                   server, gai_strerror(err));
            goto error;
        }

        do_client_bind = config_getswitch(IMAPOPT_CLIENT_BIND);
    }

    for (res = res0; res; res = res->ai_next) {
        sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if (sock < 0)
            continue;

        if (do_client_bind) {
            r = backend_client_bind(sock, res);
            if (r) {
                close(sock);
                sock = -1;
                continue;
            }
        }

        /* Do a non-blocking connect() */
        nonblock(sock, 1);
        if (!connect(sock, res->ai_addr, res->ai_addrlen)) {
            /* connect() succeeded immediately */
            break;
        }
        else if (errno == EINPROGRESS) {
            /* connect() in progress */
            int n;
            fd_set wfds, rfds;
            time_t now = time(NULL);
            time_t timeout = now + config_getduration(IMAPOPT_CLIENT_TIMEOUT, 's');
            struct timeval waitfor;

            /* select() socket for writing until we succeed, fail, or timeout */
            do {
                FD_ZERO(&wfds);
                FD_SET(sock, &wfds);
                rfds = wfds;
                waitfor.tv_sec = timeout - now;
                waitfor.tv_usec = 0;

                n = select(sock + 1, &rfds, &wfds, NULL, &waitfor);
                now = time(NULL);

                /* Retry select() if interrupted */
            } while (n < 0 && errno == EINTR && now < timeout);

            if (!n) {
                /* select() timed out */
                errno = ETIMEDOUT;
            }
            else if (FD_ISSET(sock, &rfds) || FD_ISSET(sock, &wfds)) {
                /* Socket is ready for I/O - get SO_ERROR to determine status */
                socklen_t errlen = sizeof(err);

                if (!getsockopt(sock, SOL_SOCKET, SO_ERROR, &err, &errlen) &&
                    !(errno = err)) {
                    /* connect() succeeded */
                    break;
                }
            }
        }

        close(sock);
        sock = -1;
    }

    if (sock < 0) {
        if (res0 != &hints) freeaddrinfo(res0);
        syslog(LOG_ERR, "connect(%s) failed: %m", server);
        goto error;
    }

    /* Reset socket to blocking */
    nonblock(sock, 0);

    memcpy(&ret->addr, res->ai_addr, res->ai_addrlen);
    if (res0 != &hints)
        freeaddrinfo(res0);

    ret->in = prot_new(sock, 0);
    ret->out = prot_new(sock, 1);
    ret->sock = sock;
    prot_settimeout(ret->in, config_getduration(IMAPOPT_CLIENT_TIMEOUT, 's'));
    prot_setflushonread(ret->in, ret->out);
    ret->prot = prot;

    /* use literal+ to send literals */
    prot_setisclient(ret->in, 1);
    prot_setisclient(ret->out, 1);

    /* Start TLS if required */
    if (do_tls) {
        r = backend_starttls(ret, NULL, NULL, NULL);
        if (r) goto error;
    }

    /* Login to the server */
    if (prot->type == TYPE_SPEC)
        r = prot->u.spec.login(ret, userid, cb, auth_status, noauth);
    else
        r = backend_login(ret, userid, cb, auth_status, noauth);

    if (r) goto error;

    if (logfd >= 0) {
        prot_setlog(ret->in, logfd);
        prot_setlog(ret->out, logfd);
    }
    else prot_settimeout(ret->in, 0);

    return ret;

error:
    if (sock >= 0) backend_disconnect(ret);
    ret->sock = -1;
    if (!ret_backend) free(ret);
    return NULL;
}

EXPORTED int backend_ping(struct backend *s, const char *userid)
{
    char buf[1024];
    struct simple_cmd_t *ping_cmd;

    if (!s) return 0;
    if (s->sock == -1) return -1; /* Disconnected Socket */

    if (s->prot->type == TYPE_SPEC) return s->prot->u.spec.ping(s, userid);

    ping_cmd = &s->prot->u.std.ping_cmd;
    if (!ping_cmd->cmd) return 0;

    prot_printf(s->out, "%s\r\n", ping_cmd->cmd);
    prot_flush(s->out);

    for (;;) {
        if (!prot_fgets(buf, sizeof(buf), s->in)) {
            /* connection closed? */
            return -1;
        } else if (ping_cmd->unsol &&
                   !strncmp(ping_cmd->unsol, buf,
                            strlen(ping_cmd->unsol))) {
            /* unsolicited response */
            continue;
        } else {
            /* success/fail response */
            return strncmp(ping_cmd->ok, buf, strlen(ping_cmd->ok));
        }
    }
}

EXPORTED void backend_disconnect(struct backend *s)
{
    if (!s) return;

    if (!prot_error(s->in)) {
       if (s->prot->type == TYPE_SPEC) s->prot->u.spec.logout(s);
       else {
           struct simple_cmd_t *logout_cmd = &s->prot->u.std.logout_cmd;

           if (logout_cmd->cmd) {
                prot_printf(s->out, "%s\r\n", logout_cmd->cmd);
                prot_flush(s->out);

                for (;;) {
                    char buf[1024];

                    if (!prot_fgets(buf, sizeof(buf), s->in)) {
                        /* connection closed? */
                        break;
                    } else if (logout_cmd->unsol &&
                               !strncmp(logout_cmd->unsol, buf,
                                        strlen(logout_cmd->unsol))) {
                        /* unsolicited response */
                        continue;
                    } else {
                        /* success/fail response -- don't care either way */
                        break;
                    }
                }
            }
        }

        /* Flush the incoming buffer */
        prot_NONBLOCK(s->in);
        prot_fill(s->in);
    }

#ifdef HAVE_SSL
    /* Free tlsconn */
    if (s->tlsconn) {
        tls_reset_servertls(&s->tlsconn);
        s->tlsconn = NULL;
    }
#endif /* HAVE_SSL */

    /* close/free socket & prot layer */
    if (s->sock != -1) cyrus_close_sock(s->sock);
    s->sock = -1;

    prot_free(s->in);
    prot_free(s->out);
    s->in = s->out = NULL;

    /* Free saslconn */
    if (s->saslconn) {
        sasl_dispose(&(s->saslconn));
        s->saslconn = NULL;
    }

    /* Free any SASL callbacks */
    if (s->sasl_cb) {
        free_callbacks(s->sasl_cb);
        s->sasl_cb = NULL;
    }



    /* free last_result buffer */
    buf_free(&s->last_result);

    forget_capabilities(s);
}

EXPORTED int backend_version(struct backend *be)
{
    const char *minor;

    /* IMPORTANT:
     *
     * When adding checks for new versions, you must also backport these
     * checks to previous versions (especially 2.4 and 2.5).
     *
     * Otherwise, old versions will be unable to recognise the new version,
     * assume it is ancient, and downgrade the index to the oldest version
     * supported (version 6, prior to v2.3).
     *
     * In 3.2 and earlier, this function lives in imapd.c
     */

    /* It's like looking in the mirror and not suffering from schizophrenia */
    if (strstr(be->banner, CYRUS_VERSION)) {
        return MAILBOX_MINOR_VERSION;
    }

    /* unstable 3.5 series ranges from 17..?? */
    if (strstr(be->banner, "Cyrus IMAP 3.5")) {
        /* all versions of 3.5 support at least this version */
        return 17;
    }

    /* version 3.4 is 17 */
    if (strstr(be->banner, "Cyrus IMAP 3.4")) {
        return 17;
    }

    /* unstable 3.3 series is 17 */
    if (strstr(be->banner, "Cyrus IMAP 3.3")) {
        /* all versions of 3.3 support at least this version */
        return 17;
    }

    /* version 3.2 is 16 */
    if (strstr(be->banner, "Cyrus IMAP 3.2")) {
        return 16;
    }

    /* unstable 3.1 series ranges from 13..16 */
    if (strstr(be->banner, "Cyrus IMAP 3.1")) {
        /* all versions of 3.1 support at least this version */
        return 13;
    }

    /* version 3.0 is 13 */
    if (strstr(be->banner, "Cyrus IMAP 3.0")) {
        return 13;
    }

    /* version 2.5 is 13 */
    if (strstr(be->banner, "Cyrus IMAP 2.5.")
     || strstr(be->banner, "Cyrus IMAP Murder 2.5.")
     || strstr(be->banner, "git2.5.")) {
        return 13;
    }

    /* version 2.4 was all 12 */
    if (strstr(be->banner, "v2.4.") || strstr(be->banner, "git2.4.")) {
        return 12;
    }

    minor = strstr(be->banner, "v2.3.");
    if (!minor) goto unrecognised;
    minor += strlen("v2.3.");

    /* at least version 2.3.10 */
    if (minor[1] != ' ') {
        return 10;
    }
    /* single digit version, figure out which */
    switch (minor[0]) {
    case '0':
    case '1':
    case '2':
    case '3':
        return 7;
        break;

    case '4':
    case '5':
    case '6':
        return 8;
        break;

    case '7':
    case '8':
    case '9':
        return 9;
        break;
    }

unrecognised:
    /* fallthrough, shouldn't happen */
    syslog(LOG_WARNING, "%s: did not recognise remote Cyrus version from "
                        "banner \"%s\".  Assuming index version 6!",
                        __func__, be->banner);
    return 6;
}
