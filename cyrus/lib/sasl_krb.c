/* sasl_krb.c -- KERBEROS_V4 SASL mechanism common routines
 $Id: sasl_krb.c,v 1.3 1998/05/15 21:53:09 neplokh Exp $
 
 #        Copyright 1998 by Carnegie Mellon University
 #
 #                      All Rights Reserved
 #
 # Permission to use, copy, modify, and distribute this software and its
 # documentation for any purpose and without fee is hereby granted,
 # provided that the above copyright notice appear in all copies and that
 # both that copyright notice and this permission notice appear in
 # supporting documentation, and that the name of CMU not be
 # used in advertising or publicity pertaining to distribution of the
 # software without specific, written prior permission.
 #
 # CMU DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING
 # ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO EVENT SHALL
 # CMU BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR
 # ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
 # WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
 # ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 # SOFTWARE.
 *
 */

#include <stdio.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/param.h>
#include <netinet/in.h>
#include <krb.h>

#include "sasl.h"
#include "sasl_krb_internal.h"

extern char *malloc();

extern char *lcase P((char *str));

/*
 * Free the space used by an opaque state pointer
 */
void
krb_free_state(state)
void *state;
{
    memset((char *)state, 0, sizeof(struct krb_state));
    free((char *) state);
}

/*
 * Query public values of the state pointer after authentiation
 * complete.  Fills in buffers pointed to by the following arguments:
 *
 * user       -- IMAP userid authenticated as
 * protlevel  -- bitmask for selected protection mechanism
 * encodefunc -- if nonzero, protection mechanism function to encode
 *               outgoing data with.
 * decodefunc -- if nonzero, protection mechanism function to decode
 *               incoming data with.
 * maxplain   -- The maximum number of bytes that may be encoded by
 *                the encodefunc at one time
 */
void 
krb_query_state(state, user, protlevel, encodefunc, decodefunc, maxplain)
void *state;
char **user;
int *protlevel;
sasl_encodefunc_t **encodefunc;
sasl_decodefunc_t **decodefunc;
int *maxplain;
{
    struct krb_state *kstate = (struct krb_state *)state;

    *user = kstate->user;
    *protlevel = kstate->protallowed;

    switch (kstate->protallowed) {
    case SASL_PROT_NONE:
	*encodefunc = 0;
	*decodefunc = 0;
	*maxplain = 0;
	return;

    case SASL_PROT_INTEGRITY:
	*encodefunc = krb_en_integrity;
	*decodefunc = krb_de_integrity;
	*maxplain = kstate->maxbufsize - PROTECTION_OVERHEAD;
	return;

#ifndef NOPRIVACY
    case SASL_PROT_PRIVACY:
	*encodefunc = krb_en_privacy;
	*decodefunc = krb_de_privacy;
	*maxplain = kstate->maxbufsize - PROTECTION_OVERHEAD;
	return;
#endif

    default:
	abort();
    }
}

/*
 * Apply integrity protection to the 'inputlen' bytes of data at 'input',
 * using the state in 'state', placing the output data and length in the
 * buffers pointed to by 'output' and 'outputlen' respectively.
 */
const char *
krb_en_integrity(state, input, inputlen, output, outputlen)
void *state;
char *input;
int inputlen;
char *output;
int *outputlen;
{
    struct krb_state *kstate = (struct krb_state *)state;

    *outputlen = krb_mk_safe(input, output, inputlen, kstate->session,
			     &kstate->localaddr, &kstate->remoteaddr);
    return 0;
}

/*
 * Decode integrity protection on the 'inputlen' bytes of data at
 * 'input', using the state in 'state', placing a pointer to the
 * output data and length in the buffers pointed to by 'output' and
 * 'outputlen' respectively.
 */
const char *
krb_de_integrity(state, input, inputlen, output, outputlen)
void *state;
char *input;
int inputlen;
char **output;
int *outputlen;
{
    struct krb_state *kstate = (struct krb_state *)state;
    int code;
    MSG_DAT m_data;

    code = krb_rd_safe(input, inputlen, kstate->session,
		       &kstate->remoteaddr, &kstate->localaddr, &m_data);
    if (code) return krb_err_txt[code];
    if (m_data.time_sec < kstate->prot_time_sec ||
	(m_data.time_sec == kstate->prot_time_sec &&
	 m_data.time_5ms < kstate->prot_time_5ms)) {
	return krb_err_txt[RD_AP_TIME];
    }
    kstate->prot_time_sec = m_data.time_sec;
    kstate->prot_time_5ms = m_data.time_5ms;

    *output = m_data.app_data;
    *outputlen = m_data.app_length;
    return 0;
}

#ifndef NOPRIVACY
/*
 * Apply privacy protection to the 'inputlen' bytes of data at 'input',
 * using the state in 'state', placing the output data and length in the
 * buffers pointed to by 'output' and 'outputlen' respectively.
 */
const char *
krb_en_privacy(state, input, inputlen, output, outputlen)
void *state;
char *input;
int inputlen;
char *output;
int *outputlen;
{
    struct krb_state *kstate = (struct krb_state *)state;

    *outputlen = krb_mk_priv(input, output, inputlen, kstate->schedule,
			     kstate->session, &kstate->localaddr,
			     &kstate->remoteaddr);
    return 0;
}

/*
 * Decode privacy protection on the 'inputlen' bytes of data at
 * 'input', using the state in 'state', placing a pointer to the
 * output data and length in the buffers pointed to by 'output' and
 * 'outputlen' respectively.
 */
const char *
krb_de_privacy(state, input, inputlen, output, outputlen)
void *state;
char *input;
int inputlen;
char **output;
int *outputlen;
{
    struct krb_state *kstate = (struct krb_state *)state;
    int code;
    MSG_DAT m_data;

    code = krb_rd_priv(input, inputlen, kstate->schedule, kstate->session,
		       &kstate->remoteaddr, &kstate->localaddr, &m_data);
    if (code) return krb_err_txt[code];
    if (m_data.time_sec < kstate->prot_time_sec ||
	(m_data.time_sec == kstate->prot_time_sec &&
	 m_data.time_5ms < kstate->prot_time_5ms)) {
	return krb_err_txt[RD_AP_TIME];
    }
    kstate->prot_time_sec = m_data.time_sec;
    kstate->prot_time_5ms = m_data.time_5ms;

    *output = m_data.app_data;
    *outputlen = m_data.app_length;
    return 0;
}
#endif /* !NOPRIVACY */

char *krb_srvtab = "";	/* Srvtab filename */

/*
 * Kerberos set srvtab filename
 * Accepts: name of srvtab file to use in reading authenticators
 */
int kerberos_set_srvtab(fname)
char *fname;
{
    krb_srvtab = fname;
    return 0;
}

/*
 * Kerberos get srvtab filename
 * Returns: name of srvtab file to use in reading authenticators
 */
char *kerberos_get_srvtab()
{
    return krb_srvtab;
}

