/* sasl_krb.c -- KERBEROS_V4 authentication routines for SASL.
 *
 *	(C) Copyright 1994 by Carnegie Mellon University
 *
 *                      All Rights Reserved
 *
 * Permission to use, copy, modify, distribute, and sell this software
 * and its documentation for any purpose is hereby granted without
 * fee, provided that the above copyright notice appear in all copies
 * and that both that copyright notice and this permission notice
 * appear in supporting documentation, and that the name of Carnegie
 * Mellon University not be used in advertising or publicity
 * pertaining to distribution of the software without specific,
 * written prior permission.  Carnegie Mellon University makes no
 * representations about the suitability of this software for any
 * purpose.  It is provided "as is" without express or implied
 * warranty.
 *
 * CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
 * FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 *
 */

/* Maximum number of bytes of overhead the protection mechanisms use */
#define PROTECTION_OVERHEAD 31

/* Private state used by this mechanism */
struct krb_state {
    /* common */
    char service[MAX_K_NAME_SZ+1];
    int authstepno;
    des_cblock session;	/* Our session key */
    des_key_schedule schedule; /* Schedule for our session key */
    long challenge;
    char user[MAX_K_NAME_SZ+1];
    int protallowed;
    int maxbufsize;
    struct sockaddr_in localaddr, remoteaddr;
    long prot_time_sec;
    char prot_time_5ms;
    /* client */
    char instance[INST_SZ];
    char realm[REALM_SZ];
    /* server */
    int (*authproc)();
    AUTH_DAT kdata;
};

extern void krb_free_state P((void *state));

extern sasl_encodefunc_t krb_en_integrity;
extern sasl_decodefunc_t krb_de_integrity;
#ifndef NOPRIVACY
extern sasl_encodefunc_t krb_en_privacy;
extern sasl_decodefunc_t krb_de_privacy;
#endif

extern void 
krb_query_state P((void *state, char **user, int *protlevel,
			   sasl_encodefunc_t **encodefunc,
			   sasl_decodefunc_t **decodefunc, int *maxplain));

extern char *krb_srvtab;	/* Srvtab filename */

