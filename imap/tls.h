/* tls.h - STARTTLS helper functions for imapd
 * Tim Martin
 * 9/21/99
 *
 *  Based upon Lutz Jaenicke's TLS patches for postfix
 */
/***********************************************************
        Copyright 1999 by Carnegie Mellon University

                      All Rights Reserved

Permission to use, copy, modify, and distribute this software and its
documentation for any purpose and without fee is hereby granted,
provided that the above copyright notice appear in all copies and that
both that copyright notice and this permission notice appear in
supporting documentation, and that the name of Carnegie Mellon
University not be used in advertising or publicity pertaining to
distribution of the software without specific, written prior
permission.

CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND
FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE FOR
ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
******************************************************************/

#ifdef HAVE_SSL

#ifndef TLS_H
#define TLS_H

/* init tls */
int     tls_init_serverengine(int verifydepth, /* depth to verify */
			      int askcert,     /* 1 = verify client */
			      int requirecert, /* 1 = another client verify? */
			      char *var_imapd_tls_CAfile,
			      char *var_imapd_tls_CApath,
			      char *var_imapd_tls_cert_file,
			      char *var_imapd_tls_key_file);

/* start tls negotiation */
int tls_start_servertls(int readfd, int writefd, int *layerbits, char **authid);

#endif /* CYRUSTLS_H */



#endif /* HAVE_SSL */
