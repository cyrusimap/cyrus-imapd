/* tls_th-lock.h */
/* Derived from openssl-0.9.8i/crypto/threads/th-lock.c
 * by Duncan Gibb <duncan.gibb@siriusit.co.uk>
 * 4 November 2008
 */

#ifndef INCLUDED_TLS_TH_LOCK_H
#define INCLUDED_TLS_TH_LOCK_H

#ifdef HAVE_SSL

void CRYPTO_thread_setup(void);
void CRYPTO_thread_cleanup(void);
/*
static void pthreads_locking_callback(int mode,int type,char *file,int line);
static unsigned long pthreads_thread_id(void );
*/
void pthreads_locking_callback(int mode,int type,char *file,int line);
unsigned long pthreads_thread_id(void );

#endif /* HAVE_SSL */
#endif /* INCLUDED_TLS_TH_LOCK_H */
