/* tls_th-lock.c */
/* Derived from openssl-0.9.8i/crypto/threads/th-lock.c
 * by Duncan Gibb <duncan.gibb@siriusit.co.uk>
 * 4 November 2008
 */

#include <config.h>
#include <pthread.h>
#include <syslog.h>

#include <openssl/ssl.h>

#include "tls_th-lock.h"

static pthread_mutex_t *lock_cs;
static long *lock_count;

void CRYPTO_thread_setup(void)
{
    int i;

    syslog(LOG_DEBUG, "Setting up pthreads TLS.");

    lock_cs = OPENSSL_malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t));
    lock_count = OPENSSL_malloc(CRYPTO_num_locks() * sizeof(long));

    for (i = 0; i < CRYPTO_num_locks(); i++) {
	lock_count[i]=0;
	pthread_mutex_init(&(lock_cs[i]),NULL);
    }

    CRYPTO_set_id_callback((unsigned long (*)())pthreads_thread_id);
    CRYPTO_set_locking_callback((void (*)())pthreads_locking_callback);
}

void CRYPTO_thread_cleanup(void)
{
    int i;

    CRYPTO_set_locking_callback(NULL);
    for (i = 0; i < CRYPTO_num_locks(); i++) {
	pthread_mutex_destroy(&(lock_cs[i]));
    }

    OPENSSL_free(lock_cs);
    OPENSSL_free(lock_count);
}

void pthreads_locking_callback(int mode, int type,
			       char *file __attribute__((unused)),
			       int line __attribute__((unused)))
{
    if (mode & CRYPTO_LOCK) {
	pthread_mutex_lock(&(lock_cs[type]));
	lock_count[type]++;
    }
    else {
	pthread_mutex_unlock(&(lock_cs[type]));
    }
}

unsigned long pthreads_thread_id(void)
{
    unsigned long ret;

    ret = (unsigned long)pthread_self();
    return(ret);
}

