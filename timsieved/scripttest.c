/* scripttest.c -- test wheather the sieve script is valid
 * Tim Martin
 * 9/21/99
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



#include "codes.h"

#include "sieve_interface.h"

#include "mystring.h"

/* to make larry's stupid functions happy :) */ 
int foo(char *addr, void *ic, void *sc, void *mc)
{
  printf("should never get here\n");
}


sieve_vacation_t vacation = {
    0,				/* min response */
    0,				/* max response */
    &foo,   		/* autorespond() */
    &foo		/* send_response() */
};


/* returns TRUE or FALSE */
int is_script_parsable(string_t *data)
{
  sieve_interp_t *i;
  sieve_script_t *s;
  int fd, res;
  FILE *write_stream;
  FILE *read_stream;
  char *dataptr;
  int lup;
  char tmpname[100];

  
  res = sieve_interp_alloc(&i, &foo);
  if (res != SIEVE_OK) {
    printf("sieve_interp_alloc() returns %d\n", res);
    return TIMSIEVE_FAIL;
  }

  res = sieve_register_redirect(i, &foo);
  if (res != SIEVE_OK) {
    printf("sieve_register_redirect() returns %d\n", res);
    return TIMSIEVE_FAIL;
  }
  res = sieve_register_discard(i, &foo);
  if (res != SIEVE_OK) {
    printf("sieve_register_discard() returns %d\n", res);
    return TIMSIEVE_FAIL;
  }
  res = sieve_register_reject(i, &foo);
  if (res != SIEVE_OK) {
    printf("sieve_register_reject() returns %d\n", res);
    return TIMSIEVE_FAIL;
  }
  res = sieve_register_fileinto(i, &foo);
  if (res != SIEVE_OK) {
    printf("sieve_register_fileinto() returns %d\n", res);
    return TIMSIEVE_FAIL;
  }
  res = sieve_register_keep(i, &foo);
  if (res != SIEVE_OK) {
    printf("sieve_register_keep() returns %d\n", res);
    return TIMSIEVE_FAIL;
  }
  
  res = sieve_register_size(i, &foo);
  if (res != SIEVE_OK) {
    printf("sieve_register_size() returns %d\n", res);
    return TIMSIEVE_FAIL;
  }
  
  res = sieve_register_header(i, &foo);
  if (res != SIEVE_OK) {
    printf("sieve_register_header() returns %d\n", res);
    return TIMSIEVE_FAIL;
  }
  
  res = sieve_register_envelope(i, &foo);
  if (res != SIEVE_OK) {
    printf("sieve_register_envelope() returns %d\n", res);
    return TIMSIEVE_FAIL;
  }
  
  res = sieve_register_vacation(i, &vacation);
  if (res != SIEVE_OK) {
    printf("sieve_register_vacation() returns %d\n", res);
    return TIMSIEVE_FAIL;
  }

  /* this is idiotic. sieve_script_parse takes a FILE*
     we have raw data

     write a file. then open it
  */

  /* make unique string */
  snprintf(tmpname,sizeof(tmpname),"/tmp/script.%d.%d",getpid(), time(NULL));

  write_stream=fopen(tmpname,"w");

  if (write_stream==NULL)
  {
    printf("couldn't open file\n");
    return TIMSIEVE_FAIL;
  }
  
  dataptr=string_DATAPTR(data);

  for (lup=0;lup<= data->len / BLOCKSIZE; lup++)
  {
    int amount=BLOCKSIZE;

    if (lup*BLOCKSIZE+BLOCKSIZE > data->len)
      amount=data->len % BLOCKSIZE;

    fwrite(dataptr, 1, amount, write_stream);

    dataptr+=amount;
  }

  fclose(write_stream);

  read_stream=fopen(tmpname,"r+");

  unlink(tmpname);

  if (read_stream==NULL)
  {
    printf("couldn't open file\n");
    return TIMSIEVE_FAIL;
  }
  

  res = sieve_script_parse(i, read_stream, NULL, &s);
  if (res != SIEVE_OK) {
    free(i);
    return TIMSIEVE_FAIL;
  }

  fclose(read_stream);

  /* free interpreter */
  free(i);

  return TIMSIEVE_OK;
}
