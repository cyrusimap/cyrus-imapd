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
