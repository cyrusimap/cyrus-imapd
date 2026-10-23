/* isieve.c */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <sasl/saslutil.h>
#include <stdbool.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <string.h>
#include <unistd.h>

#include "iptostring.h"
#include "util.h"
#include "xmalloc.h"
#include "perl/sieve/lib/isieve.h"
#include "perl/sieve/lib/lex.h"
#include "perl/sieve/lib/request.h"

struct iseive_s {
    char *serverFQDN;
    int port;

    int sock;

    sasl_conn_t *conn;
    sasl_callback_t *callbacks;

    char *refer_authinfo;
    sasl_callback_t *refer_callbacks;

    int version;
    bool starttls_offered;

    SSL_CTX *tls_ctx;
    SSL *tls_conn;
    sasl_ssf_t tls_ssf;
    /* kept so that referrals also use TLS */
    bool usetls;
    char *cafile;
    char *capath;

    struct protstream *pin;
    struct protstream *pout;
};

void fillin_interactions(sasl_interact_t *tlist);

/* we need this separate from the free() call so that we can reuse
 * the same memory for referrals */
static void sieve_dispose(isieve_t *obj)
{
    if(!obj) return;
    sasl_dispose(&obj->conn);
    free(obj->serverFQDN);

    free(obj->refer_authinfo);
    free(obj->refer_callbacks);

    prot_free(obj->pin);
    prot_free(obj->pout);

    SSL_free(obj->tls_conn);
    SSL_CTX_free(obj->tls_ctx);
    free(obj->cafile);
    free(obj->capath);

    close(obj->sock);
}

void sieve_free_net(isieve_t *obj)
{
    sieve_dispose(obj);
    free(obj);
}

/* initialize the network */
int init_net(char *serverFQDN, int port, isieve_t **obj)
{
  struct addrinfo hints, *res0, *res;
  int err;
  char portstr[6];
  int sock = -1;

  snprintf(portstr, sizeof(portstr), "%d", port);
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = PF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  if ((err = getaddrinfo(serverFQDN, portstr, &hints, &res0)) != 0) {
      fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(err));
      return -1;
  }

  for (res = res0; res; res = res->ai_next) {
      sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
      if (sock < 0)
          continue;
      if (connect(sock, res->ai_addr, res->ai_addrlen) >= 0)
          break;
      close(sock);
      sock = -1;
  }

  freeaddrinfo(res0);
  if (sock < 0) {
    perror("connect");
    return -1;
  }

  *obj = (isieve_t *) xzmalloc(sizeof(isieve_t));

  (*obj)->sock = sock;
  (*obj)->serverFQDN = xstrdup(serverFQDN);
  (*obj)->port = port;

  /* set up the prot layer */
  (*obj)->pin = prot_new(sock, 0);
  (*obj)->pout = prot_new(sock, 1);

  return 0;
}

static sasl_security_properties_t *make_secprops(int min,int max)
{
  sasl_security_properties_t *ret=(sasl_security_properties_t *)
    xmalloc(sizeof(sasl_security_properties_t));

  ret->maxbufsize=1024;
  ret->min_ssf=min;
  ret->max_ssf=max;

  /* should make this configurable */
  ret->security_flags=SASL_SEC_NOANONYMOUS;
  ret->property_names=NULL;
  ret->property_values=NULL;

  return ret;
}

/*
 * Initialize SASL and set necessary options
 */
int init_sasl(isieve_t *obj,
              int ssf,
              sasl_callback_t *callbacks)
{
  static int sasl_started = 0;
  int saslresult = SASL_OK;
  sasl_security_properties_t *secprops=NULL;
  socklen_t addrsize=sizeof(struct sockaddr_storage);
  struct sockaddr_storage saddr_l, saddr_r;
  char localip[60], remoteip[60];

  /* attempt to start sasl */
  if(!sasl_started) {
      saslresult=sasl_client_init(NULL);
      obj->conn = NULL;
      sasl_started = 1;
  }

  /* Save the callbacks array */
  obj->callbacks = callbacks;

  if (saslresult!=SASL_OK) return -1;

  addrsize=sizeof(struct sockaddr_storage);
  if (getpeername(obj->sock,(struct sockaddr *)&saddr_r,&addrsize)!=0)
      return -1;

  addrsize=sizeof(struct sockaddr_storage);
  if (getsockname(obj->sock,(struct sockaddr *)&saddr_l,&addrsize)!=0)
      return -1;

  if (iptostring((struct sockaddr *)&saddr_r, addrsize, remoteip, 60))
      return -1;

  if (iptostring((struct sockaddr *)&saddr_l, addrsize, localip, 60))
      return -1;

  if(obj->conn) sasl_dispose(&obj->conn);

  /* client new connection */
  saslresult=sasl_client_new(SIEVE_SERVICE_NAME,
                             obj->serverFQDN,
                             localip, remoteip,
                             callbacks,
                             SASL_SUCCESS_DATA,
                             &obj->conn);

  if (saslresult!=SASL_OK) return -1;

  if (obj->tls_ssf) {
      sasl_setprop(obj->conn, SASL_SSF_EXTERNAL, &obj->tls_ssf);
  }

  /* create a security structure and give it to sasl */
  secprops = make_secprops(0, ssf);
  if (secprops != NULL)
  {
    sasl_setprop(obj->conn, SASL_SEC_PROPS, secprops);
    free(secprops);
  }

  return 0;
}

char *read_capability(isieve_t *obj, char **errstr)
{
  lexstate_t state;
  char *cap = NULL;

  obj->version = NEW_VERSION;
  obj->starttls_offered = false;

  while (yylex(&state,obj->pin)==STRING)
  {
      char *attr = state.str;
      char *val;

      val = NULL;

      if (yylex(&state,obj->pin)==' ')
      {
          if (yylex(&state,obj->pin)!=STRING)
          {
              parseerror(obj->pin, "STRING", errstr);
              free(attr);
              free(cap);
              return NULL;
          }
          val = state.str;
          if (yylex(&state,obj->pin)!=EOL)
          {
              parseerror(obj->pin, "EOL1", errstr);
              free(attr);
              free(val);
              free(cap);
              return NULL;
          }
      }

      if (strcasecmp(attr,"SASL")==0)
      {
        free(cap);
        cap = xstrdupnull(val);
      } else if (strcasecmp(attr,"SIEVE")==0) {

      } else if (strcasecmp(attr,"IMPLEMENTATION")==0) {

      } else if (strcasecmp(attr,"STARTTLS")==0) {
          obj->starttls_offered = true;
      } else if (val && strncmp(val,"SASL=",5)==0) {
          obj->version = OLD_VERSION;
          free(cap);
          cap = xstrdup(val+5);
          free(attr);
          free(val);
          return cap;
      } else {
          /* unknown capability */
      }
      free(attr);
      free(val);
  }

  if (yylex(&state,obj->pin)!=EOL)
  {
      parseerror(obj->pin, "EOL2", errstr);
      free(cap);
      return NULL;
  }

  return cap;
}

int isieve_starttls(isieve_t *obj,
                    const char *cafile,
                    const char *capath,
                    char **mechlist,
                    char **errstr)
{
    lexstate_t state;
    char *refer_to = NULL, *resp = NULL;
    struct in6_addr addr;
    char errbuf[256];
    long verify;
    unsigned long err;

    if (!obj->starttls_offered) {
        *errstr = xstrdup("server does not offer STARTTLS");
        return -1;
    }

    prot_printf(obj->pout, "STARTTLS\r\n");
    prot_flush(obj->pout);
    if (handle_response(yylex(&state, obj->pin),
                        obj->version,
                        obj->pin,
                        &refer_to,
                        &resp))
    {
        *errstr =
            strconcat("STARTTLS failed: ", resp ? resp : "", (char *) NULL);
        free(resp);
        free(refer_to);
        return -1;
    }
    free(refer_to);

    /* anything after the OK was sent before TLS, so can't be trusted */
    if (obj->pin->cnt) {
        *errstr = xstrdup("STARTTLS failed: data received before TLS");
        return -1;
    }

    ERR_clear_error();
    obj->tls_ctx = SSL_CTX_new(TLS_client_method());
    if (!obj->tls_ctx
        || !SSL_CTX_set_min_proto_version(obj->tls_ctx, TLS1_2_VERSION)
        || !SSL_CTX_set_default_verify_paths(obj->tls_ctx))
    {
        goto tlserr;
    }
    if ((cafile || capath)
        && !SSL_CTX_load_verify_locations(obj->tls_ctx, cafile, capath))
    {
        goto tlserr;
    }
    SSL_CTX_set_verify(obj->tls_ctx, SSL_VERIFY_PEER, NULL);

    obj->tls_conn = SSL_new(obj->tls_ctx);
    if (!obj->tls_conn || !SSL_set_fd(obj->tls_conn, obj->sock)) {
        goto tlserr;
    }
    /* an address literal is checked against IP SANs and gets no SNI */
    if (inet_pton(AF_INET, obj->serverFQDN, &addr) == 1
        || inet_pton(AF_INET6, obj->serverFQDN, &addr) == 1)
    {
        if (!X509_VERIFY_PARAM_set1_ip_asc(SSL_get0_param(obj->tls_conn),
                                           obj->serverFQDN))
        {
            goto tlserr;
        }
    }
    else if (!SSL_set1_host(obj->tls_conn, obj->serverFQDN)
             || !SSL_set_tlsext_host_name(obj->tls_conn, obj->serverFQDN))
    {
        goto tlserr;
    }
    if (SSL_connect(obj->tls_conn) <= 0) {
        goto tlserr;
    }

    obj->tls_ssf = SSL_get_cipher_bits(obj->tls_conn, NULL);
    prot_settls(obj->pin, obj->tls_conn);
    prot_settls(obj->pout, obj->tls_conn);

    obj->usetls = true;
    if (obj->cafile != cafile) {
        free(obj->cafile);
        obj->cafile = xstrdupnull(cafile);
    }
    if (obj->capath != capath) {
        free(obj->capath);
        obj->capath = xstrdupnull(capath);
    }

    /* the server sends its capabilities again once TLS is up */
    char *caperr = NULL;
    *mechlist = read_capability(obj, &caperr);
    if (caperr) {
        *errstr = caperr;
        return -1;
    }
    return 0;

tlserr:
    verify = obj->tls_conn ? SSL_get_verify_result(obj->tls_conn) : X509_V_OK;
    if (verify != X509_V_OK) {
        *errstr = strconcat("TLS negotiation failed: ",
                            X509_verify_cert_error_string(verify),
                            (char *) NULL);
    }
    else if ((err = ERR_get_error())) {
        ERR_error_string_n(err, errbuf, sizeof(errbuf));
        *errstr = strconcat("TLS negotiation failed: ", errbuf, (char *) NULL);
    }
    else {
        *errstr = xstrdup("TLS negotiation failed: connection closed");
    }
    return -1;
}

int detect_mitm(isieve_t *obj, char *mechlist, char **errstr)
{
    char *new_mechlist, *caperr = NULL;
    int ch;

    /* wait and probe for possible automatic capability response */
    usleep(250000);
    prot_NONBLOCK(obj->pin);
    if ((ch = prot_getc(obj->pin)) != EOF) {
        /* automatic capability response */
        prot_ungetc(ch, obj->pin);
    } else {
        /* manually ask for capabilities */
        prot_printf(obj->pout, "CAPABILITY\r\n");
        prot_flush(obj->pout);
    }
    prot_BLOCK(obj->pin);

    new_mechlist = read_capability(obj, &caperr);
    if (caperr) {
        *errstr = caperr;
        return -1;
    }
    /* if the server still advertises SASL mechs, compare lists */
    if (new_mechlist && strcmp(new_mechlist, mechlist)) {
        free(new_mechlist);
        *errstr = xstrdup("possible MITM attack: "
                          "list of available SASL mechanisms changed");
        return -1;
    }
    free(new_mechlist);
    return 0;
}

static int getauthline(isieve_t *obj, char **line, unsigned int *linelen,
                       char **errstrp)
{
  lexstate_t state;
  int res;
  size_t len;
  char *errstr = NULL;
  char *last_send;
  int r;

  /* now let's see what the server said */
  res=yylex(&state, obj->pin);
  *line = NULL;
  if (res!=STRING)
  {
      r = handle_response(res, obj->version,
                          obj->pin, &last_send, &errstr);

      if (res == TOKEN_OK && r == 0) {
          /* Was there a last send from the server? */
          if(last_send) {
              /* it's base64 encoded */
              int last_send_len = strlen(last_send);

              len = last_send_len*2+1;
              *line = xmalloc(len);

              r = sasl_decode64(last_send, last_send_len,
                                *line, len, linelen);

              free(last_send);
              if (r != SASL_OK)
                return STAT_NO;
          }
          return STAT_OK;
      } else { /* server said no or bye*/
          /* XXX handle referrals */
          free(last_send);
          *errstrp = errstr;
          return STAT_NO;
      }
  }

  len = strlen(state.str)*2+1;
  *line=(char *) xmalloc(len);

  r = sasl_decode64(state.str, strlen(state.str),
                    *line, len, linelen);
  if (r != SASL_OK)
      return STAT_NO;

  if (yylex(&state, obj->pin)!=EOL)
      return STAT_NO;

  return STAT_CONT;
}


int auth_sasl(char *mechlist, isieve_t *obj, const char **mechusing,
              sasl_ssf_t *ssf, char **errstr)
{
  sasl_interact_t *client_interact=NULL;
  int saslresult=SASL_INTERACT;
  const char *out = NULL;
  unsigned int outlen = 0;
  char *in;
  unsigned int inlen;
  char inbase64[2048];
  unsigned int inbase64len;

  imt_stat status = STAT_CONT;

  if(!mechlist || !obj || !mechusing) return -1;

  /* call sasl client start */
  while (saslresult==SASL_INTERACT)
  {
    saslresult=sasl_client_start(obj->conn, mechlist,
                                 &client_interact,
                                 &out, &outlen,
                                 mechusing);
    if (saslresult==SASL_INTERACT)
      fillin_interactions(client_interact); /* fill in prompts */
  }

  if ((saslresult!=SASL_OK) && (saslresult!=SASL_CONTINUE)) return saslresult;

  if (out!=NULL)
  {
    prot_printf(obj->pout,"AUTHENTICATE \"%s\" ",*mechusing);

    sasl_encode64(out, outlen,
                  inbase64, sizeof(inbase64), &inbase64len);

    prot_printf(obj->pout, "{%d+}\r\n",inbase64len);
    prot_write(obj->pout,inbase64,inbase64len);
    prot_printf(obj->pout,"\r\n");
  } else {
    prot_printf(obj->pout,"AUTHENTICATE \"%s\"\r\n",*mechusing);
  }
  prot_flush(obj->pout);

  inlen = 0;

  /* get reply */
  status=getauthline(obj,&in,&inlen, errstr);

  while (status==STAT_CONT)
  {
    saslresult=SASL_INTERACT;
    while (saslresult==SASL_INTERACT)
    {
      saslresult=sasl_client_step(obj->conn,
                                  in,
                                  inlen,
                                  &client_interact,
                                  &out,&outlen);

      if (saslresult==SASL_INTERACT)
        fillin_interactions(client_interact); /* fill in prompts */
    }

    /* check if sasl succeeded */
    if (saslresult<SASL_OK)
    {
        /* send cancel notice */
        prot_printf(obj->pout, "*\r\n");
        prot_flush(obj->pout);

        /* eat the auth line that confirms that we canceled */
        if(getauthline(obj,&in,&inlen,errstr) != STAT_NO) {
            *errstr = xstrdup("protocol error");
        } else {
            *errstr = xstrdup(sasl_errstring(saslresult,NULL,NULL));
        }

        return saslresult;
    }

    /* send to server */

    sasl_encode64(out, outlen,
                  inbase64, sizeof(inbase64), &inbase64len);

    prot_printf(obj->pout, "{%d+}\r\n",inbase64len);
    prot_flush(obj->pout);
    prot_write(obj->pout,inbase64,inbase64len);
    prot_flush(obj->pout);
    prot_printf(obj->pout,"\r\n");
    prot_flush(obj->pout);

    /* get reply */
    status=getauthline(obj,&in,&inlen, errstr);
  }

  if(status == STAT_OK) {
      /* do we have a last send? */
      if(in) {
          saslresult=sasl_client_step(obj->conn,
                                      in,
                                      inlen,
                                      &client_interact,
                                      &out, &outlen);

          if(saslresult != SASL_OK)
              return -1;
      }

      if (ssf) {
          const void *ssfp;

          saslresult = sasl_getprop(obj->conn, SASL_SSF, &ssfp);
          if(saslresult != SASL_OK) return -1;

          *ssf = *((sasl_ssf_t *) ssfp);
      }

      /* turn on layer if need be */
      prot_setsasl(obj->pin,  obj->conn);
      prot_setsasl(obj->pout, obj->conn);

      /* There wasn't a last send, or we are already OK */
      return 0;
  } else {
      /* Error */
      return -1;
  }
}

static int refer_simple_cb(void *context, int id, const char **result,
                            unsigned int *len)
{
    if (!result) {
        return SASL_BADPARAM;
    }

    switch (id) {
    case SASL_CB_USER:
        *result = (char *) context;
        break;
    case SASL_CB_AUTHNAME:
        *result = (char *) context;
        break;
    default:
        return SASL_BADPARAM;
    }
    if (len) {
        *len = *result ? strlen(*result) : 0;
    }

    return SASL_OK;
}

static int do_referral(isieve_t *obj, char *refer_to)
{
    int ret;
    struct servent *serv;
    isieve_t *obj_new = NULL;
    char *mechlist = NULL;
    int port;
    char *errstr = NULL;
    const char *mtried;
    const char *scheme = "sieve://";
    char *host, *p;
    sasl_callback_t *callbacks;
    char *refer_authinfo = NULL;
    sasl_callback_t *refer_callbacks = NULL;
    sasl_ssf_t ssf;

    /* check scheme */
    if (strncasecmp(refer_to, scheme, strlen(scheme)))
        return STAT_NO;

    /* get host */
    if ((host = strrchr(refer_to, '@'))) {
        char *authid, *userid;
        int n;

        *host++ = '\0';

        /* get authid - make a copy so it persists for the callbacks */
        authid = refer_authinfo = xstrdup(refer_to + strlen(scheme));

        /* get userid */
        if ((userid = strrchr(authid, ';')))
            *userid++ = '\0';

        /* count the callbacks */
        for (n = 0; obj->callbacks[n++].id != SASL_CB_LIST_END;);

        /* copy the callbacks, substituting some of our own */
        callbacks = refer_callbacks = xmalloc(n*sizeof(sasl_callback_t));

        while (--n >= 0) {
            callbacks[n].id = obj->callbacks[n].id;

            switch (callbacks[n].id) {
            case SASL_CB_USER:
                callbacks[n].proc = (int (*)()) &refer_simple_cb;
                callbacks[n].context = userid ? userid : authid;
                break;
            case SASL_CB_AUTHNAME:
                callbacks[n].proc = (int (*)()) &refer_simple_cb;
                callbacks[n].context = authid;
                break;
            default:
                callbacks[n].proc = obj->callbacks[n].proc;
                callbacks[n].context = obj->callbacks[n].context;
                break;
            }
        }
    }
    else {
        host = refer_to + strlen(scheme);
        callbacks = obj->callbacks;
    }

    /* get port */
    p = host;
    if (*host == '[') {
        if ((p = strrchr(host + 1, ']')) != NULL) {
            *p++ = '\0';
            host++;                     /* skip first bracket */
        } else
            p = host;
    }
    if ((p = strchr(p, ':'))) {
        *p++ = '\0';
        port = atoi(p);
    } else {
        serv = getservbyname("sieve", "tcp");
        if (serv == NULL) {
            port = 4190;
        } else {
            port = ntohs(serv->s_port);
        }
    }

    ret = init_net(host, port, &obj_new);
    if (ret) {
        goto fail;
    }

    /* Start up SASL */
    ret = init_sasl(obj_new, 128, callbacks);
    if (ret) {
        goto fail;
    }

    mechlist = read_capability(obj_new, &errstr);
    if (errstr) {
        free(errstr);
        goto fail;
    }

    if (obj->usetls) {
        free(mechlist);
        mechlist = NULL;
        if (isieve_starttls(obj_new,
                            obj->cafile,
                            obj->capath,
                            &mechlist,
                            &errstr))
        {
            free(errstr);
            goto fail;
        }
        ret = init_sasl(obj_new, 128, callbacks);
        if (ret) {
            goto fail;
        }
    }

    /* Authenticate */

    do {
        mtried = NULL;
        ret = auth_sasl(mechlist, obj_new, &mtried, &ssf, &errstr);
        if (errstr) {
            free(errstr);
            errstr = NULL;
        }
        if(ret) init_sasl(obj_new, 128, callbacks);

        if(mtried) {
            char *newlist = (char*) xmalloc(strlen(mechlist)+1);
            char *mtr = xstrdup(mtried);
            char *tmp;

            ucase(mtr);
            tmp = strstr(mechlist,mtr);
            if (tmp) {
                *tmp = '\0';
                strcpy(newlist, mechlist);
                tmp++;
                tmp = strchr(tmp, ' ');
                if (tmp) {
                    strcat(newlist,tmp);
                }
            }

            free(mtr);
            free(mechlist);
            mechlist = newlist;
        }
    } while(ret && mtried);

    if (ret) {
        goto fail;
    }

    if (ssf) {
        /* SASL security layer negotiated --
           check if SASL mech list changed */
        if (detect_mitm(obj_new, mechlist, &errstr)) {
            free(errstr);
            goto fail;
        }
    }
    free(mechlist);

    /* the new connection's SASL context points into these */
    if (refer_callbacks) {
        obj_new->refer_authinfo = refer_authinfo;
        obj_new->refer_callbacks = refer_callbacks;
    }
    else {
        obj_new->refer_authinfo = obj->refer_authinfo;
        obj_new->refer_callbacks = obj->refer_callbacks;
        obj->refer_authinfo = NULL;
        obj->refer_callbacks = NULL;
    }

    /* free old isieve_t */
    sieve_dispose(obj);

    /* Copy new isieve_t into memory used by old object */
    memcpy(obj,obj_new,sizeof(isieve_t));
    free(obj_new);

    /* Destroy the string that was allocated to save the destination server */
    free(refer_to);

    return STAT_OK;

fail:
    free(mechlist);
    sieve_free_net(obj_new);
    free(refer_authinfo);
    free(refer_callbacks);
    return STAT_NO;
}

int isieve_logout(isieve_t **obj)
{
    prot_printf((*obj)->pout, "LOGOUT\r\n");
    prot_flush((*obj)->pout);

    sieve_free_net(*obj);
    *obj = NULL;

    return STAT_OK;
}

int isieve_put_file(isieve_t *obj, char *filename, char *destname,
                    char **errstr)
{
    char *refer_to;
    int ret = installafile(obj->version,
                           obj->pout, obj->pin,
                           filename, destname,
                           &refer_to, errstr);
    if(ret == -2 && refer_to) {
        ret = do_referral(obj, refer_to);
        if(ret == STAT_OK) {
            ret = isieve_put_file(obj, filename, destname, errstr);
        } else {
            *errstr = xstrdup("referral failed");
        }
    }
    return ret;
}

int isieve_put(isieve_t *obj, char *name, char *data, int len, char **errstr)
{
    char *refer_to;
    int ret = installdata(obj->version,
                          obj->pout, obj->pin,
                          name, data, len, &refer_to, errstr);
    if(ret == -2 && refer_to) {
        ret = do_referral(obj, refer_to);
        if(ret == STAT_OK) {
            ret = isieve_put(obj, name, data, len, errstr);
        } else {
            *errstr = xstrdup("referral failed");
        }
    }
    return ret;
}

int isieve_delete(isieve_t *obj, char *name, char **errstr)
{
    char *refer_to;
    int ret = deleteascript(obj->version,
                            obj->pout, obj->pin,
                            name, &refer_to, errstr);
    if(ret == -2 && refer_to) {
        ret = do_referral(obj, refer_to);
        if(ret == STAT_OK) {
            ret = isieve_delete(obj, name, errstr);
        } else {
            *errstr = xstrdup("referral failed");
        }
    }
    return ret;
}

int isieve_list(isieve_t *obj, isieve_listcb_t *cb,void *rock, char **errstr)
{
    char *refer_to;
    int ret = list_wcb(obj->version, obj->pout, obj->pin, cb, rock, &refer_to,
                       errstr);
    if(ret == -2 && refer_to) {
        ret = do_referral(obj, refer_to);
        if(ret == STAT_OK) {
            ret = isieve_list(obj, cb, rock, errstr);
        }
    }
    return ret;
}

int isieve_activate(isieve_t *obj, char *name, char **errstr)
{
    char *refer_to;
    int ret = setscriptactive(obj->version,obj->pout, obj->pin, name,
                              &refer_to, errstr);
    if(ret == -2 && refer_to) {
        ret = do_referral(obj, refer_to);
        if(ret == STAT_OK) {
            ret = isieve_activate(obj, name, errstr);
        } else {
            *errstr = xstrdup("referral failed");
        }
    }
    return ret;
}

int isieve_get(isieve_t *obj,char *name, char **output, char **errstr)
{
    int ret;
    char *refer_to;
    char *mystr = NULL;

    ret = getscriptvalue(obj->version,obj->pout, obj->pin,
                         name, &mystr, &refer_to, errstr);

    if(ret == -2 && *refer_to) {
        ret = do_referral(obj, refer_to);
        if(ret == STAT_OK) {
            ret = isieve_get(obj,name,output,errstr);
            return ret;
        } else {
            *errstr = xstrdup("referral failed");
        }
    }

    *output = mystr;

    return ret;
}
