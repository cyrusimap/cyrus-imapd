.. _compilationerrors:

Compilation errors about kssl.h and krb5.h on Red Hat Linux/Fedora
------------------------------------------------------------------

When trying to compile Cyrus IMAPd on Red Hat Linux or Fedora, you may be encountering errors like these::

    In file included from /usr/include/openssl/ssl.h:179,
                    from prot.h:56,
                    from prot.c:72:
    /usr/include/openssl/kssl.h:72:18: krb5.h: No such file or directory
    In file included from /usr/include/openssl/ssl.h:179,
                    from prot.h:56,
                     from prot.c:72:
    /usr/include/openssl/kssl.h:134: syntax error before "krb5_enctype"
    /usr/include/openssl/kssl.h:136: syntax error before '*' token
    /usr/include/openssl/kssl.h:137: syntax error before '}' token
    /usr/include/openssl/kssl.h:149: syntax error before "kssl_ctx_setstring"
    /usr/include/openssl/kssl.h:149: syntax error before '*' token
    /usr/include/openssl/kssl.h:150: syntax error before '*' token
    /usr/include/openssl/kssl.h:151: syntax error before '*' token
    /usr/include/openssl/kssl.h:151: syntax error before '*' token
    /usr/include/openssl/kssl.h:152: syntax error before '*' token
    /usr/include/openssl/kssl.h:153: syntax error before "kssl_ctx_setprinc"
    /usr/include/openssl/kssl.h:153: syntax error before '*' token
    /usr/include/openssl/kssl.h:155: syntax error before "kssl_cget_tkt"
    /usr/include/openssl/kssl.h:155: syntax error before '*' token
    /usr/include/openssl/kssl.h:157: syntax error before "kssl_sget_tkt"
    /usr/include/openssl/kssl.h:157: syntax error before '*' token
    /usr/include/openssl/kssl.h:159: syntax error before "kssl_ctx_setkey"
    /usr/include/openssl/kssl.h:159: syntax error before '*' token
    /usr/include/openssl/kssl.h:161: syntax error before "context"
    /usr/include/openssl/kssl.h:162: syntax error before
    "kssl_build_principal_2"
    /usr/include/openssl/kssl.h:162: syntax error before "context"
    /usr/include/openssl/kssl.h:165: syntax error before "kssl_validate_times"
    /usr/include/openssl/kssl.h:165: syntax error before "atime"
    /usr/include/openssl/kssl.h:167: syntax error before "kssl_check_authent"
    /usr/include/openssl/kssl.h:167: syntax error before '*' token
    /usr/include/openssl/kssl.h:169: syntax error before "enctype"
    In file included from prot.h:56,
                    from prot.c:72:
    /usr/include/openssl/ssl.h:909: syntax error before "KSSL_CTX"
    /usr/include/openssl/ssl.h:931: syntax error before '}' token
    make[1]: *** [prot.o] Error 1
    make[1]: Leaving directory `/opt/cyrus-imapd-2.2.3/lib'
    make: *** [all] Error 1

The key bit of this error is::

    /usr/include/openssl/kssl.h:72:18: krb5.h: No such file or directory

Essentially, what is happening is that Cyrus is trying to use OpenSSL, and OpenSSL's headers include some Kerberos header files. Red Hat, in their infinite wisdom, chose to place the Kerberos headers outside the normal header search path, despite having built OpenSSL to require the Kerberos headers. As a result, even if your program is not using Kerberos, it may fail to compile if gcc can't find the Kerberos headers.

The solution is to either add the Kerberos headers to gcc's header search path, or prevent OpenSSL from trying to use the Kerberos includes in the first place. To tell OpenSSL you really don't want kerberos, just run::

    export LOCALDEFS="-DOPENSSL_NO_KRB5"

(as suggested by Ken Murchison on info-cyrus) before you run ./configure. Alternately, you can tell gcc where to find the Kerberos includes so that it'll stop complaining::

    export C_INCLUDE_PATH="/usr/kerberos/include"

If neither of these work, make sure you have the Kerberos development libraries installed ( you should have if you have openssl-devel, but one never does know ...). If you run ``rpm -q openssl-devel krb5-devel`` you should get a result like::

    openssl-devel-0.9.7a-23
    krb5-devel-1.3.1-6
