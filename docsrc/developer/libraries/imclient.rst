.. cyrusman:: imclient(3)

.. author: Nic Bernstein (Onlight)

.. _imap-admin-commands-imclient-library:

====================
**imclient** library
====================

Authenticating callback interface to IMAP servers

Synopsis
========

.. parsed-literal::

    #include <cyrus/imclient.h>

    **int imclient_connect(struct imclient \*\***\ *imclient* **, const char \***\ *host* **,
        const char \***\ *port*\ **);**

    **void imclient_close (struct imclient \***\ *imclient*\ **);**
    **void imclient_setflags(struct imclient \***\ *imclient* **, int** *flags*\ **);**
    **void imclient_clearflags (struct imclient \***\ *imclient* **, int** *flags*\ **);**
    **char\* imclient_servername (struct imclient \***\ *imclient*\ **);**
    **void imclient_addcallback (struct imclient \***\ *imclient*\ ,...\ **);**
    **void imclient_send (struct imclient \***\ *imclient*\ **, void (\***\ *finishproc*\ **)(),
        void \***\ *finishrock*\ **, const char \***\ *fmt*\ ,...\ **);**
    **void imclient_getselectinfo (struct imclient \***\ *imclient*\ **, int \*** *fd*\ **,
        int \*** *wanttowrite*\ **);**
    **void imclient_processoneevent (struct imclient \***\ *imclient*\ **);**
    **int imclient_authenticate (struct imclient \***\ *imclient*\ **,
        struct sasl_client \*\***\ *availmech*\ **, const char \***\ *service*\ **,
        const char \***\ *user*\ **, int** *protallowed*\ **);**
    **int imclient_havetls ();**
    **int imclient_starttls (struct imclient \***\ *imclient*\ **, char \***\ *cert_file*\ **,
        char \***\ *key_file*\ **, char \***\ *CAfile*\ **, char \***\ *CApath*\ **);**


Description
===========

The imclient library functions are distributed with Cyrus IMAP.
These functions are used for building IMAP client software. These
functions handle Kerberos authentication and can set callbacks based on the
keyword in untagged replies or based on the command tag at the end of
command replies.

Users must link with the -lcyrus switch, and must supply a function
called *fatal* to be called in case of any error within *libcyrus.la*\ .

All of the **imclient** functions begin with the prefix *imclient* and
take  an  argument of type **struct imclient \*** as the first argument
which is  initialized by **imclient_connect** and freed by
**imclient_close**\ .

See below for a description of each function.

**imclient_connect()**
    Connects the client server to the host. If successful, it returns
    0 and sets the imclient argument to a pointer to an **imclient**
    struct.  The **imclient** struct represents the current connection,
    flags, and callbacks.  On failure, the current **errno** is returned
    if a system call failed, -1 is returned if the host name was not
    found, and -2 is returned if the service name was not found.

**imclient_close()**
    Closes and frees the **imclient** connection.

**imclient_setflags()**
    Sets the flags specified by the *flags* argument on the **imclient**
    connection. Currently the only  flag allowed is
    **IMCLIENT_CONN_NONSYNCLITERAL** (this flag indicates that the
    server supports non-synchronizing literals described by the LITERAL+
    extension).

**imclient_clearflags()**
    Clears the flags specified by the *flags* argument on the
    **imclient** connection.

**imclient_servername()**
    Returns a char * pointer to the name of the server connected to
    by **imclient**.

**imclient_addcallback()**
    Adds an untagged data callback to the **imclient** connection. The
    function **imclient_addcallback** takes callbacks of the type
    **imclient_proc_t** which is defined to be:

        ::

            typedef void imclient_proc_t (struct imclient *imclient, void *rock, struct imclient_reply *reply);

    and **struct imclient_reply \***
    is defined to be:

        ::

            struct imclient_reply {
                char *keyword;
                long msgno;
                char *text;
            };

    After the first argument, *imclient*, there can be zero or more
    instances of the set of *keyword*, *flags*, *proc*, and *rock*,
    each adding or changing a single callback.  Each instance adds or
    changes the callback for *keyword*.  The argument *flags* specifies
    information about the parsing of the untagged data.  *proc* and
    *rock* specify the callback function and rock to invoke when the
    untagged data is received.  *proc* may be a null pointer, in which
    case no function is invoked.  The callback function may not call
    the functions **imclient_close(), imclient_send(), imclient_eof(),
    imclient_processoneevent()**, or **imclient_authenticate()** on the
    connection. The callback function may overwrite  the text of
    untagged data.

**imclient_send()**
    Sends a new command to the **imclient** connection.  *finishproc*
    and *finishrock* are the function and rock called when the command
    completes.  *functionproc* may be a null pointer, in which case no
    callback is made. The callback function may not call the functions
    **imclient_close(), imclient_send(), imclient_eof(),
    imclient_processoneevent()**, or **imclient_authenticate()** on the
    connection.  The argument *fmt* is a :manpage:`printf(3)` like
    specification of the command. It must not include the tag as the
    tag is automatically added by **imclient_send()**.

    The defined %-sequences are:

        ::

            %% for %
            %a for an IMAP atom
            %s for an astring (which will be quoted or literalized as needed)
            %d for a decimal
            %u for an unsigned decimal
            %v for #astring (argument is a null-terminated array of char *
            which are written as space separated astrings)

**imclient_getselectinfo()**
    Gets the information for calling :manpage:`select(2)`.  *fd* is
    filled in with the file descriptor to :manpage:`select(2)` for read.
    *wanttowrite* is filled in with a nonzero value if **select** should
    be used for write as well.

**imclient_processoneevent()**
    Processes one input or output event on the **imclient** connection.

**imclient_authenticate()**
    Authenticates the **imclient** connection using one of the mechanisms
    in *availmech*.  The argument *user*, if not NULL, specifies the user
    to authenticate as. If the user is NULL, the current user is used.
    The argument *protallowed* is a bitmask of permissible protection
    mechanisms.
    On success, 0 is returned.  On failure (i.e., "BAD" keyboard, or
    no authentication mechanisms worked), 1 is returned. On extreme
    failure (premature "OK"), 2 is returned.

**imclient_havetls()**
    Returns a Boolean indicating whether the **imclient** library was
    compiled with TLS (SSL) support.  If so, **imclient_starttls()** may
    be used to secure the IMAP connection.

**imclient_starttls()**
    Issues a STARTTLS command on an existing IMAP connection and
    negotiates the secure link.  The *cert_file* and *key_file* arguments
    specify the client certificate and secret key to use to
    authenticate ourselves to the server.  If client authentication is
    not needed, set both of these arguments to NULL.

    The *CAfile* and *CApath* arguments specify a file or directory,
    respectively, of CA certificates for validating server
    certificates. (See :manpage:`SSL_CTX_load_verify_locations(3)` for
    details.)  If both of these are NULL, the client will be unable to
    validate the server's certificate, in which case the connection may
    succeed but a warning will be printed to stdout.

Examples
========

The following code is a possible skeleton of **imclient** that relies
on Kerberos to do authentication.  This code performs an IMAP
CAPABILITY request and prints out the result.

    ::

        #include <cyrus/xmalloc.h> /* example uses xstrdup */
        #include <cyrus/sasl.h>
        #include <cyrus/imclient.h>
        #include <stdio.h>

        extern struct sasl_client krb_sasl_client;

        struct sasl_client *login_sasl_client[] = {
            &krb_sasl_client,
            NULL
        };
        struct imclient *imclient;
        char server[] = "cyrus.andrew.cmu.edu" ;
        char port[] = "imap";

        void fatal(char* message, int rc) {
            fprintf(stderr, "fatal error: %s\en", message);
            exit(rc);
        }

        static void callback_capability(struct imclient *imclient,
                                        void *rock,
                                        struct imclient_reply *reply) {
            if (reply->text != NULL) {
                *((char**)rock) = xstrdup( reply->text );
            }
        }

        static void end_command(struct imclient *connection, void*
                                rock,  struct imclient_reply *inmsg) {
            (*(int*)rock)--;
        }

        main() {
            char* capability_string;
            int nc;

            if (imclient_connect(&imclient, server, port)) {
                fprintf(stderr,
                        "error: Couldn't connect to %s %s\en",
                        server, port);
                exit(1);
            }

            if (imclient_authenticate(imclient, login_sasl_client, "imap"
                                      /* service */,
                                      NULL /* user */, SASL_PROT_ANY)) {
                exit(1);
            }

            imclient_addcallback(imclient, "CAPABILITY",
                                 CALLBACK_NOLITERAL,
                                 callback_capability,
                                 &capability_string,
                                 NULL);

            nc = 1;

            imclient_send(imclient, end_command,
                          (void*) &nc, "CAPABILITY");

            while(nc > 0) {
                imclient_processoneevent(imclient);
            }

            if (strstr("LITERAL+", capability_string)) {
                imclient_setflags(imclient, IMCLIENT_CONN_NONSYNCLITERAL);
            }

            imclient_send(imclient, NULL, NULL, "LOGOUT");
            imclient_close(imclient);

            printf("capability text is: %s\en", capability_string);

            free(capability_string);
        }

Bugs
====

No known bugs.

See Also
========

:cyrusman:`cyradm(8)`,
:cyrusman:`imapd(8)`,
:rfc:`2033` (IMAP LITERAL+ extension),
:rfc:`2060` (IMAP4rev1 specification), and
:manpage:`select(2)`

Keywords
========

IMAP, ACAP, Kerberos, Authentication
