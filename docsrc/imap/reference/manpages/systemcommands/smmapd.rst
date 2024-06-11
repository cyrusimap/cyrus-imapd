.. cyrusman:: smmapd(8)

.. author: Nic Bernstein (Onlight)

.. _imap-reference-manpages-systemcommands-smmapd:

==========
**smmapd**
==========

Sendmail and Postfix socket map daemon

Synopsis
========

.. parsed-literal::

    **smmapd** [ **-C** *config-file* ]  [ **-U** *uses* ] [ **-T** *timeout* ] [ **-D** ] [**-p**]

Description
===========

**smmapd** is a Sendmail and Postfix socket map daemon which is used to verify
that a Cyrus mailbox exists, that it is postable, it is not blocked for the
smmapd service in the userdeny database, and it is under quota.  It
accepts commands on its standard input and responds on its standard
output.  It MUST be invoked by :cyrusman:`master(8)` with those
descriptors attached to a remote client connection.  The received queries
contain map name followed by mailbox, **smmapd** ignores the map name.
Queries with plus addressing, when *-p* is not passed, return *OK* when
the user has a mailbox with the name after plus, otherwise the result
is *NOTFOUND*.  Match for the mailbox after plus is performed
case-sensitive, for the address before the plus - depends on
`lmtp_downcase_rcpt`.

The use case is to verify in Sendmail or Postfix if the destination exists,
before accepting an email.  Then, if `autocreate_sieve_folders` is set, but
the folder does not exist yet, **smmapd** will return *NOTFOUND*, unless *-p*
is passed.  Another use case is to do something in a Sieve script with emails,
based on plus addressing, without delivering them in the correspondent sub-folder.
To accept such emails, when the folder with the same name does not exist, *-p* must
be passed.

**smmapd** |default-conf-text|

Options
=======

.. program:: smmapd

.. option:: -C config-file

    |cli-dash-c-text|

.. option:: -U  uses

    The maximum number of times that the process should be used for new
    connections before shutting down.  The default is 250.

.. option:: -T  timeout

    The number of seconds that the process will wait for a new
    connection before shutting down.  Note that a value of 0 (zero)
    will disable the timeout.  The default is 60.

.. option:: -D

    Run external debugger specified in debug_command.

.. option:: -p

    Skip plus addressing: everything from `+` until `@`.  When looking up the userdeny
    database, plus addressing is always skipped, irrespective of this option.

Examples
========

**smmapd** is commonly included in the SERVICES section of
:cyrusman:`cyrus.conf(5)` like so:

.. parsed-literal::
    SERVICES {
        imap        cmd="imapd -U 30" listen="imap" prefork=0
        imaps       cmd="imapd -s -U 30" listen="imaps" prefork=0 maxchild=100
        lmtpunix    cmd="lmtpd" listen="/var/run/cyrus/socket/lmtp" prefork=0 maxchild=20
        **smmap       cmd="smmapd" listen="/var/run/cyrus/socket/smmap" prefork=0**
        sieve       cmd="timsieved" listen="sieve" prefork=0
        notify      cmd="notifyd" listen="/var/run/cyrus/socket/notify" proto="udp" prefork=1
        httpd       cmd="httpd" listen=8080 prefork=1 maxchild=20
    }


Files
=====

/etc/imapd.conf,
/etc/cyrus.conf

See Also
========

:cyrusman:`imapd.conf(5)`,
:cyrusman:`cyrus.conf(5)`
