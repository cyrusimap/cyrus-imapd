.. _imap-admin-systemcommands-nntpd:

=========
**nntpd**
=========

NNTP server process

Synopsis
========

.. parsed-literal::

    **nntpd** [ **-C** *config-file* ] [ **-U** *uses* ] [ **-T** *timeout* ] [ **-D** ]
        [ **-s** ] [ **-r** ] [ **-f** ] [ **-p** *ssf* ]

Description
===========

**nntpd** is an NNTP server. It accepts commands on its standard input
and responds on its standard output. It MUST invoked by
:cyrusman:`master(8)` with those descriptors attached to a remote client
connection.

**nntpd** |default-conf-text|  The optional ``newsprefix`` setting
specifies a prefix to be prepended to newsgroup names to make the
corresponding IMAP mailbox names.  The optional ``newspostuser``
setting specifies the special userid to be used when contructing the
*To:* header address for following up to articles when read via IMAP.
The optional ``newspeer`` setting specifies the fully qualified hostname
of the upstream news server to which articles are fed.  The optional
``allownewnews`` setting enables the NNTP NEWNEWS command.  

.. Note:: 
  For servers with a large volume of articles, the NEWNEWS command can
  be expensive.

If the directory ``<configdirectory>/log/``\ *user* exists, then
**nntpd** will create protocol telemetry logs for sessions
authenticating as *user*. The telemetry logs will be stored in the
``log/``\ *user* directory with a filename of the **nntpd** process-id.

Options
=======

.. program:: nntpd

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

.. option:: -s

    Serve NNTP over SSL (https).  All data to and from **nntpd**
    is encrypted using the Secure Sockets Layer.

.. option:: -r

    Only allow NNTP reader commands.  Permitted clients will only be
    allowed to read/post articles.

.. option:: -f

    Only allow NNTP feeder commands.  Permitted clients will only be
    allowed to feed articles (no reading).

.. option:: -p  ssf

    Tell **nntpd** that an external layer exists.  An *SSF* (security
    strength factor) of 1 means an integrity protection layer exists.
    Any higher SSF implies some form of privacy protection.

Files
=====

/etc/imapd.conf

See Also
========

:cyrusman:`imapd.conf(5)`,
:cyrusman:`master(8)`
