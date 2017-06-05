.. cyrusman:: smmapd(8)

.. author: Nic Bernstein (Onlight)

.. _imap-reference-manpages-systemcommands-smmapd:

==========
**smmapd**
==========

Sendmail socket map daemon

Synopsis
========

.. parsed-literal::

    **smmapd** [ **-C** *config-file* ]  [ **-U** *uses* ] [ **-T** *timeout* ] [ **-D** ]

Description
===========

**smmapd** is a Sendmail socket map daemon which is used to verify that
a Cyrus mailbox exists, that it is postable and it is under quota.  It
accepts commands on its standard input and responds on its standard
output.  It MUST be invoked by :cyrusman:`master(8)` with those
descriptors attached to a remote client connection.

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

Examples
========

Files
=====

/etc/imapd.conf,
/etc/cyrus.conf

See Also
========

:cyrusman:`imapd.conf(5)`,
:cyrusman:`cyrus.conf(5)`
