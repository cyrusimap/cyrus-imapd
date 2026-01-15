.. cyrusman:: backupcyrusd(8)

.. author: Bron Gondwana

.. _imap-reference-manpages-systemcommands-backupcyrusd:

================
**backupcyrusd**
================

Backup Server for the Fastmail-derived simple Cyrus backup protocol

Synopsis
========

.. parsed-literal::

    **backupcyrusd** [ **-C** *config-file* ] [ **-U** *uses* ] [ **-T** *timeout* ] [ **-D** ]

Description
===========

**backupcyrusd** is server which speaks the backup protocol used at Fastmail.
It implements NO AUTHENTICATION so MUST only listen on safe internal networks
and be firewalled from any untrusted users.

It accepts commands on its standard input and responds on its standard output.
It MUST invoked by :cyrusman:`master(8)` with those descriptors attached to a
remote client connection.

Options
=======

.. program:: backupcyrusd

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

Files
=====

/etc/imapd.conf

See Also
========

:cyrusman:`imapd.conf(5)`,
:cyrusman:`master(8)`
