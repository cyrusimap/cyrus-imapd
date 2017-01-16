.. cyrusman:: ptexpire(8)

.. _imap-reference-manpages-systemcommands-ptexpire:

============
**ptexpire**
============

Program to expire pts cache DB entries on command.

Synopsis
========

.. parsed-literal::

    **ptexpire** [**-C** *filename*] [**-E** *time*]

Description
===========

The **ptexpire** program sweeps the ``ptscache_db`` database, expiring
entries older than the time specified on the command line (default 3
hours).

**ptexpire** |default-conf-text|

Options
=======

.. program::  ptexpire

.. option::  -C config-file

  |cli-dash-c-text|
  
.. option::  -E time

  Expire entries older than this time.
  Default: 3 hours

Files
=====

/etc/imapd.conf

See Also
========
:cyrusman:`imapd.conf(5)`
