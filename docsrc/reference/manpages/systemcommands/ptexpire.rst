.. cyrusman:: ptexpire(8)

.. author: Nic Bernstein (Onlight)

.. _imap-reference-manpages-systemcommands-ptexpire:

============
**ptexpire**
============

Program to expire pts cache DB entries on command.

Synopsis
========

.. parsed-literal::

    **ptexpire** [**-C** *filename*] [**-E** *seconds*] [ *username* ...]

Description
===========

The **ptexpire** program sweeps the ``ptscache_db`` database, deleting
entries older than the expiry duration, which defaults to 5400 seconds
(3 hours).  The expiry duration can be changed with the **-E** option.

Alternatively, if it's passed a list of usernames it deletes just those
usernames, immediately.

**ptexpire** |default-conf-text|

Options
=======

.. program::  ptexpire

.. option::  -C config-file

  |cli-dash-c-text|

.. option::  -E seconds, --expire-duration=seconds

  Set the expiry duration to *seconds*.

Files
=====

/etc/imapd.conf

See Also
========
:cyrusman:`imapd.conf(5)`
