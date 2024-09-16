.. cyrusman:: sync_reset(8)

.. author: David Carter (dpc22@cam.ac.uk)
.. author: Ken Murchison (ken@oceana.com)
.. author: Nic Bernstein (Onlight)

.. _imap-reference-manpages-systemcommands-sync_reset:

==============
**sync_reset**
==============

Account reset utility. DANGER.

Synopsis
========

.. parsed-literal::

    **sync_reset** [ **-C** *config-file* ] [ **-v** ] [ **-f** ]

Description
===========

**sync_reset** is a small utility program to destroy user accounts on a
system.  The only safeguard which is in place is the obligatory force
option.

**sync_reset** |default-conf-text|

Options
=======

.. program:: sync_reset

.. option:: -C config-file

    |cli-dash-c-text|

.. option:: -v, --verbose

  Verbose mode.

.. option:: -f, --force

  Force operation. Without this flag **sync_reset** just bails out with
  an error.  Principally here to try and prevent accidents with command
  autorepeat.

Files
=====

/etc/imapd.conf

See Also
========

:cyrusman:`imapd.conf(5)`
