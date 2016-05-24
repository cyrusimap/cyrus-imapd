.. _imap-admin-systemcommands-masssievec:

==============
**masssievec**
==============

Script to compile a mass of sieve scripts in one pass.

Synopsis
========

.. parsed-literal::

    **masssievec** \<path to sievec\> [ *imapd.conf* ]

Description
===========

**masssievec** compiles a set of sieve scripts, using :cyrusman:`sievec(1)` based on the files found in the **sievedir**  config from the ``imapd.conf`` file.

It cannot compile scripts stored in user's home directories.


Options
=======

.. program:: masssievec

.. option:: imapd.conf

    Provide an alternate impad.conf. If not specified, uses ``/etc/imapd.conf``.

See Also
========

:cyrusman:`sievec(1)`, :cyrusman:`imapd.conf(5)`
