.. cyrusman:: translatesieve(8)

.. author: Nic Bernstein (Onlight)

.. _imap-reference-manpages-systemcommands-translatesieve:

==================
**translatesieve**
==================

Translate sieve scripts to use unixhierarchysep and/or altnamespace.

Synopsis
========

.. parsed-literal::

    **translatesieve** [**-f**] [**-a**] [**-u**] [**-n**] [**-v**] [**-C** *imapd.conf*]

Description
===========

**translatesieve** can both translate the mailbox separator characters
in sieve scripts from traditional netnews style -- '.' -- to new Unix
style -- '/' -- and vice versa.  It can also convert sieve scripts to
use ``altnamespace`` mailbox naming conventions.  Please also see
:ref:`Mailbox namespaces <mailbox-namespaces>` for details.

In its default mode, **translatesieve** assumes that the old configuration
used *both* ``unixhierarchysep: no`` and ``altnamespace: no``.  If your
configuration was already using one of these, then use the appropriate
flag, **-u** for ``unixhierarchysep: yes`` or **-a** for
``altnamespace: yes``.  Failure to do so may ruin your sieve scripts.

A "Dry run" mode is available via **-n** and you are strongly encouraged
to use this.

**translatesieve** |default-conf-text|

Must be run as the cyrus user.


Options
=======

.. program:: translatesieve

.. option:: -f

  Keep going on errors.

.. option:: -a

  Translate from a configuration which already used ``altnamespace: yes``.

.. option:: -u

  Translate from a configuration which already used ``unixhierarchysep: yes``.

.. option:: -n

  Dry-run mode.  No changes will be written, but you'll be shown what would
  be changed.

.. option:: -v

  Verbose mode.  Note: -n implies -v.

.. option:: -C config-file

    |cli-dash-c-text|

See Also
========
:cyrusman:`imapd.conf(5)`
