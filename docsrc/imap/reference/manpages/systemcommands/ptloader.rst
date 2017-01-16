.. cyrusman:: ptloader(8)

.. _imap-reference-manpages-systemcommands-ptloader:

============
**ptloader**
============

The AFS & LDAP pts server loader service

Synopsis
========

.. parsed-literal::

    ptloader [**-d**]

Description
===========

**ptloader** interacts with the authorization service, either AFS or
LDAP, providing group membership information to Cyrus.  When
``auth_mech: pts`` is set in :cyrusman:`imapd.conf(5)`, **ptsloader**
will then consult the backend specified in the ``pts_module`` setting
(currently either ``afs`` or ``ldap``).

**ptloader** reads its configuration options out of the
:cyrusman:`imapd.conf(5)` file and *does not* accept the **-C** option.

Options
=======

.. program:: ptloader

.. option:: -d

    Run **ptloader** in debugging mode.

Files
=====

/etc/imapd.conf

See Also
========
:cyrusman:`imapd.conf(5)`
