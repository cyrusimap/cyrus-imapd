.. cyrusman:: cyr_deny(8)

.. author: Nic Bernstein (Onlight)

.. _imap-reference-manpages-systemcommands-cyr_deny:

============
**cyr_deny**
============

deny users access to Cyrus services

Synopsis
========

.. parsed-literal::

    **cyr_deny** [ **-C** *config-file* ] [ **-s** *services* ] [ **-m** *message* ] *user*
    **cyr_deny** [ **-C** *config-file* ] **-a** *user*
    **cyr_deny** [ **-C** *config-file* ] **-l**
    **cyr_deny** [ **-C** *config-file* ] **-r** [ **-a** ] *user*
    **cyr_deny** [ **-C** *config-file* ] **-r** **-l**

Description
===========

**cyr_deny** is used to deny individual users access to Cyrus services.
The first synopsis denies user *user* access to Cyrus services, the
second synopsis allows access again.  **cyr_deny** works by adding an
entry to the Cyrus ``user_deny.db`` database; the third synopsis lists
the entries in the database.  The service names to be matched are those
as used in :cyrusman:`cyrus.conf(5)`.

With **-r**, **cyr_deny** instead marks *user* as replica-only, or with
**-a** clears that mark, or with **-l** lists the marked users.  A
replica-only user is treated as if the server had ``replicaonly`` set:
their data comes from replication, and local changes are limited to
housekeeping such as :cyrusman:`cyr_expire(8)` removing already-expunged
messages.  Other local changes, such as delivery, APPEND, STORE or CREATE,
are refused as temporary failures, including in sessions that are already
open.  Unlike a deny, existing sessions are not disconnected;
use ``auth_notreplicaonly`` in :cyrusman:`imapd.conf(5)` to also refuse new
logins.  *user* is canonicalized as for a login.  Once **cyr_deny -r**
returns, nothing else can write to the user.

**cyr_deny** |default-conf-text|

Options
=======

.. program:: cyr_deny

.. option:: -C config-file

    |cli-dash-c-text|

.. option:: -a, --allow

    Allow access to all services for user *user* (remove any entry
    from the deny database).

.. option:: -s services, --services=services

    Deny access only to the given *services*, which is a
    comma-separated list of wildcard patterns.  The default is "*"
    which denies access to all services.


.. option:: -m message, --message=message

    Provide a message which is sent to the user to explain why access is
    being denied.  A default message is used if none is specified.

.. option:: -l, --list

    List the entries in the deny database.

.. option:: -r, --replicaonly

    Set, clear (with **-a**) or list (with **-l**) the per-user
    replica-only mark instead of the deny database.  The list does not
    include users covered only by the server-wide ``replicaonly``
    option.  See
    ``auth_notreplicaonly`` in :cyrusman:`imapd.conf(5)` to also refuse
    logins for such users.

Examples
========

[NB: Examples needed]

History
=======

|v3-new-command|

Files
=====

/etc/imapd.conf, <configdirectory>/user_deny.db,
<configdirectory>/replicaonly/

See Also
========

:cyrusman:`imapd.conf(5)`
