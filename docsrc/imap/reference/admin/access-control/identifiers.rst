.. _imap-admin-access-control-identifiers:


Access Control Identifier (ACI)
===============================

The Access Control Identifier (ACI) part of an ACL entry specifies the
user or group for which the entry applies.  Group identifiers are
distinguished by the prefix "group:".  For example, "group:accounting".

.. todo:: FIXME: Clarify what an ACL entry looks like first. Refer to
          how user login names are translated into their identifiers, and (in
          that section) refer to altnamespace, unixhierarchysep, default domain,
          virtdomains, tips and tricks etc.

There are two special identifiers, "anonymous", and "anyone".  The meaning of
other identifiers usually depends on the authorization mechanism being used.

``anonymous`` and ``anyone``
----------------------------

With any authorization mechanism, two special identifiers are defined.
The identifier ``anonymous`` refers to the anonymous, or unauthenticated
user. The identifier ``anyone`` refers to all users, including the
anonymous user.

Both ``anonymous`` and ``anyone`` may commonly be used with the **post**
right ``p`` to allow message insertion to mailboxes.


Authorization Mechanisms
========================

The Cyrus IMAP server comes with four authorization mechanisms, one is
compatible with Unix-style (``/etc/passwd``) authorization, one called
``mboxgroups``, one for use with Kerberos 5, and one for use with an
external authorization process (ptloader) which can interface with
other group databases (e.g. AFS PTS groups, LDAP Groups, etc).

.. note::
    **Authentication !== Authorization**

    Note that authorization is *not* the same thing as authentication.
    Authentication is the act of proving who you are. Authorization is
    the act of determining what rights you have. Authentication is
    discussed in the :ref:`imap-concepts-login-authentication` part of
    this document.

The authorization mechanism in use is determined by the ``auth_mech``
:cyrusman:`imapd.conf(5)` option:

    .. include:: /imap/reference/manpages/configs/imapd.conf.rst
        :start-after: startblob auth_mech
        :end-before: endblob auth_mech


Unix Authorization
------------------

::

    auth_mech: unix

In the Unix authorization mechanism, ACIs are either a valid userid or
the string ``group:`` followed by a group listed in ``/etc/group``.
Thus:

::

    root                Refers to the user root
    group:staff         Refers to the group staff

It is also possible to use unix groups with users authenticated through
a non-/etc/passwd backend. Note that using unix groups in this way
(without associated ``/etc/passwd`` entries) is not recommended.

..  note::
    Cyrus requires the getgrent(3) POSIX sysctl. As such, NSS needs to
    be configured to have the groups available, one of which includes
    "files", but could also include "ldap".

    NSS augmentations, such as ``nss_ldap``, ``pam_ldap`` or ``sssd``
    may be used to provide Cyrus access to group information via NSS.

mboxgroups Authorization
------------------------

::

    auth_mech: mboxgroups

The mboxgroups authorization mechanism is like the Unix mechanism, but it
looks for groups stored in the mailboxes.db instead of the system groups file.

When this authorization mechanism is in use, imapd will report the capability
``XUSERGROUPS``, and admins can use the IMAP commands ``GETUSERGROUP``,
``SETUSERGROUP``, and ``UNSETUSERGROUP`` for group management.

    **GETUSERGROUP** *item*

        If *item* is a userid, returns the groups the user belongs to.  If
        *item* is a group identifier, returns its members.

        ::

            C: 8 GETUSERGROUP cassandane
            S: * USERGROUP cassandane ("group:group c" "group:group co")
            S: 8 OK Completed
            C: 9 GETUSERGROUP "group:group co"
            S: * USERGROUP "group:group co" (cassandane otheruser)
            S: 9 OK Completed

    **SETUSERGROUP** *userid* *group*

        Adds *userid* as a member of *group*

        ::

            C: 9 SETUSERGROUP cassandane "group:new group"
            S: 9 OK Completed

    **UNSETUSERGROUP** *userid* *group*

        Removes *userid* from *group*

        ::

            C: 9 UNSETUSERGROUP cassandane "group:group c"
            S: 9 OK Completed

Kerberos Authorization
----------------------

::

    auth_mech: krb5

Using the Kerberos authorization mechanism, ACIs are of the form:

    *$principal*.*$instance*@*$realm*

If ``$instance`` is omitted, it defaults to the null string. If
``$realm`` is omitted, it defaults to the local realm.

PTS Authorization
-----------------

::

    auth_mech: pts

The PTS authorization mechanism is modular, with the module selected by the
``pts_module`` :cyrusman:`imapd.conf(5)` option:

    .. include:: /imap/reference/manpages/configs/imapd.conf.rst
        :start-after: startblob pts_module
        :end-before: endblob pts_module

The meaning of identifiers depends on the PTS module being used.

AFSKRB Authorization using PTS
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

::

    auth_mech: pts
    pts_module: afskrb

Document this!  Probably by linking to a separate document.

HTTP Authorization using PTS
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

::

    auth_mech: pts
    pts_module: http

Document this!  Probably by linking to a separate document.

LDAP Authorization using PTS
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

::

    auth_mech: pts
    pts_module: ldap

Document this!  Probably by linking to a separate document.

Alternative Authorization using PTS
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

::

    auth_mech: pts
    pts_module: ???

A site may wish to write their own authorization mechanism, perhaps to
implement a local group mechanism.  You do this by implementing a custom
PTS module.  The form and meaning of identifiers will be up to the
implementation.
