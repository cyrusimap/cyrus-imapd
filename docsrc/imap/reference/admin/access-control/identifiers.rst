.. _imap-admin-access-control-identifiers:


Access Control Identifier (ACI)
===============================

The Access Control Identifier (ACI) part of an ACL entry specifies the
user or group for which the entry applies.  Group identifiers are
distinguished be the prefix "group:".  For example, "group:accounting".

.. todo:: FIXME: Clarify what an ACL entry looks like first. Refer to
          how user login names are translated into their identifiers, and (in
          that section) refer to altnamespace, unixhiersep, default domain,
          virtdomains, sasl_auth_mech tips and tricks etc.

There are two special identifiers, "anonymous", and "anyone", which are
explained below. The meaning of other identifiers usually depends on
the authorization mechanism being used (selected by ``--with-auth`` at
compile time, defaulting to Unix).

``anonymous`` and ``anyone``
----------------------------

With any authorization mechanism, two special identifiers are defined.
The identifier ``anonymous`` refers to the anonymous, or unauthenticated
user. The identifier ``anyone`` refers to all users, including the
anonymous user.

Both ``anonymous`` and ``anyone`` may commonly be used with the **post**
right ``p`` to allow message insertion to mailboxes.


Kerberos vs. Unix Authorization
-------------------------------

The Cyrus IMAP server comes with four authorization mechanisms, one is
compatible with Unix-style (``/etc/passwd``) authorization, one for use
with Kerberos 4, one for use with Kerberos 5, and one for use with an
external authorization process (ptloader) which can interface with
other group databases (e.g. AFS PTS groups, LDAP Groups, etc).

.. note::
    **Authentication !== Authorization**

    Note that authorization is *not* the same thing as authentication.
    Authentication is the act of proving who you are. Authorization is
    the act of determining what rights you have. Authentication is
    discussed in the :ref:`imap-concepts-login-authentication` part of
    this document.

Unix Authorization
^^^^^^^^^^^^^^^^^^

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

Kerberos Authorization
^^^^^^^^^^^^^^^^^^^^^^

Using the Kerberos authorization mechanism, ACIs are of the form:

    *$principal*.*$instance*@*$realm*

If ``$instance`` is omitted, it defaults to the null string. If
``$realm`` is omitted, it defaults to the local realm.

The file ``/etc/krb.equiv`` contains mappings between Kerberos
principals. The file contains zero or more lines, each containing two
fields. Any identity matching the first field of a line is changed to
the second identity during canonicalization. For example, a line in
``/etc/krb.equiv`` of:

::

    bovik@REMOTE.COM bovik

will cause the identity ``bovik@REMOTE.COM`` to be treated as if it
were the local identity ``bovik``.

Alternative Authorization
^^^^^^^^^^^^^^^^^^^^^^^^^

A site may wish to write their own authorization mechanism, perhaps to
implement a local group mechanism. If it does so (by implementing an
``auth_[whatever]`` PTS module), it will dictate its own form and
meaning of identifiers.
