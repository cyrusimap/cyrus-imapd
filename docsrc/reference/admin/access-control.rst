.. _imap-admin-access-control-lists:

==============
Access Control
==============

Cyrus IMAP features rich access control compliant with :rfc:`2086`,
:rfc:`4314`, :rfc:`5257` and :rfc:`5464`.

.. toctree::
    :maxdepth: 1
    :glob:

    access-control/*

.. _imap-admin-access-control-lists-discretionary:

Discretionary Access Control
============================

Cyrus IMAP employs discretionary access control, meaning that users
themselves are in charge of what folders are shared, and with whom.

Two means exist to suppress sharing folders between users:

#.  Revoke the :ref:`imap-admin-access-control-right-a` (administration)
    right on all mailboxes in the personal namespace for each user.

#.  Suppress the listing of the
    :ref:`imap-features-namespaces-other-users` by enabling
    ``disable_user_namespace`` in :cyrusman:`imapd.conf(5)`.

Back to :ref:`imap-admin`
