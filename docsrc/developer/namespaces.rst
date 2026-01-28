.. _imap-developer-namespaces:

============================
Namespaces: a developer view
============================

Since Cyrus allows dot characters in the mailbox names, one may have a
naming convention that leads user *John Doe* to hold an email address of
``john.doe@example.org``. The internal representation of this mailbox is
``example.org!user.john^doe``.

.. NOTE::

    A second user mailbox, if shared with *Uhura*, would present itself
    to *Uhura* as being in the
    :ref:`imap-features-namespaces-other-users`, but the internal
    representation of it remains the same.

The namespace mode does NOT change the rules governing the behavior of mailboxes or how mailboxes are stored on the filesystem. The mailboxes are ALWAYS stored with dot hierarchy separators. When configured to use the different modes and separators, the server translates mailbox names between the internal names and the external names when used by the client in the IMAP protocol and in Sieve scripts.

This design allows the namespace to be changed at runtime (even on a running server) without having to reconfigure the server. This also means that one mailstore can support different namespaces.
