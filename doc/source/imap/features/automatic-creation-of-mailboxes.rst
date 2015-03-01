===============================
Automatic Creation of Mailboxes
===============================

Cyrus IMAP features the ability to create mailboxes automatically;

*   for successful login events,

*   for email messages that arrive for a user,

*   when a Sieve script uses the "fileinto" action.

.. NOTE::

    Cyrus IMAP documentation is a work in progress, and the completion
    of this part of the documentation is pending the resolution of
    :task:`41`.

When operating an IT infrastructure, Cyrus IMAP may only be one part of
such larger environment. When adding a user
*John Doe <john.doe@example.org>*, several pieces may need to fall or
put in place to ensure the account is fully functional.

Cyrus IMAP allows the automatic creation of John's INBOX, and selected
sub-folders, either when John first logs in to Cyrus IMAP, or when the
first message is to be delivered to John's INBOX.

Additional features of this functionality include;

*   the automatic creation of a Sieve script for
    :ref:`imap-features-server-side-filtering`.

*   setting a storage quota and message quota for the user,

*   automatic subscription to folders in the
    :ref:`imap-features-namespaces-personal`,

*   automatic subscription to a selection of or all shared folders.

.. IMPORTANT::

    Third party solutions incorporating Cyrus IMAP, and distributors of
    Cyrus IMAP (such as your Linux distribution) may have disabled this
    functionality altogether, during the building of the packages.

    Cyrus IMAP does not currently strip options from man-pages that are
    rendered irrelevant by the functionality not being built in, so
    while the man-page on your system may refer to settings related to
    this functionality, the actual functionality may not be available.

To enable the automatic creation of mailboxes, set the following options
in :manpage:`imapd.conf(5)`:

*   ``autocreate_quota``

    Set ``autocreate_quota`` to a value of zero or greater to allow
    successful login events to create a user's INBOX if it does not
    already exist.

    .. NOTE::

        A value of ``0`` corresponds with no quota. The value depicts
        quota in kilobytes.

        The default is for this configuration option is ``-1``.

*   ``autocreate_post``

    Set ``autocreate_post`` to ``1`` to allow :manpage:`lmtpd(8)` to
    create user's INBOX (and sub-) folders.

See :manpage:`imapd.conf(5)` for the full documentation of all options.
