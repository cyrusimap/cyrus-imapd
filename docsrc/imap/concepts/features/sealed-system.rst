====================
Sealed System Design
====================

Cyrus IMAP is designed to run on *sealed system*, meaning that no
user-related information needs to be available to the POSIX system,
aside from the user and group Cyrus IMAP itself runs under.

This eliminates the requirement for any of the service's users to hold
POSIX account information attributes, and eliminates the need for
Cyrus IMAP to maintain a super-privileged process allowed to substitute
user.

The message spool directory or directories are held privately by the
Cyrus IMAP software, and can be accessed by user through IMAP, POP, NNTP
or JMAP protocols.

This design concept vastly increases the efficiency, scalability and
security of Cyrus IMAP, and makes it easier to configure, maintain,
troubleshoot and administer a Cyrus IMAP environment.

.. NOTE::

    Since all files and directories are held by the user and group that
    Cyrus IMAP runs under, any filesystem quota being used does not
    apply to anyone other than this user and group, voiding the ability
    to count disk usage towards a billing account's quota.

Back to :ref:`imap-features`
