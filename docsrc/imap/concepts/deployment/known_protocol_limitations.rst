Known Protocol Limitations
==========================

This chapter lists known limitations to protocols commonly in use today, that
may impact your deployment.

POP3 and Mailbox Locking
------------------------

POP3, as described in :rfc:`1939`, requires a mailbox to be locked by a POP3
session.

As such, when POP3 is used simultaneously across multiple clients, and a common
set of mailboxes, an error similar to the following would occur::

    Mailbox locked by POP server.

The exact error message may be subject to the specific error message a client
application wishes to display.

Cyrus IMAP POP3 Implementation
------------------------------

The Cyrus IMAP POP3 server implementation does not have the aforementioned
problem of POP3 sessions locking mailboxes. As of version 2.4.0, Cyrus IMAP
allows multiple POP3 sessions to operate on a single mailbox by providing a
*virtual* snapshot of the mailbox, and all operations are executed to this
snapshot. A safety mechanism ensures no messages are deleted until after all
existing operations have closed the mailbox - including IMAP, LMTP and POP.

