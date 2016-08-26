==================
Shared \Seen State
==================

IMAP users maintain the information on whether or not a message is
marked as read using so-called flags on the messages. The flag for
marking a message as read or unread is ``\Seen``.

Normally, each individual user has their own copy of which messages they
did or did not yet read. This is not necessarily ideal, such as for a
shared mailbox ``shared/info@example.org`` -- a team of users may be
picking messages from this mailbox as if it were a queue, and it would
therefore be really useful if one team member could see whether another
team member has already read the message.

Cyrus IMAP features the ability to share ``\Seen`` flags between all
users with access to a mailbox to facilitate precisely this and other
use-cases.

Back to :ref:`imap-features`
