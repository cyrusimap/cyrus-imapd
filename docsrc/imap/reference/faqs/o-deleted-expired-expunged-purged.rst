.. _imap-admin-deleted-expired-expunged-purged:

======================================================
When is What ... Deleted, Expired, Expunged or Purged?
======================================================

The terminology sometimes plays administrators for fools -- which they
are obviously not -- but an article clarifying what it is that is meant
by either term of Deleted, Expired, Expunged or Purged goes a long way.

**Deleted**

    A message has been flagged as ``\Deleted``.

    In the context of folders, *Deleted* only really applies to a folder
    having been removed (from the user's (IMAP client) view), as opposed
    to having been renamed to a hierarchy in a trash folder.

**Expired**

    The index records of a message have been expired, and usually this
    means the message file has been purged as well. However the message
    file could be purged prior to index records being expired.

**Expunged**

    The message (which has been flagged as ``\Deleted``) is also
    expunged, meaning that the user can in no way retrieve the message
    autonomously.

**Purged**

    The message's index record may still exist (until they are expired),
    but the message file is removed from the filesystem, or in the
    context of folders, the mail folder is removed from the filesystem.

Users and IMAP Clients Deleting Messages
========================================

When a **message** is deleted by a user, this means that the user's IMAP
client has in fact *flagged* the message with ``\Deleted``, or
alternatively, the IMAP client has moved the message to a trash folder
(and has at least flagged the original copy as ``\Deleted``).

What is the exact behavior depends on the IMAP client software, and if
so allowed, the user's preferences specified within the IMAP client
software, and the Cyrus IMAP server configuration.

Flagged As ``\Deleted``
-----------------------

When a message is merely flagged with ``\Deleted``, the message itself
as such remains available to the IMAP client, but the IMAP client used
may not make it possible for the user to view a list of messages flagged
with ``\Deleted``. As such, the user may interpret the message as
removed and unavailable -- if the removal was accidental, a support call
may be on its way.

The message in fact still resides in the Cyrus IMAP mail spool, still
resides in the same IMAP folder, and still resides on the filesystem.

Only when the user (or the user's IMAP client as is often the case)
issues an ``EXPUNGE`` against the folder, or a ``UID EXPUNGE`` against
the message [#]_, will the message be actually removed -- at least from
the user's perspective. It then becomes irretrievable even if the IMAP
client allows the listing of messages flagged with ``\Deleted``.

Issuing an ``EXPUNGE`` may come in the form of a button to "compact" the
folder, or an IMAP client routine that is executed periodically or at
the end of a session (e.g. as the client application is closed), such as
an "Empty Trash folder" kind of option.

It is here that the Cyrus IMAP server settings come in to play, most
prominently the ``expunge_mode`` setting, which has three possible
values:

**delayed** (the default *since version 2.5.0*)

    The message files as well as the index records are retained for an
    undetermined period of time -- possibly indefinitely.

    A separate job (using :ref:`imap-reference-manpages-systemcommands-cyr_expire`) is
    responsible for actually removing index records and message files.

**default**

    The message files are removed at the first opportunity, while the
    index records remain available to facilitate ``QRESYNC``.

    In this context also, when we say "message files are removed", we
    mean "purged from the filesystem".

**immediate**

    The message files as well as the index records are removed at the
    earliest opportunity.

    In this context, when we say "message files are removed", we mean
    "purged from the filesystem".

Exceptional circumstances aside, when ``immediate`` or ``default`` is
the configured ``expunge_mode``, message files are often purged from the
filesystem too quickly for anyone to recover.

.. NOTE::

    One such exceptional circumstance is a mailbox with multiple
    sessions keeping the mailbox open. Cyrus IMAP ensures no mailbox
    records disappear from underneath an existing open mailbox session.

Moved to Trash Folder
---------------------

Should the IMAP client normally, or allow the user to specify through
preferences, that messages being deleted should be moved in to a trash
folder, then the user will usually be able to recover from accidental
deletion autonomously, for as long as a copy of the deleted message(s)
resides in such trash folder.

However, the trash folder would typically continue to grow and grow, and
usually counts towards the user's resource usage (a.k.a.
:ref:`imap-features-quota`); many IMAP clients therefore allow the user
to specify a preference to empty the trash folder at the end of a
session, or otherwise periodically.

If the IMAP client does not support :rfc:`6851` (for ``UID MOVE``), the
client may choose to ``COPY`` the message then flag the original with
``\Deleted``, then ``EXPUNGE`` the folder or ``UID EXPUNGE``
(:rfc:`4315`) the message.

This does not fare well in situations where the user is over quota,
though, and (other) messages will need to be flagged as ``\Deleted`` and
expunged, and/or folders within the quota root hierarchy will need to be
deleted.

Expunged Messages
-----------------

Messages in expunged folders, or messages that have been expunged
individually, can not autonomously be restored by a user, and are gone
permanently unless ``expunge_mode: delayed`` is used.

Recovering expunged messages requires administrator assistance, who can
use command-line tools such as :ref:`imap-reference-manpages-systemcommands-unexpunge` to
list and restore messages expunged. See the documentation on
:ref:`imap-reference-manpages-systemcommands-unexpunge` for a walk-through on how that
works.

With the use of ``expunge_mode: delayed``, a regular ``EVENT`` (see
:cyrusman:`cyrus.conf(5)`) is responsible for triggering
:ref:`imap-reference-manpages-systemcommands-cyr_expire`. This utility takes a parameter
``-X <days>`` to delete from the filesystem any messages that had been
expunged (by the user or the IMAP client) more than ``<days>`` days ago.

In other words, using ``expunge_mode: delayed`` and
:ref:`imap-reference-manpages-systemcommands-cyr_expire` allows an administrator to recover
messages that have been deleted by the user less than ``<days>`` ago.

.. NOTE::

    This also offers a backup program the chance to obtain all message
    files. For a monthly full cycle, for example, one could choose to
    purge message files from the filesystem only after 69 days: two
    months plus the maximum margin for a first Saturday to Sunday night
    of the week.

Deleting Folders
================

When folders are deleted the IMAP client tends to either delete the
folder, or rename the folder to a hierarchy in a trash folder.

.. NOTE::

    Note that deleting a folder ``A/B`` in a hierarchy ``A/B/C`` also
    deletes the folder ``A/B/C``.

If the folder is not renamed to a hierarchy in a trash folder but
instead removed directly, then the user has no way to autonomously
recover from such event.

This is where the Cyrus IMAP server settings come in to play, most
prominently ``delete_mode``.

The setting holds two values:

**delayed** (the default *since version 2.5.0*)

    Mailboxes that are being deleted are not deleted from the
    filesystem, but instead renamed to a special mailbox hierarchy under
    the deleted prefix, to be removed later by
    :ref:`imap-reference-manpages-systemcommands-cyr_expire`.

**immediate**

    In immediate mode, the mailbox is removed from the filesystem
    immediately. Note that for large folders, this can be a
    comparatively expensive operation.

Where are the Messages?
=======================

This part of the documentation assumes that you have run with the
default settings of ``delete_mode: delayed`` and
``expunge_mode: delayed``.

The result of a message having deleted in either of the former ways, or
an entire folder having been deleted, is one of the following stages;

*   The message has only been flagged as ``\Deleted`` and the message
    nor the folder has been expunged.

    Result: The message resides in the original folder.

*   The message has only been flagged as ``\Deleted`` and either the
    message individually or the entire folder as a whole has been
    expunged.

    Result: The message resides in the original folder and can be
    retrieved using :ref:`imap-reference-manpages-systemcommands-unexpunge`.

*   The message has been copied to the trash folder and at least flagged
    ``\Deleted`` in the source folder, and the original message or the
    entire folder in which the original message resided may or may not
    have been expunged.

    Similarly, the trash folder may or may not have been "emptied".

    Result: A copy of the message still exists in the original folder
    and can be retrieved using :ref:`imap-reference-manpages-systemcommands-unexpunge`.

*   The message was moved in to the trash folder, implying the original
    message is expunged from the source folder -- through ``UID MOVE``
    or :rfc:`6851` support *since version 2.5.0*.

    The trash folder may or may not have been "emptied".

    Result: A copy of the message still exists in the original folder
    and can be retrieved using :ref:`imap-reference-manpages-systemcommands-unexpunge`.

*   The folder was moved to a hierarchy in the trash folder, and the
    trash folder has not yet been "emptied".

    Result: A copy of the message exists in the trash folder's
    hierarchy.

*   The folder was moved to a hierarchy in the trash folder, and the
    trash folder as subsequently been emptied.

    Result: The folder hierarchy has been renamed to the deleted
    namespace.

.. rubric:: Footnotes

.. [#]

    Only if the IMAP client supports :rfc:`4315`, the IMAP UIDPLUS
    Extension.
