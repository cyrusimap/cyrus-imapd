.. cyrusman:: ipurge(8)

.. _imap-reference-manpages-systemcommands-ipurge:

==========
**ipurge**
==========

Delete mail from IMAP mailbox or partition based on age or size

Synopsis
========

.. parsed-literal::

    **ipurge** [ **-f** ] [ **-C** *config-file* ] [ **-x** ] [ **-X** ] [ **-i** ] [ **-s** ] [ **-o** ] [ **-n** ] [ **-v** ]
            [ **-d** *days* | **-b** *bytes* | **-k** *Kbytes* | **-m** *Mbytes* ]
            [ *mailbox-pattern*... ]

Description
===========

*ipurge* deletes messages from the mailbox(es) specified by
*Imailbox-pattern* that are older or larger than specified by the
**-d**, **-b**, **-k** or **-m** options.  If no *mailbox-pattern* is
given, *ipurge* works on all mailboxes.  If the **-x** option is given,
the message age and size MUST match exactly those specified by **-d**,
**-b**, **-k** or **-m**.  The are no default values, and at least one
of **-d**, **-b**, **-k** or **-m** MUST be specified.

*Ipurge* by default only deletes mail below shared folders, which means
that mails in mailbox(es) below INBOX.* and user.* stay untouched. Use
the option **-f** to also delete mail in mailbox(es) below these
folders.

*ipurge* |default-conf-text|

Options
=======

.. program:: ipurge

.. option:: -C config-file

    |cli-dash-c-text|

.. option:: -f

    Force ipurge to examine mailboxes below INBOX.* and user.*.

.. option:: -d days

    Age of message in *days*.

.. option:: -b bytes

    Size of message in *bytes*.

.. option:: -k Kbytes

    Size of message in *Kbytes* (2^10 bytes).

.. option:: -m Mbytes

    Size of message in *Mbytes* (2^20 bytes).

.. option:: -x

    Perform an exact match on age or size (instead of older or larger).

.. option:: -X

    Use delivery time instead of Date: header for date matches.

.. option:: -i

    Invert match logic: -x means not equal, date is for newer, size is
    for smaller.

.. option:: -s

    Skip over messages that have the \\Flagged flag set.

.. option:: -o

    Only purge messages that have the \\Deleted flag set.

.. option:: -n

    Only print messages that would be deleted (dry run).

.. option:: -v

    Enable verbose output/logging.

Examples
========

[NB: Examples needed]

Files
=====

/etc/imapd.conf

See Also
========
:cyrusman:`imapd.conf(5)`
