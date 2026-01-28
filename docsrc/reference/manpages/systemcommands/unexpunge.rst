.. cyrusman:: unexpunge(8)

.. author: Nic Bernstein (Onlight)
.. author: Jeroen van Meeuwen (Kolab Systems)

.. _imap-reference-manpages-systemcommands-unexpunge:

=============
**unexpunge**
=============

Recover messages the user has (accidentally) deleted.

Synopsis
========

.. parsed-literal::

    **unexpunge** [ **-C** *config-file* ] **-l** *mailbox* [ *uid*... ]
    **unexpunge** [ **-C** *config-file* ] **-t** *time-interval* [ **-d** ] [ **-v** ] [ **-f** *flagname* ] **mailbox**
    **unexpunge** [ **-C** *config-file* ] **-a** [ **-d** ] [ **-v** ] [ **-f** *flagname* ] *mailbox*
    **unexpunge** [ **-C** *config-file* ] **-u** [ **-d** ] [ **-v** ] [ **-f** *flagname* ] *mailbox* *uid*...

Description
===========

The **unexpunge** program is used to list or restore messages which have
been deleted from a mailbox, but still reside in the Cyrus IMAP mail
spool.

This utility is only useful when the server is configured with
``expunge_mode`` set to ``delayed`` in its configuration file.

**unexpunge** |default-conf-text|

Options
=======

.. program:: unexpunge

.. option:: -C config-file

    |cli-dash-c-text|

.. option:: -l, --list

    List the expunged messages in the specified mailbox which are
    available for restoration.
    Optionally, only list the messages in the mailbox matching the
    UIDs in the space\-separated list at the end of the command invocation.

.. option:: -t time-interval, --within-time-interval=time-interval

    Unexpunge messages which were expunged within the last
    ``time-interval`` seconds.
    Use one of the trailing modifiers -- ``m`` (minutes), ``h`` (hours),
    ``d`` (days) or ``w`` (weeks) -- to specify a different time unit.

.. option:: -a, --all

    Restore **all** of the expunged messages in the specified mailbox.

.. option:: -u, --uids

    Restore only messages matching the UIDs, in a space-separated list
    at the end of the command invocation, in the specified mailbox.

.. option:: -d, --unset-deleted

    Unset the *\\Deleted* flag on any restored messages.

.. option:: -f flagname, --set-flag=flagname

    Set the user flag *\\flagname* on the messages restored, making it
    easier for the user(s) to find the restored messages and operate on
    them (in a batch).

.. option:: -v, --verbose

    Enable verbose output/logging.

Examples
========

.. parsed-literal::

    **unexpunge -l** *user/john@example.org*

..

        List the messages that are expunged and could be restored for mailbox
        *user/john@example.org*.

.. only:: html

    ::

        UID: 278786
            Size: 2548
            Sent: Sat Mar  7 12:00:00 2015
            Recv: Sat Mar  7 12:42:52 2015
            Expg: Sun Mar  8 14:37:43 2015
            From: <notifications@fedoraproject.org>
            To  : <john+fedora@example.org>
            Cc  :
            Bcc :
            Subj: "pghmcfc submitted milter-greylist-4.5.12-2.fc21 to testing"

        UID: 278787
            Size: 2545
            Sent: Sat Mar  7 12:00:00 2015
            Recv: Sat Mar  7 12:42:52 2015
            Expg: Sun Mar  8 14:37:43 2015
            From: <notifications@fedoraproject.org>
            To  : <john+fedora@example.org>
            Cc  :
            Bcc :
            Subj: "pghmcfc submitted milter-greylist-4.5.12-2.el7 to testing"

        UID: 278788
            Size: 2548
            Sent: Sat Mar  7 12:00:00 2015
            Recv: Sat Mar  7 12:42:53 2015
            Expg: Sun Mar  8 14:37:43 2015
            From: <notifications@fedoraproject.org>
            To  : <john+fedora@example.org>
            Cc  :
            Bcc :
            Subj: "pghmcfc submitted milter-greylist-4.5.12-2.fc20 to testing"

.. parsed-literal::

    **unexpunge -u** *user/john@example.org 278787 278788*

..

        Unexpunge two of these messages.

.. only:: html

    ::

        restoring expunged messages in mailbox 'example/org!user/john'
        restored 2 expunged messages

    .. NOTE::
        The output of the unexpunge command may not match the input
        terms, in the case above, the mailbox ``user/john@example.org``
        appears in the output as ``example/org!user/john``.

.. parsed-literal::

    **mbexamine** *user/john@example.org*

..

        Examine the mailbox for the two restored messages.

.. only:: html

    ::

        (...snip...)
        000001> UID:00278862   INT_DATE:1425728572 SENTDATE:1425726000 SIZE:2545
            > HDRSIZE:2259   LASTUPD :1425912731 SYSFLAGS:00000014   LINES:6
            > CACHEVER:3  GUID:95349cd5d1cf21b55e6e0930b2ee5754f977ba8c MODSEQ:274250 CID: 0
            > USERFLAGS: 00000000 00000000 00000000 00000000
        Envel>{369}("Sat,  7 Mar 2015 11:42:47 +0000 (UTC)" "pghmcfc submitted milter-greylist-4.5.12-2.el7 to testing" (...snip...)
        BdyStr>{76}("TEXT" "PLAIN" ("CHARSET" "us-ascii") NIL NIL "7BIT" 286 6 NIL NIL NIL NIL)
        Body>{60}("TEXT" "PLAIN" ("CHARSET" "us-ascii") NIL NIL "7BIT" 286 6)
        CacHdr>{98}X-Spam-Score: -6.909
        Message-Id: <20150307114247.3829C6087DAC@bastion01.phx2.fedoraproject.org>

        From>{33}<notifications@fedoraproject.org>
        To>{32}<john+fedora@example.org>
        Cc>{0}
        Bcc>{0}
        Subjct>{59}"pghmcfc submitted milter-greylist-4.5.12-2.el7 to testing"
        000001> UID:00278863   INT_DATE:1425728573 SENTDATE:1425726000 SIZE:2548
            > HDRSIZE:2260   LASTUPD :1425912743 SYSFLAGS:00000014   LINES:6
            > CACHEVER:3  GUID:e503646e389f507777fb75eeacc2da0d2156016a MODSEQ:274251 CID: 0
            > USERFLAGS: 00000000 00000000 00000000 00000000
        Envel>{370}("Sat,  7 Mar 2015 11:42:51 +0000 (UTC)" "pghmcfc submitted milter-greylist-4.5.12-2.fc20 to testing" (...snip...)
        BdyStr>{76}("TEXT" "PLAIN" ("CHARSET" "us-ascii") NIL NIL "7BIT" 288 6 NIL NIL NIL NIL)
        Body>{60}("TEXT" "PLAIN" ("CHARSET" "us-ascii") NIL NIL "7BIT" 288 6)
        CacHdr>{98}X-Spam-Score: -6.909
        Message-Id: <20150307114251.A0E716087DAC@bastion01.phx2.fedoraproject.org>

        From>{33}<notifications@fedoraproject.org>
        To>{32}<john+fedora@example.org>
        Cc>{0}
        Bcc>{0}
        Subjct>{60}"pghmcfc submitted milter-greylist-4.5.12-2.fc20 to testing"
        (...snip...)

.. parsed-literal::

    **unexpunge -u -d** *user.johnsmith 46908*

..

        Unexpunge a select message based on its UID, clearing the
        *\\Deleted* flag.

.. parsed-literal::

    **unexpunge -a** *user.johnsmit.Trash*

..

        Unexpunge all messages in a user's Trash, but leave them
        flagged *\\Deleted*.

.. parsed-literal::

    **unexpunge -a -f** *\Flagged user.johnsmith.Trash*

..

        The same, but setting user flag *\\Flagged* to facilitate later
        bulk operations.

.. parsed-literal::

    **unexpunge -t** *24h* **-d -f** *\Flagged user.johnsmith*

..

        Unexpunge messages matching only a given time period.

.. parsed-literal::

    **unexpunge -t** *24h* **-d -f** *\Flagged user/johnsmith*

..

        The same command, supporting the ``unixhierarchysep: yes``
        option in :cyrusman:`imapd.conf(5)`.

Files
=====
/etc/imapd.conf

See Also
========
:cyrusman:`imapd.conf(5)`
