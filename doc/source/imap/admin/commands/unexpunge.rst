.. _imap-admin-commands-unexpunge:

=============
``unexpunge``
=============

Recover messages the user has (accidentally) deleted.

Synopsis
========

.. parsed-literal::

    unexpunge [-C config-file] -l mailbox
    unexpunge [-C config-file] -t time-interval [-d] [-v] [-f flagname] mailbox
    unexpunge [-C config-file] -a [-d] [-v] [-f flagname] mailbox
    unexpunge [-C config-file] -u [-d] [-v] [-f flagname] mailbox uid...

Description
===========

The ``unexpunge`` program is used to list or restore messages which have
been deleted from a mailbox, but still reside in the Cyrus IMAP mail
spool.

This utility is only useful when the server is configured with
``expunge_mode`` set to ``delayed`` in :manpage:`imapd.conf(5)`.

Options
=======

.. program:: unexpunge

.. option:: -C config-file

    |cli-dash-c-text|

.. option:: -l

    List the messages that have been expunged but are still available on
    the filesystem.

.. option:: -t time-interval

    Unexpunge messages which where expunged within the last
    ``time-interval`` seconds.

    Use one of the modifiers ``m`` (minutes), ``h`` (hours), ``d``
    (days), ``w`` (weeks) to specify a different time unit.

.. option:: -a

    Unexpunge all of the expunged messages in the specified mailbox.

.. option:: -u

    Only restore the messages with the UIDs specified as a space-
    separated list at the end of the command invocation.

.. option:: -d

    Not only unexpunge the messages, but also remove the ``\\Deleted``
    flag.

.. option:: -f flagname

    Set the user flag ``flagname`` on the messages restored, making it
    easier for the user(s) to find the restored messages and operate on
    them (in a batch).

.. option:: -v

    Enable verbose output/logging.

Examples
========

List the messages that are expunged and could be restored for mailbox
``user/john@example.org``:

.. parsed-literal::

    # :command:`/usr/lib/cyrus-imapd/unexpunge -l user/john@example.org`
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

Unexpunge two of these messages:

.. parsed-literal::

    # :command:`/usr/lib/cyrus-imapd/unexpunge -u user/john@example.org 278787 278788`
    restoring expunged messages in mailbox 'example/org!user/john'
    restored 2 expunged messages

.. NOTE::

    Note that the output of the unexpunge command is not completely
    consistent with the expected result of:

    .. parsed-literal::

        # :command:`/usr/lib/cyrus-imapd/unexpunge -u user/john@example.org 278787 278788`
        restoring expunged messages in mailbox 'user/john@example.org'
        restored 2 expunged messages

Examine the mailbox for the two restored messages:

.. parsed-literal::

    # :command:`/usr/lib/cyrus-imapd/mbexamine user/john@example.org`
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

See Also
========
