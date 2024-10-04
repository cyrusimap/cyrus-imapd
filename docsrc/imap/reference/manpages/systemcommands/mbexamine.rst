.. cyrusman:: mbexamine(8)

.. author: Nic Bernstein (Onlight)

.. _imap-reference-manpages-systemcommands-mbexamine:

=============
**mbexamine**
=============

Examine a cyrus-format mailbox

Synopsis
========

.. parsed-literal::

    **mbexamine** [ **-C** *config-file* ] [ **-u** *uid* ] *mailbox*...
    **mbexamine** [ **-C** *config-file* ] [ **-s** *seqnum*] *mailbox*...
    **mbexamine** [ **-C** *config-file* ] **-q** *mailbox*...
    **mbexamine** [ **-C** *config-file* ] **-c** *mailbox*...

Description
===========

**mbexamine** will examine the header, index, and cache files of a
cyrus format mailbox and dump the information contained therein.  It
can also limit its output to a specific uid or sequence number, through
use of the **-s** and **-u** switches.

**mbexamine** |default-conf-text| It uses
<configdirectory>/mailboxes.db to locate the mailbox on disk.

Options
=======

.. program:: mbexamine

.. option:: -C config-file

    |cli-dash-c-text|

.. option:: -u  uid, --uid=uid

    Dump information for the given uid only.

.. option:: -s  seqnum, --seq=seqnum

    Dump information for the given sequence number only.

.. option:: -q, --check-quota

    Compare the quota usage in cyrus.index to the actual message file
    sizes and report any differences.  If there are differences, the
    mailbox SHOULD be reconstructed.

.. option:: -c, --check-message-files

    Compare the records in cyrus.index to the actual message files
    report any differences.  This can help detect issues if messages
    files were manipulated manually and/or restored incorrectly.

Examples
========

.. parsed-literal::

    **mbexamine** *user.jsmith*

..

        Examine the mailbox hierarchy rooted at *user.jsmith*.

.. only:: html

    ::

        Examining user.jsmith...
         Mailbox Header Info:
          Path to mailbox: /var/spool/cyrus/user/jsmith
          Mailbox ACL: jsmith	lrswipkxtecda
          Unique ID: 3ab4f8d5512e33b1
          User Flags: [none]

         Index Header Info:
          Generation Number: 0
          Minor Version: 12
          Header Size: 128 bytes  Record Size: 96 bytes
          Number of Messages: 9  Mailbox Size: 35955 bytes
          Last Append Date: (1404765874) Mon Jul  7 20:44:34 2014
          UIDValidity: 1404761793  Last UID: 9
          Deleted: 0  Answered: 0  Flagged: 0
          Mailbox Options: POP3_NEW_UIDL
          Last POP3 Login: (0) Thu Jan  1 00:00:00 1970
          Highest Mod Sequence: 15

         Message Info:
        000001> UID:00000001   INT_DATE:1361982429 SENTDATE:1361966400 SIZE:6762
              > HDRSIZE:1443   LASTUPD :1361982447 SYSFLAGS:00000010   LINES:125
              > CACHEVER:3  GUID:69bdb40dac9de4d17057a5245c34544f2d6849db MODSEQ:3
              > USERFLAGS: 00000000 00000000 00000000 00000000
        <...>

.. parsed-literal::

    **mbexamine -u** *00000004 user.jsmith*

..

        Examine the mailbox hierarchy rooted at *user.jsmith* looking
        for messages with UID = *00000004*.

.. only:: html

    ::

        Examining user.jsmith...
         Mailbox Header Info:
          Path to mailbox: /var/spool/cyrus/user/jsmith
          Mailbox ACL: jsmith	lrswipkxtecda
          Unique ID: 3ab4f8d5512e33b1
          User Flags: [none]

         Index Header Info:
          Generation Number: 0
          Minor Version: 12
          Header Size: 128 bytes  Record Size: 96 bytes
          Number of Messages: 9  Mailbox Size: 35955 bytes
          Last Append Date: (1404765874) Mon Jul  7 20:44:34 2014
          UIDValidity: 1404761793  Last UID: 9
          Deleted: 0  Answered: 0  Flagged: 0
          Mailbox Options: POP3_NEW_UIDL
          Last POP3 Login: (0) Thu Jan  1 00:00:00 1970
          Highest Mod Sequence: 15

         Message Info:
        000001> UID:00000004   INT_DATE:1377891971 SENTDATE:1377864000 SIZE:4097
              > HDRSIZE:1771   LASTUPD :1377891971 SYSFLAGS:00000000   LINES:60
              > CACHEVER:3  GUID:dc814658a4d676789578bff3de35b45914abd774 MODSEQ:7
              > USERFLAGS: 00000000 00000000 00000000 00000000
        <...>

.. parsed-literal::

    **mbexamine -q** *user.jsmith*

..

        Examine the mailbox hierarchy rooted at *user.jsmith* checking
        quotas.

.. only:: html

    ::

        Examining user.jsmith...  Mailbox has CORRECT total quota usage
        Examining user.jsmith.Drafts...  Mailbox has CORRECT total quota usage
        Examining user.jsmith.Sent...  Mailbox has CORRECT total quota usage
        Examining user.jsmith.Spam...  Mailbox has CORRECT total quota usage
        Examining user.jsmith.Trash...  Mailbox has CORRECT total quota usage

.. parsed-literal::

    **mbexamine -c** *user.jsmith*

..

        Examine the mailbox hierarchy rooted at *user.jsmith* comparing
        index records to the actual message files in the mailbox directory.

.. only:: html

    ::

        Examining user.jsmith...
         Mailbox Header Info:
          Path to mailbox: /var/spool/cyrus/user/jsmith

         Index Record Info:                                     	Message File Info:
          UID: 00000002
           GUID: 4aa62f540d81395dc7d52518ae8e8c75571c8f11
           Size: 6964
           Date: Tue, 29 Nov 2016 12:00:00 -0500
           From: <foo@example.com>
           Subj: "Re: hello there"

          UID: 00000011
           GUID: 6aa93fd583f143dde555184d508ab0916e06b026          	739232245980a3efe3df490841221a4b7bac4f27
           Size: 21427                                             	23450
           Date: Wed, 30 Nov 2016 12:00:00 -0500                   	Wed, 26 Oct 2005 12:00:00 -0400
           From: <bar@example.com>                              	<foo@example.com>
           Subj: "Re: what's up?"                               	"hello there"

          UID: 00000022
           GUID:                                                   	12a62f123451395dc7d52518ae8e8c75571c9876
           Size:                                                   	5623
           Date:                                                   	Tue, 29 Mar 2016 12:00:00 -0500
           From:                                                   	<foo@example.com>
           Subj:                                                   	"Re: vacation"

Files
=====

/etc/imapd.conf,
<configdirectory>/mailboxes.db

See Also
========

:cyrusman:`imapd.conf(5)`
