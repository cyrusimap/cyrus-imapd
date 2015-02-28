Deleting and Undeleting Messages and Folders
============================================

Terminology & Definitions
-------------------------

This section clarifies some of the subtle nuances between delete, expunge and expire in different contexts, used throughout this chapter.

Message context
+++++++++++++++

.. glossary::
    Delete
        sets the \\Deleted flag on the message using STORE +Flags \\Deleted via IMAP client 

.. glossary::
    Expunge
        delete messages from the cyrus folder index that have the \\Deleted flag set using EXPUNGE via IMAP client. With **expunge_mode: delayed**, this doesn't delete the file from the filesystem 

.. glossary::
    Unexpunge
        recover messages into the cyrus folder index based on filesystem content (only possible with **expunge_mode: delayed**) 

.. glossary::
    Undelete
        remove the \\Deleted flag on the message using STORE -Flags \\Deleted via IMAP client 

Folder context
++++++++++++++

.. glossary::
    Delete
        deletes the folder and all messages inside it using DELETE via IMAP client. If using **delete_mode: delayed**, this renames the folder as discussed below. Otherwise, the folder and messages are removed from the mailbox list and the filesystem. 

.. glossary::
    Undelete
        rename the deleted folder back to the original location using renamemailbox in cyradm 

Expiring Deleted Messages and Folders
-------------------------------------

In the EVENTS block of cyrus.conf, you should have a line similar to the following::

    delprune  cmd="cyr_expire -E 1 -D 7 -X 7 -a" at=2300

-D 7
    permanently deletes from the filesystem mailboxes and folders that were deleted more than 7 days ago. 
-E 1
    prunes entries older than 1 day from the duplicate delivery suppression database. 
-X 7
    permanently deletes from the filesystem expunged messages that were expunged more than 7 days ago. 

To use delayed deletion of mailboxes, you need the following entry in imapd.conf and a version at least 2.3.9::

    delete_mode: delayed

The default prefix for deleted mailboxes is DELETED but it probably doesn't hurt to specify it in imapd.conf as well::

    deletedprefix: DELETED

Undeleting Folders
------------------

The following assumes that unixhierarchysep is on. If it's off then replace '/' in the names with '.'

With the previous configuration options in place, whenever a mail folder or mailbox is deleted, it will be renamed to DELETED/mailfoldername/4D5C6B7A where 4D5C6B7A is a hex-encoded timestamp and DELETED/ is the prefix for deleted mailboxes.

4D5C6B7A can be converted back to a human-readable time using a simple one-liner in Perl::

    $ perl -le 'print scalar(localtime(hex("4D5C6B7A")));'
    Thu Feb 17 00:27:38 2011

.. note:: **ACL Entries on the Deleted Folder**

    The ACL on the deleted folder remains the same so undeleting it is as simple as renaming it as a sub-folder of the recreated mailbox or back to the original folder name depending on whether the mailbox has been recreated or not. If you have to add an ACL to be able to delete the mailbox, you may wish to remove the ACL after the undelete has been finished.

The following examples assume a mailbox for info@example.com has been deleted::

    cyradm> listmailbox user/info*@example.com

If there's no output from the above command, the mailbox has not been recreated since being deleted and you can rename the mailbox and any folders back to the original name as follows. If the mailbox has been recreated, you will probably want to rename the deleted folders into a subfolder of the new mailbox, for example user/info/4D88AF31@example.com becomes user/info/restored@example.com and user/info/Sent/4D88AF34@example.com becomes user/info/restored/Sent@example.com

In either case the commands are similar but with the latter option you need to insert the extra "/restored" after the user/info:

::

    cyradm> listmailbox DELETED/user/info*@example.com
    DELETED/user/info/4D88AF31@example.com (\HasNoChildren)
    DELETED/user/info/Drafts/4D88AF34@example.com (\HasNoChildren)
    DELETED/user/info/Sent/4D88AF34@example.com (\HasNoChildren)
    DELETED/user/info/Trash/4D88AF35@example.com (\HasNoChildren)
    cyradm> renamemailbox DELETED/user/info/4D88AF31@example.com user/info@example.com
    cyradm> renamemailbox DELETED/user/info/Drafts/4D88AF34@example.com user/info/Drafts@example.com
    cyradm> renamemailbox DELETED/user/info/Sent/4D88AF34@example.com user/info/Sent@example.com
    cyradm> renamemailbox DELETED/user/info/Trash/4D88AF35@example.com user/info/Trash@example.com

Unfortunately there's no easy way to rename the entire mailbox back including all the subfolders and the hex timestamp can vary between folders in the same mailbox if it was a mailbox with some large folders. This is because it's the time that particular folder was deleted, not when the first folder was deleted.

Recursively undeleting a mailbox and all subfolders: http://git.kolab.org/pykolab/tree/pykolab/imap/cyrus.py. 

Undeleting messages in a mailbox
--------------------------------

The following examples assume you have an installation of cyrus where there are binaries in /usr/lib/cyrus-imapd/ - if not, adjust path to suit.

List messages available to unexpunge:

::

    # su cyrus -c "/usr/lib/cyrus-imapd/unexpunge -l user/simon@example.org"

Each message will give you something like the following:

::

    UID: 11422
        Size: 7786
        Sent: Mon Mar 10 12:00:00 2014
        Recv: Mon Mar 10 16:06:32 2014
        Expg: Mon Mar 10 16:53:55 2014
        From: john doe <john.doe@example.com>
        To  : <info-cyrus@lists.andrew.cmu.edu>
        Cc  : 
        Bcc : 
        Subj: {44}
    re: some random subject of length 44 chars."

To unexpunge a single message:

::

    # su cyrus -c "/usr/lib/cyrus-imapd/unexpunge -udv user/simon@example.org 11422"
    restoring expunged messages in mailbox 'user/simon@example.org'
    Unexpunged user/simon@example.org: 11422 => 11438
    restored 1 expunged messages

To unexpunge all the messages and mark them as undeleted as well:

::

    # su cyrus -c "/usr/lib/cyrus-imapd/unexpunge -adv user/simon@example.org"

.. note:: This isn't recursive. It will only restore the inbox.

To find other folders, ctl_mboxlist can be used.

::

    # su cyrus -c "/usr/lib/cyrus-imapd/ctl_mboxlist -d" | grep example.org
    example.org!user.simon    0 default simon@example.org   lrswipkxtecda   
    example.org!user.simon.Lists  0 default simon@example.org   lrswipkxtecda   
    example.org!user.simon.Lists.cyrus    0 default simon@example.org   lrswipkxtecda   
    example.org!user.simon.Deleted Messages   0 default simon@example.org   lrswipkxtecda   

Run the unexpunge command for every folder that needs to have mail undeleted.

For folder names that have spaces ' ', the spaces need to be escaped with a backslash

::

    # su cyrus -c "/usr/lib/cyrus-imapd/unexpunge -adv user/simon/Deleted\ Messages@example.org"

