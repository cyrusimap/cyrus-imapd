Overview
========

This chapter gives an overview of several aspects of the Cyrus IMAP server, as they relate to deployment.

Access Control Lists
--------------------

Access to each mailbox is controlled by each mailbox's access control list. Access Control Lists (ACLs) provide a powerful mechanism for specifying the users or groups of users who have permission to access the mailboxes.

An ACL is a list of zero or more entries. Each entry has an identifier and a set of rights. The identifier specifies the user or group of users for which the entry applies. The set of rights is one or more letters or digits, each letter or digit conferring a particular privilege.

Working with ACLs
"""""""""""""""""

ACLs are manipulated via these subcommands within the
:cyrusman:`cyradm(8)` program:

    * :ref:`imap-reference-manpages-systemcommands-cyradm-setaclmailbox`
    * :ref:`imap-reference-manpages-systemcommands-cyradm-listaclmailbox`
    * :ref:`imap-reference-manpages-systemcommands-cyradm-deleteaclmailbox`

Sample ACL
""""""""""

A typical ACL is expressed like this:

.. parsed-literal::

    **setaclmailbox** *mailbox* *id* *rights* [*id* *rights* ...]

where *mailbox* is the name of the mailbox to which the ACL is applied,
*id* is the identifier for the user or group for which the ACL applies,
and *rights* is a concatenated list of Access Rights from the list below.

A real world example may look like this:

::

    setaclmailbox user/bovik/public bovik all group:users lrsp anyone lrs

Here's some samples, illustrated via output from the ``listaclmailbox``
command in :cyrusman:`cyradm(8)`:

.. parsed-literal::

    localhost> **listaclmamilbox tech/%**
    tech/Commits:
      group:tech lrswipkxtea
      anyone lrs
    tech/abuse:
      group:tech lrswipkxtecda
      anyone lrsp
    tech/security:
      anyone lrsp
      group:tech lrswipkxtecda
    tech/support:
      group:tech lrswipkxtecda
      anyone lrsp

    localhost> **listaclmamilbox user/ted/%**
    user/ted/Drafts:
      ted lrswipkxtecda
    user/ted/Sent:
      ted lrswipkxtecda
    user/ted/Sent Items:
      ted lrswipkxtecda
    user/ted/Spam:
      anyone p
      ted lrswipkxtecda
    user/ted/Trash:
      ted lrswipkxtecda


Access Rights
"""""""""""""

The following lists Access Rights that can be used in an Access Control List entry.

l
    The user may see that the mailbox exists (**lookup**).

r
    The user may read the mailbox (**read**).

    The user may select the mailbox, fetch data, perform searches, and copy messages from the mailbox.

s
    Keep per-user seen state (i.e. modify the "Seen" flag) (**setseen**).

    "Seen" and "Recent" flags are maintained per user.

w
    The user may modify flags and keywords other than "Seen" and "Deleted" (which are controlled by other access rights). (**write**)

i
    The user may insert (append) new messages into the mailbox
    (**insert**).

p
    The user may send email to the submission address for the mailbox
    (**post**).

    This right differs from the ``i`` (**insert**) right in that the delivery system inserts trace information into messages posted, whereas no delivery trace information is added to messages inserted (by move or copy).

c
    [**deprecated**: see ``k`` right, below.]

k
    The user may create new mailboxes in this mailbox, delete the current mailbox, or rename the mailbox (**create**).

x
    The user may delete the mailbox itself. (**deletembox**)

t
    The user may store the "Deleted" flag.  In other words, delete
    messages.  Unlike the ``d`` right, however, ``t`` does not confer
    expunge rights (**deletemsg**).

e
    The user may Expunge messages which have the "Deleted" flag already
    set (**expunge**).  Unlike the ``d`` right, however, ``e`` does not
    confer delete rights.

d
    The user may store the "Deleted" flag, and perform expunges.  This
    "legacy" right is treated by the software as a macro for ``te``
    (**deletemsg** && **expunge**).

n
    The user may store annotations for a message (**annotatemsg**)

a
    The user may change the *Access Control Information* (ACI) on the mailbox (**administer**).

.. todo::
    FIXME: Clarification Needed! Does the ``a`` right imply any other rights?


You can combine these access rights in different ways. A few examples;

lrs
    Give the user read-only access to the mailbox (*lookup*, *read* and *seen*).

lrsp
    Give the user read access to the mailbox, and allow the user to post to the mailbox using the delivery system (*lookup*, *read*, *seen* and *post*). Most delivery systems do not provide authentication, so the ``p`` right usually has meaning only for the "anonymous" user.

lr
    The user can lookup and read the contents of the mailbox, but no "Seen" or "Recent" flags may be set on the mailbox nor its contents. This set of rights is primarily useful for anonymous IMAP, which is often used to make the archives of mailing lists available.

rs
    The user can read the mailbox and the server preserves the "Seen" and "Recent" flags, but the mailbox is not visible to the user through the various mailbox listing commands. The user must know the name of the mailbox to be able to access it.

lrsip
    The user can read and append to the mailbox, either through IMAP, or through the delivery system.

Finally, there are some short-hand macros you may use:

none
    Remove any existing ACL for this identifier

read (lrs)
    Give the user read-only access to the mailbox (*lookup*, *read* and *seen*).

post (lrsp)
    Give the user read access to the mailbox, and allow the user to
    post to the mailbox using the delivery system (*lookup*, *read*,
    *seen* and *post*). Most delivery systems do not provide
    authentication, so the ``p`` right usually has meaning only for the
    "anonymous" user.

append (lrsip)
    The user can read and append to the mailbox, either through IMAP,
    or through the delivery system.

write (lrswipkxtecd)
    The user may do pretty much anything with a mailbox, and folders
    within it.

delete (lrxte)
    The user may list, read, delete and expunge messages and delete folders.

all (lrswipkxtecda)
    Same as write, plus admin rights.

Identifiers
"""""""""""

The identifier part of an ACL entry specifies the user or group for
which the entry applies.  Group identifiers are distinguished be the
prefix "group:".  For example, "group:accounting".

.. todo:: FIXME: Clarify what an ACL entry looks like first. Refer to how user login names are translated into their identifiers, and (in that section) refer to altnamespace, unixhiersep, default domain, virtdomains, sasl_auth_mech tips and tricks etc.

There are two special identifiers, "anonymous", and "anyone", which are explained below. The meaning of other identifiers usually depends on the authorization mechanism being used (selected by ``--with-auth`` at compile time, defaulting to Unix).

``anonymous`` and ``anyone``
""""""""""""""""""""""""""""

With any authorization mechanism, two special identifiers are defined.
The identifier ``anonymous`` refers to the anonymous, or unauthenticated
user. The identifier ``anyone`` refers to all users, including the
anonymous user.

Both ``anonymous`` and ``anyone`` may commonly be used with the **post**
right ``p`` to allow message insertion to mailboxes.


Kerberos vs. Unix Authorization
"""""""""""""""""""""""""""""""

The Cyrus IMAP server comes with four authorization mechanisms, one is compatible with Unix-style (``/etc/passwd``) authorization, one for use with Kerberos 4, one for use with Kerberos 5, and one for use with an external authorization process (ptloader) which can interface with other group databases (e.g. AFS PTS groups, LDAP Groups, etc).

.. note::
    **Authentication !== Authorization**

    Note that authorization is *not* the same thing as authentication. Authentication is the act of proving who you are. Authorization is the act of determining what rights you have. Authentication is discussed in the Login Authentication part of this document.

.. todo::
   In the paragraph above, make sure 'Login Authentication' links to the appropriate section.

In the Unix authorization mechanism, identifiers are either a valid userid or the string ``group:`` followed by a group listed in ``/etc/group``. Thus:

::

    root                Refers to the user root
    group:staff         Refers to the group staff


It is also possible to use unix groups with users authenticated through a non-/etc/passwd backend. Note that using unix groups in this way (without associated ``/etc/passwd`` entries) is not recommended.

.. todo::
    Actually, what Cyrus requires is the getgrent(3) POSIX sysctl. As such, NSS needs to be configured to have the groups available, one of which includes "files", but could also include "ldap".


Using the Kerberos authorization mechanism, identifiers are of the form:

    *$principal*.*$instance*@*$realm*

If ``$instance`` is omitted, it defaults to the null string. If ``$realm`` is omitted, it defaults to the local realm.


The file ``/etc/krb.equiv`` contains mappings between Kerberos principals. The file contains zero or more lines, each containing two fields. Any identity matching the first field of a line is changed to the second identity during canonicalization. For example, a line in ``/etc/krb.equiv`` of:

::

    bovik@REMOTE.COM bovik

will cause the identity ``bovik@REMOTE.COM`` to be treated as if it were the local identity ``bovik``.

A site may wish to write their own authorization mechanism, perhaps to implement a local group mechanism. If it does so (by implementing an ``auth_[whatever]`` PTS module), it will dictate its own form and meaning of identifiers.


Negative Rights
"""""""""""""""

Any of the above defined identifiers may be prefixed with a ``-`` character. The associated rights are then removed from that identifier. These are referred to as *negative rights*.

Calculating the Users' Rights
"""""""""""""""""""""""""""""

To calculate the set of rights granted to a user, the server first calculates the union of all of the rights granted to the user and to all groups the user is a member of. The server then calculates and removes the union of all the negative rights granted to the user and to all groups the user is a member of.

::

   anyone       lrsp
   fred         lwi
   -anonymous   s

The user ``fred`` will be granted the rights ``lrswip`` and the anonymous user will be granted the rights ``lrp``.

Implicit Rights for Administrators on Personal Mailboxes
""""""""""""""""""""""""""""""""""""""""""""""""""""""""

Regardless of the ACL on a mailbox, users who are listed in the "admins" configuration option in :cyrusman:`imapd.conf(5)` implicitly have the ``l`` and ``a`` rights on all mailboxes. Users also implicitly have the ``l`` and ``a`` rights on their INBOX and all of their personal mailboxes.


Initial ACLs for Newly Created Mailboxes
""""""""""""""""""""""""""""""""""""""""

When a mailbox is created, its ACL starts off with a copy of the ACL of its closest parent mailbox. When a user is created, the ACL on the user's ``INBOX`` starts off with a single entry granting all rights to the user. When a non-user mailbox is created and does not have a parent, its ACL is initialized to the value of the ``defaultacl`` option in :cyrusman:`imapd.conf(5)`.

Note that some rights are available implicitly, for example 'anonymous'
always has 'p' on user INBOXes, and users always have ``la`` rights on
mailboxes within their INBOX hierarchy.


Login Authentication
--------------------

This section discusses different types of authentication (ways of logging in) that can be used with Cyrus IMAP.

The Cyrus IMAP server uses the Cyrus SASL library for authentication. This section describes how to configure SASL with use with Cyrus imapd. Please consult the :ref:`Cyrus SASL System Administrator's Guide <cyrussasl:sasl-index>` for more detailed, up-to-date information.

Anonymous Login
"""""""""""""""

Regardless of the SASL mechanism used by an individual connection, the
server may support anonymous login. If the ``allowanonymouslogin``
option in :cyrusman:`imapd.conf(5)` is turned on, then the server will
permit plaintext password logins using the user ``anonymous`` and any
password.

Additionally, the server will enable any SASL mechanisms that allow anonymous logins.

Plaintext Authentication
""""""""""""""""""""""""

The SASL library has several ways of verifying plaintext passwords. Plaintext passwords are passed either by the IMAP ``LOGIN`` command or by the SASL ``PLAIN`` mechanism (under a TLS layer).

* PAM
* Kerberos v4: Plaintext passwords are verified by obtaining a ticket for the server's Kerberos identity, to protect against Kerberos server spoofing attacks.

* ``/etc/passwd``
* ``/etc/shadow``: ``sasl_auto_transition`` automatically creates secrets for shared secret authentication when given a password.

The method of plaintext password verification is always through the SASL library, even in the case of the internal LOGIN command. This is to allow the SASL library to be the only source of authentication information. You'll want to look at the ``sasl_pwcheck_method`` option in the SASL documentation to understand how to configure a plaintext password verifier for your system.

To disallow the use of plaintext passwords for authentication, you can set ``allowplaintext: no`` in imapd.conf. This will still allow PLAIN under TLS, but IMAP LOGIN commands will now fail.

Kerberos Logins
"""""""""""""""

The Kerberos SASL mechanism supports the ``KERBEROS_V4`` authentication mechanism. The mechanism requires that a ``srvtab`` file exist in the location given in the ``srvtab`` configuration option. The ``srvtab`` file must be readable by the Cyrus server and must contain a ``imap.$host@$realm`` service key, where ``$host`` is the first component of the server's host name and ``$realm`` is the server's Kerberos realm.

The server will permit logins by identities in the local realm and identities in the realms listed in the ``loginrealms`` option in :cyrusman:`imapd.conf(5)`.

The file ``/etc/krb.equiv`` contains mappings between Kerberos principals. The file contains zero or more lines, each containing two fields. Any identity matching the first field of a line is permitted to log in as the identity in the second field.

If the ``loginuseacl`` configuration option is turned on, than any Kerberos identity that is granted the ``a`` right on the user's ``INBOX`` is permitted to log in as that user.

Shared Secrets Logins
"""""""""""""""""""""

Some mechanisms require the user and the server to share a secret (generally a password) that can be used for comparison without actually passing the password in the clear across the network. For these mechanism (such as CRAM-MD5 and DIGEST-MD5), you will need to supply a source of passwords, such as the sasldb (which is described more fully in the :ref:`Cyrus SASL distribution <cyrussasl:sasl-index>`)

Quota
-----

Quotas allow server administrators to limit resources used by hierarchies of mailboxes on the server.

Working with Quotas
"""""""""""""""""""

Quotas are manipulated via these subcommands within the
:cyrusman:`cyradm(8)` program:

    * :ref:`imap-reference-manpages-systemcommands-cyradm-setquota`
    * :ref:`imap-reference-manpages-systemcommands-cyradm-listquota`
    * :ref:`imap-reference-manpages-systemcommands-cyradm-listquotaroot`

Supported Quota Types
"""""""""""""""""""""

The Cyrus IMAP server supports quotas on Storage (KB), Messages (#),
Folders (#) and Annotation Storage (KB).  These types each have their
own identifier:

    * STORAGE
    * MESSAGE
    * X-NUM-FOLDERS
    * X-ANNOTATION-STORAGE

Quota Roots
"""""""""""

Quotas are applied to quota roots, which can be at any level of the mailbox hierarchy. Quota roots need not also be mailboxes.

Quotas on a quota root apply to the sum of the usage of any mailbox at that level and any sub-mailboxes of that level that are not underneath a quota root on a sub-hierarchy. This means that each mailbox is limited by at most one quota root.

For example, if the mailboxes

::

   user/bovik
   user/bovik/list/imap
   user/bovik/list/info-cyrus
   user/bovik/saved
   user/bovik/todo

exist and the quota roots

::

   user/bovik
   user/bovik/list
   user/bovik/saved

exist, then the quota root ``user/bovik`` applies to the mailboxes ``user/bovik`` and ``user/bovik/todo``; the quota root ``user/bovik/list`` applies to the mailboxes ``user/bovik/list/imap`` and ``user/bovik/list/info-cyrus``; and the quota root ``user/bovik/saved`` applies to the mailbox ``user/bovik/saved``.

Quota roots are created automatically when they are mentioned in the
:ref:`imap-reference-manpages-systemcommands-cyradm-setquota` command. Quota
roots may not be deleted through the protocol, see Removing Quota Roots
for instructions on how to delete them.

Storage Quotas
""""""""""""""

Storage quotas are defined as the number of kilobytes (KB) of the
relevant :rfc:`822` messages located within a quota root. Each copy of
a message is counted independently, even when the server can conserve
disk space use by making hard links to message files. The additional
disk space overhead used by mailbox index and cache files is not
charged against a quota. On servers with ``delete_mode: delayed``
and/or ``expunge_mode:delayed`` space used by deleted mailboxes or
expunged messages are not charged against quota.

Numeric Quotas
""""""""""""""

Numeric Quotas are quite simply a limit on the number of a particular
class of object.  Cyrus IMAP currently supports quotas on the number of
messages and/or folders below a given quota root.

Controlling Quota Behavior
""""""""""""""""""""""""""

How restrictive quotas will be may be tailored to the needs of different
sites, via the use of several settings in :cyrusman:`imapd.conf(5)`:

    .. include:: /imap/reference/manpages/configs/imapd.conf.rst
        :start-after: startblob lmtp_over_quota_perm_failure
        :end-before: endblob lmtp_over_quota_perm_failure


    .. include:: /imap/reference/manpages/configs/imapd.conf.rst
        :start-after: startblob lmtp_strict_quota
        :end-before: endblob lmtp_strict_quota


    .. include:: /imap/reference/manpages/configs/imapd.conf.rst
        :start-after: startblob quotawarn
        :end-before: endblob quotawarn


    .. include:: /imap/reference/manpages/configs/imapd.conf.rst
        :start-after: startblob quotawarnkb
        :end-before: endblob quotawarnkb


    .. include:: /imap/reference/manpages/configs/imapd.conf.rst
        :start-after: startblob quotawarnmsg
        :end-before: endblob quotawarnmsg


    .. include:: /imap/reference/manpages/configs/imapd.conf.rst
        :start-after: startblob autocreate_quota
        :end-before: endblob autocreate_quota


    .. include:: /imap/reference/manpages/configs/imapd.conf.rst
        :start-after: startblob autocreate_quota_messages
        :end-before: endblob autocreate_quota_messages


Mail Delivery Behavior
""""""""""""""""""""""

Normally, in order for a message to be inserted into a mailbox, the
quota root for the mailbox must have enough unused storage so that
inserting the message will not cause the block quota to go over the
limit.

Mail delivery is a special case. In order for a message to be delivered
to a mailbox, the quota root for the mailbox must not have usage that
is over the limit

As long as usage is not over the limit, new messages may be delivered
regardless of size, unless ``lmtp_strict_quota: on`` is set in
:cyrusman:`imapd.conf(5)`.  In that case, delivery of messages will be
rejected would such delivery exceed quota.

If a delivery puts the mailbox's usage over the quota, the server will
issue an alert notifying the user that usage is close to or over the
limit, permitting them to correct it. If delivery were not permitted in
this case, the user would have no practical way of knowing that there
was mail that could not be delivered.

.. note::

    While the Cyrus IMAP server may from time to time issue alerts,
    there is great variability in how IMAP clients handle these.  Many
    sites find it preferable to install cron jobs which use the
    :cyrusman:`quota(8)` command to produce periodic reports of users
    at or near quota, so administrators may nag them or so that
    warnings may be issued to users via some other mechanism.

If the usage is over the limit, mail delivery will fail with a temporary
error (LMTP error 452), unless ``lmtp_over_quota_perm_failure: on``
is set in :cyrusman:`imapd.conf(5)` in which case a permanent error
(LMTP error 552) will be returned.

A temporary error will *typically* cause the delivery system to requeue
the message and re-attempt delivery for a few days (permitting the user
time to notice and correct the problem) before returning the mail to
the sender.

.. Note::

    Such requeuing behaviour is controlled by the MTA (i.e. Sendmail,
    EXIM or Postfix) and as such is outside the purview of this
    document.

Quota Warnings Upon Select When User Has ``d`` Rights
"""""""""""""""""""""""""""""""""""""""""""""""""""""

When a user selects a mailbox whose quota root has usage that is close to or over the limit and the user has ``d`` rights on the mailbox, the server will issue an alert notifying the user that usage is close to or over the limit. The threshold of usage at which the server will issue quota warnings is set by the ``quotawarn`` configuration option.

The server only issues warnings when the user has ``d`` rights because only users with ``d`` rights are capable of correcting the problem.

Quotas and Partitions
"""""""""""""""""""""

Quota roots are independent of partitions. A single quota root can apply to mailboxes in different partitions.

Quota Database
""""""""""""""

Quota information is stored either in a database (i.e. twoskip,
skiplist) or in "quotalegacy" format, which is a filesystem hierarchy.
This is controlled by the ``quota_db`` setting in
:cyrusman:`imapd.conf(5)`.  Here's more about the pertinent settings:

    .. include:: /imap/reference/manpages/configs/imapd.conf.rst
        :start-after: startblob quota_db
        :end-before: endblob quota_db

    .. include:: /imap/reference/manpages/configs/imapd.conf.rst
        :start-after: startblob quota_db_path
        :end-before: endblob quota_db_path

The :cyrusman:`cvt_cyrusdb(8)` utility may be used to convert between
formats.  It's usage with ``quotalegacy`` is a special case, in that
the first argument ("<old db>") will be the path to the *base* of the
``quotalegacy`` directory structure, not to a particular file.

For example, given this typical layout:

::

    /var/lib/imap/
    |            /quota/
    |                  /A/
    |                    /user/
    |                         /bob/

The proper ``cvt_cyrusdb`` command would be:

::

    cvt_cyrusdb /var/lib/imap/quota quotalegacy /var/lib/imap/quotas.db twoskip



New Mail Notification
---------------------

The Cyrus IMAP server comes with a notification daemon which
supports multiple mechanisms for notifying users of new mail.
Notifications can be configured to be sent upon normal delivery
(``MAIL`` class) and/or sent as requested by a Sieve script (``SIEVE`` class).

By default, both types of notifications are disabled.
Notifications are enabled by using one or both of the following
configuration options:

* the ``mailnotifier`` option selects the :cyrusman:`notifyd(8)` method to use for ``MAIL`` class notifications

* the ``sievenotifier`` option selects the :cyrusman:`notifyd(8)` method to use for ``SIEVE`` class notifications (when no method is specified by the Sieve action)


Partitions
----------

Partitions allow administrators to store different mailboxes in different parts of the Unix filesystem.  This is intended to be used to allow hierarchies of mailboxes to be spread across multiple disks.

Specifying Partitions with "create"
"""""""""""""""""""""""""""""""""""

When an administrator creates a new mailbox, the name of the partition for the mailbox may be specified using an optional second argument to the "create" command.  Non-administrators are not permitted to specify the partition of a mailbox.  If the partition is not specified, then the mailbox inherits the partition of its most immediate parent mailbox.  If the mailbox has no parent, it gets the partition specified in the "defaultpartition" configuration option.

The optional second argument to the "create" command can usually be given only when using a specialized Cyrus-aware administrative client such as ``cyradm``.

Changing Partitions with "rename"
"""""""""""""""""""""""""""""""""

An administrator may change the partition of a mailbox by using the
rename command with an optional third argument.  When a third argument
to rename is given, the first and second arguments can be the
same; this changes the partition of a mailbox without changing its
name.  If a third argument to rename is not given and the first
argument is not ``INBOX``, the partition of a mailbox does not change.
If a third argument to rename is not given and the first argument is
``INBOX``, the newly created mailbox gets the same partition it would
get from the ``create`` command.

News
-----

Cyrus has the ability to export Usenet via IMAP and/or export shared
IMAP mailboxes via an NNTP server which is included with Cyrus.

POP3 Server
-----------

The Cyrus IMAP server software comes with a compatibility POP3 server.
Due to limitations in the POP3 protocol, the server can only access a
user's ``INBOX`` and only one instance of a POP3 server may exist for any
one user at any time.  While a POP3 server has a user's ``INBOX`` open,
expunge operations from any concurrent IMAP session will fail.

When Kerberos login authentication is being used, the POP3 server
uses the server identity
``pop.host@realm`` instead of
``imap.host@realm``, where
``host`` is the first component of the server's host
name and ``realm`` is the server's Kerberos realm.
When the POP3 server is invoked with the ``-k`` switch, the
server exports MIT's KPOP protocol instead of generic POP3.

The syslog facility
-------------------

The Cyrus IMAP server software sends log messages to the ``local6``
syslog facility.  The severity levels used are:

* **CRIT** - Critical errors which probably require prompt administrator action
* **ERR** - I/O errors, including failure to update quota usage. The syslog message includes the specific file and Unix error.
* **WARNING** - Protection mechanism failures, client inactivity timeouts
* **NOTICE** - Authentications, both successful and unsuccessful
* **INFO** - Mailbox openings, duplicate delivery suppression

Mail Directory Recovery
-----------------------

This section describes the various databases used by the Cyrus IMAP
server software and what can be done to recover from various
inconsistencies in these databases.

Reconstructing Mailbox Directories
""""""""""""""""""""""""""""""""""

The largest database is the mailbox directories.  Each
mailbox directory contains the following files:

message files
    There is one file per message, containing the message in :rfc:`822` format.  Lines in the message are separated by CRLF, not just LF.  The file name of each message is the message's UID followed by a dot (.).

    In netnews newsgroups, the message files instead follow the format and naming conventions imposed by the netnews software.

``cyrus.header``
    This file contains a magic number and variable-length information about the mailbox itself.

``cyrus.index``
    This file contains fixed-length information about the mailbox itself and each message in the mailbox.

``cyrus.cache``
    This file contans variable-length information about each message in the mailbox.

``cyrus.seen``
    This file contains variable-length state information about each reader of the mailbox who has ``s`` permissions.

The ``reconstruct`` program can be used to recover from
corruption in mailbox directories.  If ``reconstruct`` can find
existing header and index files, it attempts to preserve any data in
them that is not derivable from the message files themselves.  The
state ``reconstruct`` attempts to preserve includes the flag
names, flag state, and internal date.  ``Reconstruct``
derives all other information from the message files.

An administrator may recover from a damaged disk by restoring message
files from a backup and then running reconstruct to regenerate what it
can of the other files.

The ``reconstruct`` program does not adjust the quota usage
recorded in any quota root files.  After running reconstruct, it is
advisable to run ``quota -f`` (described below) in order to fix
the quota root files.

Reconstructing the Mailboxes File
"""""""""""""""""""""""""""""""""

.. note::

    CURRENTLY UNAVAILABLE

The mailboxes file in the configuration directory is the most critical
file in the entire Cyrus IMAP system.  It contains a sorted list of
each mailbox on the server, along with the mailboxes quota root and
ACL.

To reconstruct a corrupted mailboxes file, run the ``reconstruct
-m`` command.  The ``reconstruct`` program, when invoked
with the ``-m`` switch, scavenges and corrects whatever data it
can find in the existing mailboxes file.  It then scans all partitions
listed in the imapd.conf file for additional mailbox directories to
put in the mailboxes file.

The ``cyrus.header`` file in each mailbox directory stores a
redundant copy of the mailbox ACL, to be used as a backup when
rebuilding the mailboxes file.

Reconstructing Quota Roots
""""""""""""""""""""""""""

.. note::

    The following instructions are valid where ``quota_db: quotalegacy``
    is set in :cyrusman:`imapd.conf(5)`.  If your site uses a different
    quota DB type, then these steps do not apply.

The subdirectory ``quota`` of the configuration directory (specified in
the ``configdirectory`` configuration option) contains one file per
quota root, with the file name being the name of the quota root.  These
files store the quota usage and limits of each of the quota roots.

The ``quota`` program, when invoked with the ``-f``
switch, recalculates the quota root of each mailbox and the quota
usage of each quota root.

Removing Quota Roots
""""""""""""""""""""

To remove a quota root, remove the quota root's file.  Then run
``quota -f`` to make the quota files consistent again.

Subscriptions
"""""""""""""

The subdirectory ``user`` of the configuration directory contains user
subscriptions.  There is one file per user, with a filename of the
userid followed by ``.sub``.  Each file contains a sorted list of
subscribed mailboxes.

There is no program to recover from damaged subscription files.  A
site may recover from lost subscription files by restoring from backups.

Configuration Directory
-----------------------

Many objects in the configuration directory are discussed in
the Database Recovery section. This section documents two
other directories that reside in the configuration directory.

Log Directory
"""""""""""""

The subdirectory ``log`` under the configuration directory permits
administrators to keep protocol telemetry logs on a per-user basis.

If a subdirectory of ``log`` exists with the same name as a user, the
IMAP and POP3 servers will keep a telemetry log of protocol sessions
authenticating as that user.  The telemetry log is stored in the
subdirectory with a filename of the server process-id and starts with
the first command following authentication.

Proc Directory
""""""""""""""

The subdirectory ``proc`` under the configuration directory
contains one file per active server process.  The file name is the ASCII
representation of the process id and the file contains the following
tab-separated fields:

* hostname of the client
* login name of the user, if logged in
* selected mailbox, if a mailbox is selected

The file may contain arbitrary characters after the first newline
character.

The ``proc`` subdirectory is normally be cleaned out on
server reboot.

Message Delivery
----------------

Mail transport agents such as Sendmail, Postfix, or Exim communicate
with the Cyrus server via LMTP (the Local Mail Transport Protocol)
implemented by the LMTP daemon.  This can be done either directly by the
MTA (prefered, for performance reasons) or via the ``deliver`` LMTP
client.

Local Mail Transfer Protocol (lmtp)
"""""""""""""""""""""""""""""""""""

LMTP, the Local Mail Transfer Protocol, is a variant of SMTP design for
transferring mail to the final message store.  LMTP allows MTAs to deliver
"local" mail over a network.  This is an easy optimization so that the
IMAP server doesn't need to maintain a queue of messages or run an
MTA.

The Cyrus server implements LMTP via the ``lmtpd`` daemon.  LMTP
can either be used over a network via TCP or local via a UNIX domain
socket. There are security differnces between these two alternatives; read
more below.

For final delivery via LMTP over a TCP socket, it is necessary to use
LMTP AUTH.  This is accomplished using SASL to authenticate the delivering
user.  If your mail server is performing delivery via LMTP AUTH (that is,
using a SASL mechanism), you will want their authentication id to be an
LMTP admins (either via the ``admins`` imapd.conf option or via the
``<service>_admins`` option, typically ``lmtp_admins``).

Alternatively you may deliver via LMTP to a unix domain socket, and the
connection will be preauthenticated as an administrative user (and access
control is accomplished by controlling access to the socket).

Note that if a user has a sieve script, the sieve script runs authorized
as *that* user, and the rights of the posting user are ignored for the purposes
of determining the outcome of the sieve script.

Single Instance Store
"""""""""""""""""""""

If a delivery attempt mentions several recipients (only possible if
the MTA is speaking LMTP to ``lmtpd``), the server attempts to
store as few copies of a message as possible.  It will store one copy
of the message per partition, and create hard links for all other
recipients of the message.

Single instance store can be turned off by using the
"singleinstancestore" flag in the configuration file.

Duplicate Delivery Suppression
""""""""""""""""""""""""""""""

A message is considered a duplicate if two copies of a message with
the same message-id and the same envelope receipient are received.
Cyrus uses the duplicate delivery database to hold this information,
and it looks approximately 3 days back in the default install.

Duplicate delivery suppression can be turned off by using the
"duplicatesuppression" flag in the configuration file.

Sieve, a Mail Filtering Language
--------------------------------

Sieve is a mail filtering language that can filter mail into an appropriate
IMAP mailbox as it is delivered via lmtp.

Cyrus Murder, the IMAP Aggregator
---------------------------------

Cyrus now supports the distribution of mailboxes across a number of IMAP
servers to allow for horizontal scalability.
