########
Overview
########

This chapter gives an overview of several aspects of the Cyrus IMAP
server, as they relate to deployment.  In an effort to reduce
duplication of information, we will often direct you to documentation
in other areas.  Please do follow such referrals.

Access Control Lists
********************

Access to each mailbox is controlled by access control
lists. Access Control Lists (ACLs) provide a powerful mechanism for
specifying the users, or groups of users, who have permission to access
the mailboxes, and the degree of that access.

An ACL is a list of zero or more entries. Each entry contains a
mailbox, an Access Control Identifier (ACI) and a set of rights. The
ACI specifies the user or group of users for which the entry
applies. The set of rights is one or more letters or digits, each
letter or digit conferring a particular privilege.

Working with ACLs
=================

ACLs are manipulated via these subcommands within the
:cyrusman:`cyradm(8)` program:

    * :ref:`imap-reference-manpages-systemcommands-cyradm-setaclmailbox`
    * :ref:`imap-reference-manpages-systemcommands-cyradm-listaclmailbox`
    * :ref:`imap-reference-manpages-systemcommands-cyradm-deleteaclmailbox`

Sample ACL
==========

A typical ACL is expressed like this:

.. parsed-literal::

    **setaclmailbox** *mailbox* *id* *rights* [*id* *rights* ...]

where *mailbox* is the name of the mailbox to which the ACL is applied,
*id* is the ACI for the user or group for which the ACL applies, and
*rights* is a concatenated list of Access Rights from the list below.

A real world example may look like this:

::

    setaclmailbox user/bovik/public bovik all group:users lrsp anyone lrs

Here are samples illustrated via output from the ``listaclmailbox``
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

    localhost> **listaclmamilbox user/bovik/%**
    user/bovik/Drafts:
      bovik lrswipkxtecda
    user/bovik/Sent:
      bovik lrswipkxtecda
    user/bovik/Sent Items:
      bovik lrswipkxtecda
    user/bovik/Spam:
      anyone p
      bovik lrswipkxtecda
    user/bovik/Trash:
      bovik lrswipkxtecda

Access Rights
=============

The following lists Access Rights that can be used in an Access Control
List entry.

l
    The user may see that the mailbox exists (**lookup**).

r
    The user may read the mailbox (**read**).

s
    Keep per-user seen state (i.e. modify the "Seen" flag)
    (**setseen**).

w
    The user may modify flags and keywords other than "Seen" and
    "Deleted". (**write**)

i
    The user may insert (append) new messages into the mailbox
    (**insert**).

p
    The user may send email to the submission address for the mailbox
    (**post**).

c
    [**deprecated**: see ``k`` right, below.]

k
    The user may create new mailboxes in this mailbox, delete the
    current mailbox, or rename the mailbox (**create**).

x
    The user may delete the mailbox itself. (**deletembox**)

t
    The user may store the "Deleted" flag.  In other words, delete
    messages.
 
e
    The user may Expunge messages which have the "Deleted" flag already
    set (**expunge**).

d
    This "legacy" right is treated by the software as a macro for ``te``
    (**deletemsg** && **expunge**).

n
    The user may store annotations for a message (**annotatemsg**)

a
    The user may change the *Access Control Information* (ACI) on the
    mailbox (**administer**).

For a complete reference to Access Rights, please see
:ref:`imap-admin-access-control-lists-rights-reference`

Rights are combined through concatenation.  Please see
:ref:`imap-admin-access-control-combining-rights`

.. include:: /imap/reference/admin/access-control/defaults.rst
    :start-after: _imap-admin-access-control-defaults:

.. include:: /imap/reference/admin/access-control/identifiers.rst
    :start-after: _imap-admin-access-control-identifiers:

Negative Rights
===============

Any of the above defined identifiers may be prefixed with a ``-``
character. The associated rights are then removed from that identifier.
These are referred to as *negative rights*.

Calculating a Users' Rights
===========================

To calculate the set of rights granted to a user, the server first
calculates the union of all of the rights granted to the user and to
all groups the user is a member of. The server then calculates and
removes the union of all the negative rights granted to the user and to
all groups the user is a member of.

::

   anyone       lrsp
   fred         lwi
   -anonymous   s

The user ``fred`` will be granted the rights ``lrswip`` and the
anonymous user will be granted the rights ``lrp``.


.. _imap-concepts-login-authentication:

Login Authentication
********************

This section discusses different types of authentication (ways of logging in) that can be used with Cyrus IMAP.

The Cyrus IMAP server uses the Cyrus SASL library for authentication. This section describes how to configure SASL with use with Cyrus imapd. Please consult the :ref:`Cyrus SASL System Administrator's Guide <cyrussasl:sasl-index>` for more detailed, up-to-date information.

Anonymous Login
===============

Regardless of the SASL mechanism used by an individual connection, the
server may support anonymous login. If the ``allowanonymouslogin``
option in :cyrusman:`imapd.conf(5)` is turned on, then the server will
permit plaintext password logins using the user ``anonymous`` and any
password.

Additionally, the server will enable any SASL mechanisms that allow anonymous logins.

Plaintext Authentication
========================

The SASL library has several ways of verifying plaintext passwords. Plaintext passwords are passed either by the IMAP ``LOGIN`` command or by the SASL ``PLAIN`` mechanism (under a TLS layer).

* PAM
* Kerberos v4: Plaintext passwords are verified by obtaining a ticket for the server's Kerberos identity, to protect against Kerberos server spoofing attacks.

* ``/etc/passwd``
* ``/etc/shadow``: ``sasl_auto_transition`` automatically creates secrets for shared secret authentication when given a password.

The method of plaintext password verification is always through the SASL library, even in the case of the internal LOGIN command. This is to allow the SASL library to be the only source of authentication information. You'll want to look at the ``sasl_pwcheck_method`` option in the SASL documentation to understand how to configure a plaintext password verifier for your system.

To disallow the use of plaintext passwords for authentication, you can set ``allowplaintext: no`` in imapd.conf. This will still allow PLAIN under TLS, but IMAP LOGIN commands will now fail.

Kerberos Logins
===============

The Kerberos SASL mechanism supports the ``KERBEROS_V4`` authentication mechanism. The mechanism requires that a ``srvtab`` file exist in the location given in the ``srvtab`` configuration option. The ``srvtab`` file must be readable by the Cyrus server and must contain a ``imap.$host@$realm`` service key, where ``$host`` is the first component of the server's host name and ``$realm`` is the server's Kerberos realm.

The server will permit logins by identities in the local realm and identities in the realms listed in the ``loginrealms`` option in :cyrusman:`imapd.conf(5)`.

The file ``/etc/krb.equiv`` contains mappings between Kerberos principals. The file contains zero or more lines, each containing two fields. Any identity matching the first field of a line is permitted to log in as the identity in the second field.

If the ``loginuseacl`` configuration option is turned on, than any Kerberos identity that is granted the ``a`` right on the user's ``INBOX`` is permitted to log in as that user.

Shared Secrets Logins
=====================

Some mechanisms require the user and the server to share a secret (generally a password) that can be used for comparison without actually passing the password in the clear across the network. For these mechanism (such as CRAM-MD5 and DIGEST-MD5), you will need to supply a source of passwords, such as the sasldb (which is described more fully in the :ref:`Cyrus SASL distribution <cyrussasl:sasl-index>`)

Quotas
******

Quotas allow server administrators to limit resources used by hierarchies of mailboxes on the server.

Working with Quotas
===================

Quotas are manipulated via these subcommands within the
:cyrusman:`cyradm(8)` program:

    * :ref:`imap-reference-manpages-systemcommands-cyradm-setquota`
    * :ref:`imap-reference-manpages-systemcommands-cyradm-listquota`
    * :ref:`imap-reference-manpages-systemcommands-cyradm-listquotaroot`

..  include:: /imap/reference/admin/quotas.rst
    :start-after: _imap-admin-quotas-repair:
    :end-before: _imap-admin-quotas-config:

..  include:: /imap/reference/admin/quotas/quotatypes.rst
    :start-after: _imap-admin-quotas-types:

..  include:: /imap/reference/admin/quotas/quotaroots.rst
    :start-after: _imap-admin-quotas-roots:

Controlling Quota Behavior
==========================

How restrictive quotas will be may be tailored to the needs of different
sites, via the use of several settings in :cyrusman:`imapd.conf(5)`.

Please consult the :ref:`imap-admin-quotas-config` section of the Cyrus
IMAP Administrator Guide for complete details.

Mail Delivery Behavior
======================

Mailboxes Near Quota
--------------------

Normally, in order for a message to be *appended* into a mailbox, the
quota root for the mailbox must have enough unused storage that
appending the message will not cause the quota to go over limit.

Mail delivery (posting) is a special case. In order for a message to be
delivered to a mailbox, the quota root for the mailbox merely need not
already be over the limit *in the default configuration*.

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
    there is great variability in how IMAP clients handle these.
    Further, such alerts are only visible to users *while they are
    connected*.

    Therefore, many sites find it preferable to install cron jobs which
    use the :cyrusman:`quota(8)` command to produce periodic reports of
    users at or near quota, so administrators may nag them or so that
    warnings may be issued to users via some other mechanism.

Mailboxes Over Quota
--------------------

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
=====================================================

When a user selects a mailbox whose quota root has usage that is close to or over the limit and the user has ``d`` rights on the mailbox, the server will issue an alert notifying the user that usage is close to or over the limit. The threshold of usage at which the server will issue quota warnings is set by the ``quotawarn`` configuration option.

The server only issues warnings when the user has ``d`` rights because only users with ``d`` rights are capable of correcting the problem.

Quotas and Partitions
=====================

Quota roots are independent of partitions. A single quota root can apply to mailboxes in different partitions.

..  include: /imap/reference/admin/quotas.rst
    :start-after:`_imap-admin-quotas-database:`
    :end-before:`_imap-admin-quotas-convert-db:`


New Mail Notification
*********************

The Cyrus IMAP server comes with a notification daemon which supports
multiple mechanisms for notifying users of new mail. Notifications can
be configured to be sent upon normal delivery (``MAIL`` class) and/or
sent as requested by a Sieve script (``SIEVE`` class).

By default, both types of notifications are disabled. Notifications are
enabled by using one or both of the following configuration options:

*   the ``mailnotifier`` option selects the :cyrusman:`notifyd(8)` method
    to use for ``MAIL`` class notifications

*   the ``sievenotifier`` option selects the :cyrusman:`notifyd(8)`
    method to use for ``SIEVE`` class notifications (when no method is
    specified by the Sieve action)


Partitions
**********

Partitions allow administrators to store different mailboxes in different parts of the Unix filesystem.  This is intended to be used to allow hierarchies of mailboxes to be spread across multiple disks.

Specifying Partitions with "create"
===================================

When an administrator creates a new mailbox, the name of the partition for the mailbox may be specified using an optional second argument to the "create" command.  Non-administrators are not permitted to specify the partition of a mailbox.  If the partition is not specified, then the mailbox inherits the partition of its most immediate parent mailbox.  If the mailbox has no parent, it gets the partition specified in the "defaultpartition" configuration option.

The optional second argument to the "create" command can usually be given only when using a specialized Cyrus-aware administrative client such as ``cyradm``.

Changing Partitions with "rename"
=================================

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
*****

Cyrus has the ability to export Usenet via IMAP and/or export shared
IMAP mailboxes via an NNTP server which is included with Cyrus.

POP3 Server
***********

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
*******************

The Cyrus IMAP server software sends log messages to the ``local6``
syslog facility.  The severity levels used are:

* **CRIT** - Critical errors which probably require prompt administrator action
* **ERR** - I/O errors, including failure to update quota usage. The syslog message includes the specific file and Unix error.
* **WARNING** - Protection mechanism failures, client inactivity timeouts
* **NOTICE** - Authentications, both successful and unsuccessful
* **INFO** - Mailbox openings, duplicate delivery suppression

Mail Directory Recovery
***********************

This section describes the various databases used by the Cyrus IMAP
server software and what can be done to recover from various
inconsistencies in these databases.

Reconstructing Mailbox Directories
==================================

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
=================================

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
==========================

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
====================

To remove a quota root, remove the quota root's file.  Then run
``quota -f`` to make the quota files consistent again.

Subscriptions
=============

The subdirectory ``user`` of the configuration directory contains user
subscriptions.  There is one file per user, with a filename of the
userid followed by ``.sub``.  Each file contains a sorted list of
subscribed mailboxes.

There is no program to recover from damaged subscription files.  A
site may recover from lost subscription files by restoring from backups.

Configuration Directory
***********************

Many objects in the configuration directory are discussed in
the Database Recovery section. This section documents two
other directories that reside in the configuration directory.

Log Directory
=============

The subdirectory ``log`` under the configuration directory permits
administrators to keep protocol telemetry logs on a per-user basis.

If a subdirectory of ``log`` exists with the same name as a user, the
IMAP and POP3 servers will keep a telemetry log of protocol sessions
authenticating as that user.  The telemetry log is stored in the
subdirectory with a filename of the server process-id and starts with
the first command following authentication.

Proc Directory
==============

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
****************

Mail transport agents such as Sendmail, Postfix, or Exim communicate
with the Cyrus server via LMTP (the Local Mail Transport Protocol)
implemented by the LMTP daemon.  This can be done either directly by the
MTA (prefered, for performance reasons) or via the ``deliver`` LMTP
client.

Local Mail Transfer Protocol (lmtp)
===================================

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
=====================

If a delivery attempt mentions several recipients (only possible if
the MTA is speaking LMTP to ``lmtpd``), the server attempts to
store as few copies of a message as possible.  It will store one copy
of the message per partition, and create hard links for all other
recipients of the message.

Single instance store can be turned off by using the
"singleinstancestore" flag in the configuration file.

Duplicate Delivery Suppression
==============================

A message is considered a duplicate if two copies of a message with
the same message-id and the same envelope receipient are received.
Cyrus uses the duplicate delivery database to hold this information,
and it looks approximately 3 days back in the default install.

Duplicate delivery suppression can be turned off by using the
"duplicatesuppression" flag in the configuration file.

Sieve, a Mail Filtering Language
********************************

Sieve is a mail filtering language that can filter mail into an appropriate
IMAP mailbox as it is delivered via lmtp.

Cyrus Murder, the IMAP Aggregator
*********************************

Cyrus now supports the distribution of mailboxes across a number of IMAP
servers to allow for horizontal scalability.
