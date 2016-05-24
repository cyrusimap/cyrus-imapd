Overview and Concepts
=====================

This chapter gives an overview of several aspects of the Cyrus IMAP server, as they relate to deployment.

Cyrus IMAP
----------

The Cyrus IMAP (Internet Message Access Protocol) server provides access to personal mail and system-wide bulletin boards through the IMAP protocol. The Cyrus IMAP server is a scalable enterprise mail system designed for use from small to large enterprise environments using technologies based on well-established Open Standards.

A full Cyrus IMAP implementation allows a seamless mail and bulletin board environment to be set up across one or more nodes. It differs from other IMAP server implementations in that it is run on *sealed nodes*, where users are not normally permitted to log in. The mailbox database is stored in parts of the filesystem that are private to the Cyrus IMAP system. All user access to mail is through software using the IMAP, IMAPS, POP3, POP3S, or KPOP protocols.

The private mailbox database design gives the Cyrus IMAP server large advantages in efficiency, scalability, and administratability. Multiple concurrent read/write connections to the same mailbox are permitted. The server supports access control lists on mailboxes and storage quotas on mailbox hierarchies.

include::
supported-platforms.rst

Cyrus IMAP Features
-------------------

Mailbox Namespaces
""""""""""""""""""

By default, the Cyrus IMAP server presents mailboxes using the **netnews** namespace convention. This means that;

* mailbox names are case-sensitive,
* a mailbox name may not start or end with a <code>.</code> (dot) character,
* a mailbox name may not contain two subsequent <code>.</code> (dot) characters.

While the aforementioned implications of the **netnews** namespace convention apply under all circumstances, some of the implications imposed by the **netnews** namespace convention can be influenced by specifying additional configuration options to Cyrus IMAP, such as is the case with the hierarchy seperator.

When using the **netnews** namespace convention, the default, a user's shorthand qualifier (e.g. `user' for ``user@example.org``) MAY NOT contain a '.' (dot) character, as the character is being used as a hierarchy separator in mailbox names, and would thus create a personal mailbox rather then a user's INBOX.

The same limitation goes for the use of virtual domains. Since a mailbox in a virtual domain typically uses a fully qualified user identifier (e.g. ``user@example.org``, thus including a valid (sub-)domain name), the '.' (dot) character is inherited from the Domain Name System naming convention. This poses a problem without the use of the '.' (dot) character as a mailbox hierarchy separator.

To illustrate the effects on an environment, please examine the following procedure, starting from a clean Cyrus IMAP installation:

Example Effects of the Netnews Namespace Convention
"""""""""""""""""""""""""""""""""""""""""""""""""""

#. In ``imapd.conf``, set ``unixhierarchysep`` to ``0``.

#. Attempt to create a mailbox for user *bovik@example.org* using the shorthand qualifier (e.g. `bovik`), and the fully qualified user identifier (e.g. ``bovik@example.org``).

::

    $ cyradm -u cyrus localhost
    verify error:num=18:self signed certificate
    IMAP Password:
    localhost.localdomain&gt; lm
    localhost.localdomain&gt; cm user/bovik
    createmailbox: Invalid mailbox name
    localhost.localdomain&gt; cm user.bovik
    localhost.localdomain&gt; lm
    user.bovik (\HasNoChildren)
    localhost.localdomain&gt; lam user.bovik
    bovik lrswipkxtecda

As you can see, the mailbox has been created succesfully using the shorthand qualifier.

::

    localhost.localdomain&gt; cm user.bovik@example.org
    createmailbox: Permission denied
    localhost.localdomain&gt; sam user.bovik cyrus all
    localhost.localdomain&gt; cm user.bovik@example.org
    createmailbox: Permission denied
    localhost.localdomain&gt; dm user.bovik
    localhost.localdomain&gt; cm user.bovik@example.org
    createmailbox: Permission denied


In ``imapd.conf``, set ``unixhierarchysep`` to ``1``.

Attempt to create a mailbox for user *bovik@example.org* using the shorthand qualifier (e.g. ``bovik``), and the fully qualified user identifier (e.g. ``bovik@example.org``).

::

    $ cyradm -u cyrus localhost
    verify error:num=18:self signed certificate
    IMAP Password:
    localhost.localdomain&gt; lm
    localhost.localdomain&gt; cm user/bovik
    localhost.localdomain&gt; lm
    user/bovik (\HasNoChildren)
    localhost.localdomain&gt; cm user/bovik@example.org
    localhost.localdomain&gt; lm
    user/bovik (\HasNoChildren)
    user/bovik@example.org (\HasNoChildren)
    localhost.localdomain&gt; lam user/bovik
    bovik lrswipkxtecda
    localhost.localdomain&gt; lam user/bovik@example.org
    bovik@example.org lrswipkxtecda
    localhost.localdomain&gt; sam user/bovik cyrus all
    localhost.localdomain&gt; sam user/bovik@example.org cyrus all
    localhost.localdomain&gt; dm user/bovik
    localhost.localdomain&gt; dm user/bovik@example.org
    localhost.localdomain&gt; lm
    localhost.localdomain&gt;

As you can see, the mailbox has been created succesfully using the shorthand qualifier, and has been created using the fully qualified user identifier as well.


Top-level or Nested Personal Folders
""""""""""""""""""""""""""""""""""""

Cyrus IMAP allows the use of an alternative namespace for the presentation of personal mailboxes to the client (see the ``altnamespace`` configuration option), and the use of a different hierarchy separator in its presentation of personal mailboxes to the client (see ``unixhierarchysep``). 

When implemented using the default ``netnews`` namespace convention, non-ASCII characters and shell meta-characters are not permitted in mailbox names. Optionally, the server can present mailboxes using the UNIX hierarchy convention - see :ref:`Alternate Namespace <alternate_namespace>` for more information.

Standard (Internal) Namespace
"""""""""""""""""""""""""""""

All personal mailboxes for user **"bovik"** begin with the string **"user.bovik."**. For example, if user **"bovik"** had a personal **"work"** mailbox, it would be called **"user.bovik.work"**. To user **"bovik"**, however, the prefix **"user.bovik."** normally appears as **"INBOX."**. The mailbox **"user.bovik.work"** would therefore appear as **"INBOX.work"**. If the access control list of the mailbox permitted other users to see that mailbox, it would appear to them as **"user.bovik.work"**.

The mailbox **"user.bovik"** is where the user **"bovik"** normally receives new mail, and normally appears to user **"bovik"** as **"INBOX"**. The mailbox **"user.bovik"** is referred to in this document as user **"bovik"**'s **INBOX**.

Administrators create and delete users by creating and deleting the users' **INBOX**. If a user has an **INBOX**, then they are allowed to subscribe to mailboxes. Only users without dots in their userid are permitted to have an **INBOX**. (A user with a dot in their userid would be able to login but would not be able to receive mail. Note that when using the unix hierarchy seperator, this is not the case, and any user may have a dot in their userid.)

When an administrator deletes a user's **INBOX**, all of the user's personal mailboxes are deleted as well.

With the one notable exception of **INBOX**, all mailbox names are system-wide &mdash;they refer to the same mailbox regardless of the user. Access control lists determine which users can access or see which mailboxes. Using

In contexts which permit relative mailbox names, the mailbox namespace works as follows:

* Names that do not start with **.** (dot) character are fully qualified.
* Names that start with **.** (dot) character are relative to the current context.
* Thus, if you are working with folder names and the top of the hierarchy is named **"cmu."**, the name **"comp.infosystems.www"** resolves to **"comp.infosystems.www"** and the name **".comp.infosystems.www"** resolves to **"cmu.comp.infosystems.www"**.


.. _alternate_namespace:

Alternate Namespace
"""""""""""""""""""

The Cyrus IMAP server can also use analternate namespace which allows a user's personal mailboxes to appear as if they reside at the same level as that user's <code>INBOX</code> as opposed to children of it. With this feature, it may appear that there are non-unique names for mailboxes between users (2 different users may each have a top level "work" mailbox), but the internal representation is still <code>user.name.work</code>.

Access Control Lists
""""""""""""""""""""

Access to each mailbox is controlled by each mailbox's access control list. Access Control Lists (ACLs) provide a powerful mechanism for specifying the users or groups of users who have permission to access the mailboxes.

An ACL is a list of zero or more entries. Each entry has an identifier and a set of rights. The identifier specifies the user or group of users for which the entry applies. The set of rights is one or more letters or digits, each letter or digit conferring a particular privilege.

Access Rights
"""""""""""""

The following lists Access Rights that can be used in an Access Control List entry.

l
    The user may see that the mailbox exists (**lookup**).

r
    The user may read the mailbox (**read**).

    The user may select the mailbox, fetch data, perform searches, and copy messages from the mailbox.

s
    Keep per-user seen state (**seen**).

    The "Seen" and "Recent" flags are preserved for the user.

w
    The user may modify flags and keywords other than "Seen" and "Deleted" (which are controlled by other access rights).

i
    The user may insert new messages into the mailbox (**insert**).

p
    The user may send email to the submission address for the mailbox (**post**).

    This right differs from the "<code>i</code>" (**insert**) right in that the delivery system inserts trace information into messages posted, whereas no delivery trace information is added to messages inserted (by move or copy).

c
    The user may create new mailboxes in this mailbox, delete the current mailbox, or rename the mailbox (**create**).

d
    The user may store the "Deleted" flag, and perform expunges (**delete**).

a
    The user may change the *Access Control Information* (ACI) on the mailbox (**administer**).

.. todo::
    FIXME: Clarification Needed! Does the <code>a</code> right imply any other rights?


You can combine these access rights in different ways. A few examples;

lrs
    Give the user read-only access to the mailbox (<emphasis>lookup</emphasis>, <emphasis>read</emphasis> and <emphasis>seen</emphasis>).

lrsp
    Give the user read access to the mailbox, and allow the user to post to the mailbox using the delivery system (<emphasis>lookup</emphasis>, <emphasis>read</emphasis>, <emphasis>seen</emphasis> and <emphasis>post</emphasis>). Most delivery systems do not provide authentication, so the "<code>p</code>" right usually has meaning only for the "anonymous" user.

lr
    The user can lookup and read the contents of the mailbox, but no "Seen" or "Recent" flags may be set on the mailbox nor its contents. This set of rights is primarily useful for anonymous IMAP, which is often used to make the archives of mailing lists available.

rs
    The user can read the mailbox and the server preserves the "Seen" and "Recent" flags, but the mailbox is not visible to the user through the various mailbox listing commands. The user must know the name of the mailbox to be able to access it.

lrsip
    The user can read and append to the mailbox, either through IMAP, or through the delivery system.


Identifiers
"""""""""""

The identifier part of an ACL entry specifies the user or group for which the entry applies.

.. todo:: FIXME: Clarify what an ACL entry looks like first. Refer to how user login names are translated into their identifiers, and (in that section) refer to altnamespace, unixhiersep, default domain, virtdomains, sasl_auth_mech tips and tricks etc.

There are two special identifiers, "anonymous", and "anyone", which are explained below. The meaning of other identifiers usually depends on the authorization mechanism being used (selected by ``--with-auth`` at compile time, defaulting to Unix).

"<code>anonymous</code>" and "<code>anyone</code>"
""""""""""""""""""""""""""""""""""""""""""""""""""

With any authorization mechanism, two special identifiers are defined. The identifier "<code>anonymous</code>" refers to the anonymous, or unauthenticated user. The identifier "<code>anyone</code>" refers to all users, including the anonymous user.


Kerberos vs. Unix Authorization
"""""""""""""""""""""""""""""""

The Cyrus IMAP server comes with four authorization mechanisms, one is compatible with Unix-style ("<code>/etc/passwd</code>") authorization, one for use with Kerberos 4, one for use with Kerberos 5, and one for use with an external authorization process (ptloader) which can interface with other group databases (e.g. AFS PTS groups, LDAP Groups, etc).

.. note::
    **Authentication !== Authorization**

    Note that authorization is *not* the same thing as authentication. Authentication is the act of proving who you are. Authorization is the act of determining what rights you have. Authentication is discussed in the Login Authentication part of this document.

.. todo::
   In the paragraph above, make sure 'Login Authentication' links to the appropriate section.

In the Unix authorization mechanism, identifiers are either a valid userid or the string "``group``": followed by a group listed in ``/etc/group``. Thus:

::

    root                Refers to the user root
    group:staff         Refers to the group staff


It is also possible to use unix groups with users authenticated through a non-/etc/passwd backend. Note that using unix groups in this way (without associated <filename>/etc/passwd</filename> entries) is not recommended.

.. todo::
    Actually, what Cyrus requires is the getgrent(3) POSIX sysctl. As such, NSS needs to be configured to have the groups available, one of which includes "files", but could also include "ldap".


Using the Kerberos authorization mechanism, identifiers are of the form:

    <emphasis>$principal</emphasis>.<emphasis>$instance</emphasis>@<emphasis>$realm</emphasis></screen>

If ``$instance`` is omitted, it defaults to the null string. If ``$realm`` is omitted, it defaults to the local realm.


The file ``/etc/krb.equiv`` contains mappings between Kerberos principals. The file contains zero or more lines, each containing two fields. Any identity matching the first field of a line is changed to the second identity during canonicalization. For example, a line in ``/etc/krb.equiv`` of:

::

    bovik@REMOTE.COM bovik

will cause the identity ``bovik@REMOTE.COM`` to be treated as if it were the local identity ``bovik``.

A site may wish to write their own authorization mechanism, perhaps to implement a local group mechanism. If it does so (by implementing an <code>auth_[whatever]</code> PTS module), it will dictate its own form and meaning of identifiers.


Negative Rights
"""""""""""""""

Any of the above defined identifiers may be prefixed with a "<code>-</code>" character. The associated rights are then removed from that identifier. These are referred to as *negative rights*.

Calculating the Users' Rights
"""""""""""""""""""""""""""""

To calculate the set of rights granted to a user, the server first calculates the union of all of the rights granted to the user and to all groups the user is a member of. The server then calculates and removes the union of all the negative rights granted to the user and to all groups the user is a member of.

    <example id="exam-Deployment_Guide-Calculating_the_Users_Rights-Example_ACL_with_Negative_User_Rights">
    <title>Example ACL with Negative User Rights</title>

::

   anyone       lrsp
   fred         lwi
   -anonymous   s

</example>

The user "<code>fred</code>" will be granted the rights "<code>lrswip</code>" and the anonymous user will be granted the rights "<code>lrp</code>".

Implicit Rights for Administrators on Personal Mailboxes
""""""""""""""""""""""""""""""""""""""""""""""""""""""""

Regardless of the ACL on a mailbox, users who are listed in the "admins" configuration option in "<code>/etc/imapd.conf</code>" implicitly have the "<code>l</code>" and "<code>a</code>" rights on all mailboxes. Users also implicitly have the "<code>l</code>" and "<code>a</code>" rights on their INBOX and all of their personal mailboxes.


Initial ACLs for Newly Created Mailboxes
----------------------------------------

When a mailbox is created, its ACL starts off with a copy of the ACL of its closest parent mailbox. When a user is created, the ACL on the user's <code>INBOX</code> starts off with a single entry granting all rights to the user. When a non-user mailbox is created and does not have a parent, its ACL is initialized to the value of the "<code>defaultacl</code>" option in "<code>/etc/imapd.conf</code>".

Note that some rights are available implicitly, for example 'anonymous' always has 'p' on user INBOXes, and users always have rights on mailboxes within their INBOX hierarchy.


Login Authentication
--------------------

This section discusses different types of authentication (ways of logging in) that can be used with Cyrus IMAP.

The Cyrus IMAP server uses the Cyrus SASL library for authentication. This section describes how to configure SASL with use with Cyrus imapd. Please consult the Cyrus SASL System Administrator's Guide for more detailed, up-to-date information.

Anonymous Login
"""""""""""""""

Regardless of the SASL mechanism used by an individual connection, the server can support anonymous login. If the "<code>allowanonymouslogin</code>" option in "<code>/etc/imapd.conf</code>" is turned on, then the server will permit plaintext password logins using the user "<code>anonymous</code>" and any password.

Additionally, the server will enable any SASL mechanisms that allow anonymous logins.

Plaintext Authentication
""""""""""""""""""""""""

The SASL library has several ways of verifying plaintext passwords. Plaintext passwords are passed either by the IMAP <code>LOGIN</code> command or by the SASL <code>PLAIN</code> mechanism (under a TLS layer).

* PAM
* Kerberos v4
    Plaintext passwords are verified by obtaining a ticket for the server's Kerberos identity, to protect against Kerberos server spoofing attacks.

* ``/etc/passwd``
* ``/etc/shadow``

            <para>
                <code>sasl_auto_transition</code> automatically creates secrets for shared secret authentication when given a password.

The method of plaintext password verification is always through the SASL library, even in the case of the internal LOGIN command. This is to allow the SASL library to be the only source of authentication information. You'll want to look at the <code>sasl_pwcheck_method</code> option in the SASL documentation to understand how to configure a plaintext password verifier for your system.

To disallow the use of plaintext passwords for authentication, you can set <code>allowplaintext: no</code> in imapd.conf. This will still allow PLAIN under TLS, but IMAP LOGIN commands will now fail.

Kerberos Logins
"""""""""""""""

The Kerberos SASL mechanism supports the <code>KERBEROS_V4</code> authentication mechanism. The mechanism requires that a <code>srvtab</code> file exist in the location given in the "<code>srvtab</code>" configuration option. The <code>srvtab</code> file must be readable by the Cyrus server and must contain a "<code>imap.$host@$realm</code>" service key, where <code>$host</code> is the first component of the server's host name and <code>$realm</code> is the server's Kerberos realm.

The server will permit logins by identities in the local realm and identities in the realms listed in the <code>loginrealms</code> option in <filename>/etc/imapd.conf</filename>.

The file <filename>/etc/krb.equiv</filename> contains mappings between Kerberos principals. The file contains zero or more lines, each containing two fields. Any identity matching the first field of a line is permitted to log in as the identity in the second field.

If the <code>loginuseacl</code> configuration option is turned on, than any Kerberos identity that is granted the "<code>a</code>" right on the user's <code>INBOX</code> is permitted to log in as that user.

Shared Secrets Logins
"""""""""""""""""""""

Some mechanisms require the user and the server to share a secret (generally a password) that can be used for comparison without actually passing the password in the clear across the network. For these mechanism (such as CRAM-MD5 and DIGEST-MD5), you will need to supply a source of passwords, such as the sasldb (which is described more fully in the Cyrus SASL distribution)

Quota
-----

Quotas allow server administrators to limit resources used by hierarchies of mailboxes on the server.

Supports Quotas on Storage
""""""""""""""""""""""""""

The Cyrus IMAP server supports quotas on storage, which is defined as the number of bytes of the relevant RFC-822 messages, in kilobytes. Each copy of a message is counted independently, even when the server can conserve disk space use by making hard links to message files. The additional disk space overhead used by mailbox index and cache files is not charged against a quota.

Quota Roots
"""""""""""

Quotas are applied to quota roots, which can be at any level of the mailbox hierarchy. Quota roots need not also be mailboxes.

Quotas on a quota root apply to the sum of the usage of any mailbox at that level and any sub-mailboxes of that level that are not underneath a quota root on a sub-hierarchy. This means that each mailbox is limited by at most one quota root.

For example, if the mailboxes

::

   user.bovik
   user.bovik.list.imap
   user.bovik.list.info-cyrus
   user.bovik.saved
   user.bovik.todo

exist and the quota roots

::

   user.bovik
   user.bovik.list
   user.bovik.saved

exist, then the quota root "<code>user.bovik</code>" applies to the mailboxes "<code>user.bovik</code>" and "<code>user.bovik.todo</code>"; the quota root "<code>user.bovik.list</code>" applies to the mailboxes "<code>user.bovik.list.imap</code>" and "<code>user.bovik.list.info-cyrus</code>"; and the quota root "<code>user.bovik.saved</code>" applies to the mailbox "<code>user.bovik.saved</code>".

Quota roots are created automatically when they are mentioned in the <code>setquota</code> command. Quota roots may not be deleted through the protocol, see Removing Quota Roots for instructions on how to delete them.


Mail Delivery Behavior
""""""""""""""""""""""

Normally, in order for a message to be inserted into a mailbox, the quota root for the mailbox must have enough unused storage so that inserting the message will not cause the block quota to go over the limit.

Mail delivery is a special case. In order for a message to be delivered to a mailbox, the quota root for the mailbox must not have usage that is over the limit. If the usage is not over the limit, then one message may be delivered regardless of its size. This puts the mailbox's usage over the quota, causing a user to be informed of the problem and permitting them to correct it. If delivery were not permitted in this case, the user would have no practical way of knowing that there was mail that could not be delivered.

If the usage is over the limit, then the mail delivery will fail with a temporary error. This will cause the delivery system to re-attempt delivery for a couple of days (permitting the user time to notice and correct the problem) and then return the mail to the sender.

Quota Warnings Upon Select When User Has "<code>d</code>" Rights
""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""

When a user selects a mailbox whose quota root has usage that is close to or over the limit and the user has "<code>d</code>" rights on the mailbox, the server will issue an alert notifying the user that usage is close to or over the limit. The threshold of usage at which the server will issue quota warnings is set by the <code>quotawarn</code> configuration option.

The server only issues warnings when the user has "<code>d</code>" rights because only users with "<code>d</code>" rights are capable of correcting the problem.

Quotas and Partitions
"""""""""""""""""""""

Quota roots are independent of partitions. A single quota root can apply to mailboxes in different partitions.


HTML Block that was commented out in XML
========================================

.. todo:: Looks like this block of HTML never got converted to XML for Publican.

<!--
<h2><a name="notification">New Mail Notification</a></h2>

The Cyrus IMAP server comes with a notification daemon which
supports multiple mechanisms for notifying users of new mail.
Notifications can be configured to be sent upon normal delivery
(<code>"MAIL"</code> class) and/or sent as requested by a <a
href=specs.php#sieve>Sieve</a> script (<code>"SIEVE"</code> class).

By default, both types of notifications are disabled.
Notifications are enabled by using one or both of the following
configuration options:

* the "``mailnotifier``" option selects the <a href=man/notifyd.8.php>notifyd</a> method to use for "<code>MAIL</code>" class notifications

* the "``sievenotifier``" option selects the <a href=man/notifyd.8.php>notifyd</a> method to use for "``SIEVE``" class notifications (when no method is specified by the Sieve action)


Partitions
----------

Partitions allow administrators to store different mailboxes in different parts of the Unix filesystem.  This is intended to be used to allow hierarchies of mailboxes to be spread across multiple disks.

Specifying Partitions with "create"
"""""""""""""""""""""""""""""""""""

When an administrator creates a new mailbox, the name of the partition for the mailbox may be specified using an optional second argument to the "create" command.  Non-administrators are not permitted to specify the partition of a mailbox.  If the partition is not specified, then the mailbox inherits the partition of its most immediate parent mailbox.  If the mailbox has no parent, it gets the partition specified in the "defaultpartition" configuration option.

The optional second argument to the "create" command can usually be given only when using a specialized Cyrus-aware administrative client such as ``cyradm``.

<h3><a name="partitionsrename">Changing Partitions with "<code>rename</code>"</a></h3>

An administrator may change the partition of a mailbox by using the
rename command with an optional third argument.  When a third argument
to rename is given, the first and second arguments can be the
same &mdash;this changes the partition of a mailbox without changing its
name.  If a third argument to rename is not given and the first
argument is not "<code>INBOX</code>", the partition of a mailbox does not change.
If a third argument to rename is not given and the first argument is
"<code>INBOX</code>", the newly created mailbox gets the same partition it would
get from the "<code>create</code>" command.

<h2><A NAME="news">News</a></h2>

Cyrus has the ability to export Usenet via IMAP and/or export shared
IMAP mailboxes via an NNTP server which is included with Cyrus.  For
more information on exporting news groups through the IMAP server, see
<a href="install-netnews.php">install-netnews.php</a>.

<h2><a name="pop3">POP3 Server</a></h2>

The Cyrus IMAP server software comes with a compatibility POP3 server.
Due to limitations in the POP3 protocol, the server can only access a
user's <code>INBOX</code> and only one instance of a POP3 server may exist for any
one user at any time.  While a POP3 server has a user's <code>INBOX</code> open,
expunge operations from any concurrent IMAP session will fail.

When Kerberos login authentication is being used, the POP3 server
uses the server identity
"<code>pop.<VAR>host</VAR>@<VAR>realm</VAR></code>" instead of
"<code>imap.<VAR>host</VAR>@<VAR>realm</VAR></code>", where
"<code><VAR>host</VAR></code>" is the first component of the server's host
name and "<code><VAR>realm</VAR></code>" is the server's Kerberos realm.
When the POP3 server is invoked with the "<code>-k</code>" switch, the
server exports MIT's KPOP protocol instead of generic POP3.

<h3><a name="syslog">The <code>syslog</code> facility</a></h3>

The Cyrus IMAP server software sends log messages to the "<code>local6</code>"
syslog facility.  The severity levels used are:

<UL>
<LI><code>CRIT</code> - Critical errors which probably require prompt administrator action
<LI><code>ERR</code> - I/O errors, including failure to update quota usage.
The syslog message includes the specific file and Unix error.
<LI><code>WARNING</code> - Protection mechanism failures, client inactivity
timeouts
<LI><code>NOTICE</code> - Authentications, both successful and unsuccessful
<LI><code>INFO</code> - Mailbox openings, duplicate delivery suppression
</UL>

<h2><a name="recovery">Mail Directory Recovery</a></h2>

This section describes the various databases used by the Cyrus IMAP
server software and what can be done to recover from various
inconsistencies in these databases.

<h3><a name="recoverymboxdir">Reconstructing Mailbox Directories</a></h3>

The largest database is the mailbox directories.  Each
mailbox directory contains the following files:

message files
    There is one file per message, containing the message in RFC 822 format.  Lines in the message are separated by CRLF, not just LF.  The file name of each message is the message's UID followed by a dot (.).

    In netnews newsgroups, the message files instead follow the format and naming conventions imposed by the netnews software.

<code>cyrus.header</code>
    This file contains a magic number and variable-length information about the mailbox itself.

<code>cyrus.index</code>
    This file contains fixed-length information about the mailbox itself and each message in the mailbox.

<code>cyrus.cache</code>
    This file contans variable-length information about each message in the mailbox.

<code>cyrus.seen</code>
    This file contains variable-length state information about each reader of the mailbox who has "<code>s</code>" permissions.

The "<code>reconstruct</code>" program can be used to recover from
corruption in mailbox directories.  If "<code>reconstruct</code>" can find
existing header and index files, it attempts to preserve any data in
them that is not derivable from the message files themselves.  The
state "<code>reconstruct</code>" attempts to preserve includes the flag
names, flag state, and internal date.  "<code>Reconstruct</code>"
derives all other information from the message files.

An administrator may recover from a damaged disk by restoring message
files from a backup and then running reconstruct to regenerate what it
can of the other files.

The "<code>reconstruct</code>" program does not adjust the quota usage
recorded in any quota root files.  After running reconstruct, it is
advisable to run "<code>quota -f</code>" (described below) in order to fix
the quota root files.

<h3><a name="recoverymbox">Reconstructing the Mailboxes File</a></h3>

<B><I> NOTE: CURRENTLY UNAVAILABLE </I></B>

The mailboxes file in the configuration directory is the most critical
file in the entire Cyrus IMAP system.  It contains a sorted list of
each mailbox on the server, along with the mailboxes quota root and
ACL.

To reconstruct a corrupted mailboxes file, run the "<code>reconstruct
-m</code>" command.  The "<code>reconstruct</code>" program, when invoked
with the "<code>-m</code>" switch, scavenges and corrects whatever data it
can find in the existing mailboxes file.  It then scans all partitions
listed in the imapd.conf file for additional mailbox directories to
put in the mailboxes file.

<p>The <code>cyrus.header</code> file in each mailbox directory stores a
redundant copy of the mailbox ACL, to be used as a backup when
rebuilding the mailboxes file.

<h3><a name="recoveryquotas">Reconstructing Quota Roots</a></h3>

The subdirectory "<code>quota</code>" of the configuration directory (specified in
the "<code>configdirectory</code>" configuration option) contains one file per
quota root, with the file name being the name of the quota root.  These
files store the quota usage and limits of each of the quota roots.

<p>The "<code>quota</code>" program, when invoked with the "<code>-f</code>"
switch, recalculates the quota root of each mailbox and the quota
usage of each <a href="#quotaroots">quota root</a>.

<h4><a name="recoveryquotasrm">Removing Quota Roots</a></h4>

To remove a quota root, remove the quota root's file.  Then run
"<code>quota -f</code>" to make the quota files consistent again.

<h3><a name="recoverysubs">Subscriptions</a></h3>

The subdirectory "<code>user</code>" of the configuration directory contains user
subscriptions.  There is one file per user, with a filename of the
userid followed by "<code>.sub</code>".  Each file contains a sorted list of
subscribed mailboxes.

<p>There is no program to recover from damaged subscription files.  A
site may recover from lost subscription files by restoring from backups.

<h2><a name="configdir">Configuration Directory</a></h2>

Many objects in the configuration directory are discussed in
the Database Recovery section. This section documents two
other directories that reside in the configuration directory.

<h3><a name="configdirlog">"<code>log</code>" Directory</a></h3>

The subdirectory "<code>log</code>" under the configuration directory permits
administrators to keep protocol telemetry logs on a per-user basis.

<p>If a subdirectory of "<code>log</code>" exists with the same name as a user, the
IMAP and POP3 servers will keep a telemetry log of protocol sessions
authenticating as that user.  The telemetry log is stored in the
subdirectory with a filename of the server process-id and starts with
the first command following authentication.

<h3><a name="configdirproc">"<code>proc</code>" Directory</a></h3>

The subdirectory "<code>proc</code>" under the configuration directory
contains one file per active server process.  The file name is the ASCII
representation of the process id and the file contains the following
tab-separated fields:

<UL>
<LI>hostname of the client
<LI>login name of the user, if logged in
<LI>selected mailbox, if a mailbox is selected
</UL>

The file may contain arbitrary characters after the first newline
character.

<p>The "<code>proc</code>" subdirectory is normally be cleaned out on
server reboot.

<h2>Message Delivery</h2><a name="messagedelivery"></a>

<p>Mail transport agents such as Sendmail, Postfix, or Exim communicate
with the Cyrus server via LMTP (the Local Mail Transport Protocol)
implemented by the LMTP daemon.  This can be done either directly by the
MTA (prefered, for performance reasons) or via the <code>deliver</code> LMTP
client.

<h3>Local Mail Transfer Protocol</h3><a name="lmtp"></a>

<p>LMTP, the Local Mail Transfer Protocol, is a variant of SMTP design for
transferring mail to the final message store.  LMTP allows MTAs to deliver
"local" mail over a network.  This is an easy optimization so that the
IMAP server doesn't need to maintain a queue of messages or run an
MTA.</p>

<p>The Cyrus server implements LMTP via the <code>lmtpd</code> daemon.  LMTP
can either be used over a network via TCP or local via a UNIX domain
socket. There are security differnces between these two alternatives; read
more below</p>

<p>For final delivery via LMTP over a TCP socket, it is necessary to use
LMTP AUTH.  This is accomplished using SASL to authenticate the delivering
user.  If your mail server is performing delivery via LMTP AUTH (that is,
using a SASL mechanism), you will want their authentication id to be an
LMTP admins (either via the <code>admins</code> imapd.conf option or via the
<code>&lt;service&gt;_admins</code> option, typically <code>lmtp_admins</code>).</p>

<p>Alternatively you may deliver via LMTP to a unix domain socket, and the
connection will be preauthenticated as an administrative user (and access
control is accomplished by controlling access to the socket).</p>

<p>Note that if a user has a sieve script, the sieve script runs authorized
as *that* user, and the rights of the posting user are ignored for the purposes
of determining the outcome of the sieve script.</p>

<h3>Single Instance Store</h3><a name="singleinstance"></a>

<p>If a delivery attempt mentions several recipients (only possible if
the MTA is speaking LMTP to <code>lmtpd</code>), the server attempts to
store as few copies of a message as possible.  It will store one copy
of the message per partition, and create hard links for all other
recipients of the message.</p>

<p>Single instance store can be turned off by using the
"singleinstancestore" flag in the configuration file.</p>

<h3>Duplicate Delivery Suppression</h3><a name="duplicate"></a>

A message is considered a duplicate if two copies of a message with
the same message-id and the same envelope receipient are received.
Cyrus uses the duplicate delivery database to hold this information,
and it looks approximately 3 days back in the default install.

<p>Duplicate delivery suppression can be turned off by using the
"duplicatesuppression" flag in the configuration file.</p>

<h3>Sieve, a Mail Filtering Language</h3><a name="sieve"></a>

Sieve is a mail filtering language that can filter mail into an appropriate
IMAP mailbox as it is delivered via lmtp.  For more information, look
<A HREF="sieve.php">here</a>.

<h3>Cyrus Murder, the IMAP Aggregator</h3><a name="aggregator"></a>

Cyrus now supports the distribution of mailboxes across a number of IMAP
servers to allow for horizontal scalability.  For information on setting
up this configuration, see <A href="install-murder.php">here</A>.

//    -->
</chapter>

