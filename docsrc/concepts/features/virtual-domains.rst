===============
Virtual Domains
===============

What are virtual domains?
=========================

Virtual domains means hosting a service for more than one
domain on a single server.  Cyrus IMAP has the ability to host IMAP/POP
mailboxes for multiple domains (for example: ``test@cyrusisgreat.org`` and
``test@ilovecyrus.com``) on a single server or Murder.

Cyrus needs to know which domain to use when a mailbox is accessed.
There are two ways in which Cyrus can determine the domain:

Fully qualified userid
    The client logs in with a userid
    containing the domain in which the user belongs (for example:
    ``test@cyrusisgreat.org`` or ``test@ilovecyrus.com``)

IP address
    The server looks up the domain based on the IP
    address of the receiving interface (useful for servers with multiple
    NICs or those using IP aliasing)

If the ``virtdomains`` option is set to ``off`` (or ``no``, ``0``, ``false``),
Cyrus does not know or care about domains, and only ever considers the local
part of email addresses.  This configuration is never recommended, but is
currently the default.

If the ``virtdomains`` option is set to ``userid``, then only the
fully qualified userid is used.  This is the only recommended configuration
for new deployments, and in the future may become the default or only option.
Existing deployments should strongly consider migrating towards this
configuration.

If the ``virtdomains`` option is set to ``on`` (or ``yes``, ``1``, ``true``),
Cyrus uses both mechanisms to work out the domain (with the fully qualified
userid taking precedence).  This configuration is not recommended.

.. note::
    If you are providing calendaring services, you MUST use the
    ``virtdomains: userid`` configuration.  Calendaring services require
    a consistent single authoritative fully-qualified email address for
    each user in order to function, and this is the only configuration
    that provides it.

    The ``virtdomains: off`` and ``virtdomains: on`` configurations both
    allow users' domains to be changed from outside of Cyrus without Cyrus
    knowing about it, which fundamentally breaks calendaring.  These
    configurations are only suitable for IMAP-only deployments.

Concepts
========

Everyone is in a domain
    It's best to think of every user as existing inside a domain.  Unqualified users are technically inside the ``defaultdomain``.

Names can be qualified
    Global admins can reference mailboxes and IDs by qualified names.  That is, for any given mailbox command, you can add ``@domain`` to the end of the mailbox name.

    Here are some examples:

        * ``cyradm> create user/lukecage@example.net`` - create a user
        * ``cyradm> create user/mercedesknight@example.net`` - create another user
        * ``cyradm> setquota user/lukecage@example.net 50000`` - define a quota
        * ``cyradm> setaclmailbox user/lukecage@example.net mercedesknight@example.net read`` - give Mercedes Knight read access to Luke Cage's mailbox
        * ``cyradm> listmailbox *@example.net`` - list all mailboxes in the example.net domain

Each mailbox exists in only one domain

Domains are mutually exclusive
    Users only have access to mailboxes within their own domain (intra-domain).  The following
    example will not work: ``setacl user/mercedesknight@herdomain.com
    lukecage@hisdomain.com read``.

Global and Domain admins
    The Cyrus virtual domains
    implementation supports per-domain administrators as well as
    global (inter-domain) administrators.

    Domain-specific administrators are specified with a fully qualified userid in the
    ``admins`` option (e.g., ``admin@example.net``) and only
    have access to mailboxes in the associated domain.

    Global administrators are specified with unqualified userids.


MOST OF THIS SHOULD BE IN DEPLOYMENT GUIDE?

Quick Start
===========

* Add ``virtdomains: userid`` to :cyrusman:`imapd.conf(5)`
* Add a ``defaultdomain`` entry to :cyrusman:`imapd.conf(5)`
* Use cyradm (as a global or domain admin) to create mailboxes for each domain.

Configuration
=============

Support for virtual domains is enabled by turning on the ``virtdomains`` option in :cyrusman:`imapd.conf(5)`.

When upgrading from a single domain installation to a virtual
domain installation, the name of the existing domain (domain of the
server hostname) should be specified using the ``defaultdomain``
option in :cyrusman:`imapd.conf(5)`.  This allows users to continue to
access their mailboxes using unqualified userids.  For example, if the
primary IP address on your server resolves to 'www.xxx.yyy.zzz',
then set ``defaultdomain`` to 'xxx.yyy.zzz'.

Even for new installations, set the ``defaultdomain`` to the "real"
domain of the server (domain of its primary hostname).
See `Administrators`_ for further discussion.

Here is a sample ``imapd.conf`` with a minimal set of configuration
options::

    configdirectory: /var/imap
    partition-default: /var/spool/cyrus
    admins: admin lukecage.admin@hisdomain.com mercedesknight.admin@herdomain.net
    virtdomains: yes
    defaultdomain: exampleisp.net

This example has three domains: exampleisp.net, hisdomain.com, and
herdomain.net.  ``admin`` can administer all three domains, while
``lukecage.admin@hisdomain.com`` and
``mercedesknight.admin@herdomain.net`` can only administer their respective
domains.

Everyday users should not be administrators.  In the
above example, Mercedes Knight and Luke Cage have separate administrative accounts for
their domains.

Multiple IP Addresses
---------------------

In order to use a multiple IP address configuration, the server must
be able to do a reverse lookup on the IP address to determine the
hostname of the receiving interface.  For example::

    192.168.0.1  ->  mail.example.com
    192.168.0.2  ->  mail.example.net
    192.168.0.3  ->  mail.foo.bar

Once the server obtains the fully qualified hostname of the
interface, it removes the localpart (i.e., 'mail') and uses the
remainder as the domain for any user that logs in.

This address to hostname mapping would usually be done via DNS,
``/etc/hosts``, NIS, etc.  Configuration of the various naming
services is beyond the scope of this document.

Delivering mail
---------------

To deliver mail to your virtual domains, configure your MTA so that
the envelope recipient (RCPT TO) passed to ``lmtpd`` is fully
qualified with the correct domain.

Configuring Sendmail
####################

Follow the basic :ref:`configuration instructions <installing>`.

Some items to be aware of:

* It is easiest to use the mailertable to route mail to Cyrus,
  rather than adding the domain to the local-host-names file ($w).
  This prevents Sendmail from changing the domain name to the local host name.

   ``example.com              cyrusv2:/var/imap/socket/lmtp``

* You'll have to use the Cyrus mailer in LMTP mode, and you'll have
  to change the mailer flags so that it provides the full domain while
  communicating via LMTP.  Specifically these changes:

    ``S=EnvFromSMTP/HdrFromSMTP, R=EnvToSMTP``

Mail Clients
------------

The only changes you'll need to make to mail clients is to change
usernames to the fully qualified domain names, i.e., ``user@example.com``.
The ``user%example.com`` form of userid is also supported.

Users in the default domain will not
need to reconfigure their clients (as unqualified userids are assumed to
be in the default domain).

Administrators
--------------

The Cyrus virtual domains implementation supports per-domain
administrators as well as "global" (inter-domain) administrators.
Domain-specific administrators are specified with a
fully qualified userid in the ``admins`` option
(e.g., ``admin@example.net``) and only have access to mailboxes in
the associated domain.  Mailbox names should be specified in the same
fashion as on a single domain configuration.

Global administrators are specified with an unqualified userid in the
``admins`` option and have access to *any* mailbox on the
server.  Because global admins use unqualified userids, they belong
to the ``defaultdomain``.  As a result, you CANNOT have a global
admin without specifying a ``defaultdomain``.  Note that when
trying to login as a global admin to a multi-homed server from a remote
machine, it might be necessary to fully qualify the userid with the
``defaultdomain``.

Global admins must use ``mailbox@domain`` syntax when
specifying mailboxes outside of the ``defaultdomain``.  Examples
(using ``cyradm``):

To create a new INBOX for user 'test' in ``defaultdomain``::

    cm user/test

To create a new INBOX for user 'test' in domain 'example.com'::

    cm user/test@example.com

To list all mailboxes in domain 'example.com'::

    lm *@example.com
