.. _cyrus-nntp:

==========
Cyrus NNTP
==========

Overview
========

.. note::

    The NNTP support in Cyrus is still relatively young in the grand scheme of things, and has not been tested under a heavy Usenet load. That being said, the code appears to be stable and is currently running in production serving 50-60 newsgroups with a volume of about 6000 messages per day.

Cyrus includes a NNTP server. The NNTP works a lot like the IMAP server, it uses the same authentication and authorization. It also stores messages like IMAP. This means the messages are stored in one file per post.

Cyrus has the ability to export Usenet via IMAP and/or export shared IMAP mailboxes via NNTP. 

This :download:`diagram <images/netnews.png>` shows how the various NNTP components interact.

NNTP Setup
==========

Decide where the newsgroup mailboxes will reside: either at the toplevel of the hierarchy (eg, comp.mail.imap) or rooted elsewhere (eg, netnews.comp.mail.imap). If the newsgroup mailboxes are not at the toplevel of the hierarchy, then the parent must be specified using **newsprefix** in :cyrusman:`imapd.conf(5)`. 

1. Make sure that Cyrus is built with NNTP support using the ``--enable-nntp`` switch. This builds nntpd and the associated utilities.
    
    In many pre-packaged versions of Cyrus, the NNTP server is in its own package (Example: Debian has a cyrus-nntpd-2.2 package that must be installed in addition to the rest of Cyrus).

2. Edit ``/etc/cyrus.conf``.

    In order to receive usenet articles, make sure that the Cyrus nntpd service is enabled in cyrus.conf. The master/conf/normal.conf and master/conf/prefork.conf sample configs both include entries for nntpd (disabled by default).

    Add a new line in the SERVICES section with something like this::

        nntp: cmd="nntpd"  listen="nntp" prefork="0"
    
    This defines a new service that will run the nntpd command (man nntpd for more info) on the nntp port (defined in /etc/services). Since the prefork is listed as 0, Cyrus will not start a new process for this.

3. Edit ``/etc/imapd.conf``.

    There are many directives for news that can be placed in /etc/imapd.conf. Check out :cyrusman:`imapd.conf(5)` to learn more.

    At minimum, something like this::

        # News:
        partition-news: /var/spool/cyrus/news
        newsprefix: ournews

    This tells Cyrus:

    * Where the news partition should be stored (should be similar to the value in **partition-default**)
    * What part of the Cyrus tree should be treated as the location for news groups.

    The **newsprefix** is a path in the IMAP directory hierarchy (that is, the hierarchy used with cyradm). User accounts, for instance, are often in the ``users`` hierarchy. Here, we are telling it to put the news in the ``ournews`` hierarchy.

4. Restart your server.

Defining Newsgroups
===================

Create a mailbox for each newsgroup to receive/export. If some groups are private, be sure to set the ACLs accordingly. The :cyrusman:`mknewsgroups(8)` script can be used to help facilitate mass creation of newsgroup mailboxes. When using this script, be sure to add posting rights for 'anyone' (eg. ``mknewsgroups -a 'anyone +p' ...``) so that articles can be fed/posted.

News groups can be defined in two ways:

1. Use :cyrusman:`mknewsgroups(8)`, which is a very simple wrapper for creating groups
2. Use :cyrusman:`cyradm(8)`, and create a new mailbox for news.

Some distributions such as debian do not include mknewsgroups.

Using Cyradm
------------

Create a new group like creating a new mailbox::

    $ cm ournews/mynewsgroup

Next, set some permissions. (See :cyrusman:`cyradm(8)` for more info on the cm and sam commands.)

::

    $ sam ournews/mynewsgroup anyone lrsp

The above gives **L** Lookup, **R** Read, **S** Seen, and **P** Post permissions (basically read/write -- see the man page for more) to anyone logged into the server. More restrictive permissions are possible. (Note: This example assumes *unixhierarchysep* is being used in :cyrusman:`imapd.conf(5)`)    

Configuration
=============

Push (traditional) feeds
------------------------

If the usenet peer will be pushing articles to the server, no further configuration is necessary, beyond providing peer access to the Cyrus server on port 119 (nntp).

Pull (suck) feeds
-----------------

If pulling articles from the peer is preferred (and the provider allows it), then use the ``fetchnews`` utility which will retrieve articles from the peer and feed them to the Cyrus server. If supported by the peer, fetchnews will use the NEWNEWS command, otherwise it will fallback to keeping track of the high water mark of each group. Configure fetchnews as an EVENT in :cyrusman:`cyrus.conf(5)` to be called periodically (eg, once an hour, every 15 minutes, etc).

imapfeed
--------

Alternatively, if there is an INN v2.3 server in-house use the included ``imapfeed`` utility (written by the authors of Cyrus) to feed articles to the Cyrus server via LMTP. Consult the INN documentation for further details.

Control Messages
----------------

Control messages are accepted, parsed and delivered to the corresponding ``control.*`` pseudo-group (eg, control.newgroup, control.cancel, etc) if it exists, so that they may be reviewed by an administrator.

Automatic execution of control messages is only performed if the newsmaster (default = "news") user has the proper access control for the given mailbox. For example, to allow cancel control messages to be performed for ``misc.test`` articles, give the "news" user the 'd' right on "misc.test". To allow newgroup, rmgroup and mvgroup control messages to be performed on the "misc" hierarchy, give the "news" user the 'c' right on "misc".

NOTE: No sender or PGP verification of control messages is currently implemented.

Reading/Posting articles
------------------------

In order to have articles posted by your local users propagate to the outside world, you must specify the name of your usenet peer(s) with the newspeer option in :cyrusman:`imapd.conf(5)`. This is the host(s) that nntpd contacts to feed outgoing articles. Depending on the configuration of the newspeer option, articles will be fed to the upstream server(s) using either the POST or IHAVE command. Also note that you may specify an optional wildmat to filter which groups will be fed (see :cyrusman:`imapd.conf(5)` for details).

Newsgroups can also be gatewayed to email by setting ``/vendor/cmu/cyrus-imapd/news2mail`` mailbox :ref:`annotations <faqs-o-annotations>` to the corresponding email addresses.

News clients
------------

If anonymous logins are disabled (default) in :cyrusman:`imapd.conf(5)`, then your news clients will have to be configured to login with a username and password, otherwise they will not be allowed to post. Furthermore, if plaintext logins are disabled in imapd.conf, then you might have to configure your news clients to use SSL/TLS and enable the nntps service in :cyrusman:`cyrus.conf(5)`.

If you want to allow your news clients to use the NNTP NEWNEWS command, you will have to enable the **allownewnews** option in imapd.conf.

Email clients
-------------

If you are exporting Usenet via IMAP, and your users' messaging clients are not savvy enough to reply to and post articles via NNTP, then you will have to configure your server so your users can reply to and post articles via SMTP.

To help facilitate this, you can set the **newspostuser** option to a pseudo user which will be used to construct email delivery addresses for each incoming article. These addresses are inserted into a Reply-To: in the article. For example, if set to "post", an article posted to comp.mail.imap will have an address of "post+comp.mail.imap" inserted into the Reply-To: header. This will allow a user to easily reply to an article via email. Otherwise, the users will have to learn the correct email address format for posting and replying to articles.

In order for these email messages to be fed into your news server (and subsequently to the outside world) you need to use an email to news gateway, such as lmtp2nntp. You need to configure your MTA (Sendmail, Postfix, etc) so that lmtp2nntp is used as the local mailer whenever it receives a news article. A simple rule for doing this in Sendmail is shown below::

    # mail addressed to post+ goes to lmtp2nntp@localhost
    LOCAL_RULE_0
    Rpost + $+ < @ $=w . >		$#lmtp2nntp $@ localhost $: $1

For other configurations, consult the lmtp2nntp and documentation and your MTA documentation.

NOTE: If anonymous logins are disabled (default) in :cyrusman:`imapd.conf(5)`, then you should configure lmtp2nntp to use its "feed" operation mode.

Expiring articles
-----------------

Expiration of articles is done by the :cyrusman:`cyr_expire(8)` utility. Control over when articles are expunged is accomplished with the ``/vendor/cmu/cyrus-imapd/expire`` mailbox :ref:`annotation <faqs-o-annotations>`. This annotation sets the number of days that messages should be kept in the mailbox before they expire. All entries in the duplicate deliver database that correspond to these messages are also kept for the same number of days before they are purged (overriding the ``cyr_expire -E`` option).

Setting the expire time to 0 (zero) for a mailbox will ensure that neither the messages nor the corresponding database entries will ever be expired. This can be useful for shared mailboxes (e.g. mailing list archives) which are being exported via NNTP. Note that this will cause the duplicate delivery database to consistently grow in proportion to the number of messages in such mailboxes.

If a mailbox does not have an expire time set on it, then the messages will never be expunged, but the corresponding database entries WILL be expired after the default number of days (``cyr_expire -E`` option).

Note that the ``/vendor/cmu/cyrus-imapd/expire`` mailbox :ref:`annotation <faqs-o-annotations>` is inherited by child mailboxes, so that you may control expiration on an entire mailbox/newsgroup hierarchy simply by setting the annotation on the root of the hierarchy. For example, if you set the annotation on ``comp``, then ALL of the newsgroups in the ``comp`` hierarchy will be expired at the same time. Similarly, if you set the annotation on ``alt.binaries``, all of the binary newsgroups under ``alt`` will be expired at the same time (independently from ``comp``).


Further information
===================

This thread from the info-cyrus :ref:`mailing list <feedback>` may be of use: `Cyrus and Usenet <http://www.mail-archive.com/info-cyrus%40lists.andrew.cmu.edu/msg22725.html>`_

