.. _murder-installation:

=============================================
Cyrus Murder: Installation and Administration
=============================================

Architecture
============

:ref:`Overall structure of a Cyrus Murder <architecture_murder>`.

The Cyrus Murder provides the ability to horizontally scale your Cyrus
IMAP environment across multiple servers. It is similar in nature to
various proxy solutions such as nginx or perdition with the difference
being that Murder offers a uniform namespace. Those not currently using
shared mailboxes and who don't intend to use shared mailboxes in the
future, should probably just consider using a simple proxy solution.

Before beginning Cyrus Murder configuration, we strongly recommended a
thorough review of the :ref:`Cyrus Murder Concepts <murder_concepts>`
guide.

Terminology
===========

Master
    In this document, Master always means the MUPDATE master server.

Installation
============

Cyrus IMAPd must be built with the ``--enable-murder`` configure
option. This builds the proxyds and the associated utilities.

.. Note::
    Those using their distribution's packages may need to install a
    separate package for aggregation support.  For example, on Debian
    and derived distros, install the ``cyrus-murder`` package.

Requirements
------------

    * At least one Cyrus IMAP server instance. If there are more than
      one, their namespaces **must not** conflict. That is, all the
      mailbox names must be unique (or in different namespaces)

    * At least one machine that will become the first Frontend Server.

    * One machine to become the MUPDATE Master server. This can be the
      same as one of the frontend servers.
    
Configuring the MUPDATE Master
------------------------------

The MUPDATE Master server needs to be running the mupdate service in
master mode. The MUPDATE master may be one of the cluster's frontend
instances, in which case no slave mupdate process should be run on this
instance.

On the mupdate master :cyrusman:`cyrus.conf(5)` must include a line
similar to the following in the SERVICES section::

    mupdate       cmd="/usr/cyrus/bin/mupdate -m" listen=3905 prefork=1
    
Note the ``-m`` option to tell mupdate that it should start in master
mode.

The MUPDATE Master will also need at least a skeleton
:cyrusman:`imapd.conf(5)` that defines the config directory, a bogus
partition-default and the ``admin``\ s who can authenticate to the server.
Slave mupdate servers as well as the back end servers will need to be
able to authenticate as admins on the master.

Here is a very simple :cyrusman:`imapd.conf(5)` for a master server::

    configdirectory: /imap/conf
    partition-default: /tmp

    admins: mupdateslave1 backend1
    
SASL must also be configured as needed to properly allow authentication.

Setting up the backends to push changes to the MUPDATE Master
-------------------------------------------------------------

On the backends, configuration to be a part of a murder is easy. Simply
set the ``mupdate_server`` option in :cyrusman:`imapd.conf(5)` and add
an entry to :cyrusman:`cyrus.conf(5)` to push the mailboxes list to
the MUPDATE Master.

Depending on the authentication mechanisms used, some or all of the
following settings in :cyrusman:`imapd.conf(5)` may be required:

    * mupdate_username
    * mupdate_authname
    * mupdate_realm
    * mupdate_password
    * servername
    
Once these settings are made, any mailbox operation on the backend will
be sent to the mupdate master for confirmation and entry into the
mupdate database.

At least one user/group must be configured using the ``proxyservers``
:cyrusman:`imapd.conf(5)` option. This user should not be an
administrator, as that would give anyone compromising this credential
full administrative control on all back ends.

.. Note::
    For lmtp to work in a murder, the proxyservers entries must also
    appear in the lmtp_admins entry.

Example of the :cyrusman:`imapd.conf(5)` settings discussed thus far::

    # How this server identifies itself within the murder
    servername: mailbox.example.com
    # Who's permitted to authenticate for which purposes
    admins: cyrus
    proxyservers: mailproxy
    lmtp_admins: mailproxy
    # Auth credentials for MUPDATE Master
    mupdate_server: postman.example.com
    mupdate_username: postman
    mupdate_authname: postman
    mupdate_password: <secret>

All proxy user(s) must exist within the authentication domain of both
the MUPDATE Master and the back end, as well.

.. Note::

    Do not set ``proxyservers`` on frontends.

Exporting the database from the backend
---------------------------------------

The existing mailboxes database must be exported to the MUPDATE Master.
Use the :cyrusman:`ctl_mboxlist(8)` command to do so. For the first
synchronization, change to the cyrus user, and run ``ctl_mboxlist -m``.

.. Important::
    One should use ``ctl_mboxlist -mw`` (dry run) first to be sure of
    understanding all the operations that this command will perform,
    since it does require that all mailboxes are unique in the murder
    namespace and could lead to deletions of conflicting mailboxes on
    other back ends already in the murder.

If everything is configured properly, the mailbox database of the
current host will upload to the mupdate master. If there are problems,
the most likely cause is a misconfiguration of the authentication
settings, or :cyrusman:`mupdate(8)` might not be running on the master.
Using :cyrusman:`mupdatetest(1)` may be helpful in this case (it
establishes an authenticated connection to the mupdate server, if it
can).

It is also useful to have the backends automatically resync the state
of their local mailboxes database with the master on start up. This is
configured by adding the following to the START section of
:cyrusman:`cyrus.conf(5)` on the backends::

    mupdatepush   cmd="ctl_mboxlist -m"
  
This will perform synchronization with the mupdate master each time the
backend restarts, bringing the mupdate database up to date with the
contents of the backend (and performing ACTIVATE and DELETES as needed
to do so).

.. Warning::

    If somehow a mailbox exists on two (or more) backend servers, each
    time one of them synchronizes its database that backend server will
    become authoritative. Though this should not happen during normal
    operation of the murder (because of the consistency guarantees of
    the MUPDATE protocol, and the fact that mailbox operations are
    denied if the mupdate master is down), it is possible when first
    creating the mupdate database or when bringing a new backend server
    into the murder.
    
Configuring the front ends
--------------------------

Configuring the front ends is a two step process. First, define
mupdate_server (and friends) as done for the backends above. However,
as the frontends only talk to the mupdate master via a slave running on
the local machine, also set up a slave on the same machine, in the
SERVICES section of :cyrusman:`cyrus.conf(5)`, like so::

  # mupdate database service - must prefork at least 1
  mupdate       cmd="mupdate" listen=3905 prefork=1
  
As this is a threaded service, prefork at least 1 so that the database
synchronizes at startup. Otherwise, the service will not start running
until after receiving a mupdate client connection to the slave (which
is not a recommended configuration at this point).

The front end SERVICES section should now look like this::

  mupdate       cmd="mupdate" listen=3905 prefork=1

  imap          cmd="imap" listen="imap" prefork=5
  imaps         cmd="imap -s" listen="imaps" prefork=1
  pop3          cmd="pop3d" listen="pop3" prefork=0
  pop3s         cmd="pop3d -s" listen="pop3s" prefork=0
  kpop          cmd="pop3d -k" listen="kpop" prefork=0
  nntp          cmd="nntpd" listen="nntp" prefork=0
  nntps         cmd="nntpd -s" listen="nntps" prefork=0
  http          cmd="httpd" listen="http" prefork=0
  https         cmd="httpd -s" listen="https" prefork=0
  sieve         cmd="timsieved" listen="sieve" prefork=0
  lmtp          cmd="lmtpd" listen="/var/imap/socket/lmtp" prefork=0
  
Note that timsieved does not need a proxy daemon, the managesieve
protocol deals with the murder with referrals to the backends
internally.

Additionally, entries in :cyrusman:`imapd.conf(5)` are required to
indicate the proxy auth name and passwords (if using a SASL mechanism
that requires them) to the backends.

For example, if the backends are ``mail1.andrew.cmu.edu`` and
``mail2.andrew.cmu.edu`` with passwords of ``foo`` and ``bar``, and an
auth name of ``mailproxy``::

    mail1_password: foo
    mail2_password: bar
    proxy_authname: mailproxy
    
For SASL mechanisms not using authnames or passwords (e.g.
KERBEROS_V4), the password options are not required. Note the use of
the same authname as configured in the proxyservers line of the
backend's :cyrusman:`imapd.conf(5)` above.

Upon starting :cyrusman:`master(8)` on the frontend, the local
mailboxes database should automatically synchronize with the contents
of the MUPDATE master, and it's ready to go. Clients should connect to
the frontends, and the frontends will proxy or refer as applicable to
the backend servers.

Additional backend configuration
--------------------------------

Authentication system expecting usernames, passwords, etc, to
authenticate, will also need to specify proxy_authname (and friends) in
the backend imapd.confs. This is so the backends can authenticate to
each other to facilitate mailbox moves. (Backend machines will need to
be full admins).

Delivering mail
---------------

To deliver mail to a Murder, configure MTAs just as before, but instead
of connecting directly to lmtpd on a back end, they should connect to
lmtpproxyd on any front end. Remote MTAs may connect to the lmtpproxyd
running on any front end machine (listening  on a TCP socket), or
install master and lmtpproxyd on your SMTP servers to connect via Unix
domain socket.

Administration
==============

Keeping the database synced
---------------------------

Consistency in the database is maintained by pushing the current status
of the backends to the master, and having the frontends stay up to date
with the master's database. Since the frontends resync themselves
entirely when they startup, downtime should not be a problem.
(While they are up they should be continuously receiving database
updates, as well when they lose connection to the master, they will
try to reconnect and resync their database upon reconnection)

Provided that the namespace of the backend servers is kept discrete
(with no mailboxes existing on the same server), it is not a big deal
to resync the mupdate master using ``ctl_mboxlist -m``. If two servers
do have the same mailbox, this will need to be resolved before database
consistency can be guaranteed.

Moving Mailboxes between backends
---------------------------------

There is currently no 100% foolproof way to do this, however, if you
issue a rename command to a frontend (as you would to move a mailbox
between partitions), and replace the partition name with the name of
the new backend, it will move the mailbox to the indicated backend. You
can also use the format ``backend.domain.com!partition`` to move to a
specific partition (otherwise the default partition will be used).

In cyradm, this looks like::

    cyrus.andrew.cmu.edu> rename user.bcyrus user.bcyrus mail2.andrew.cmu.edu!u2

Note that since seen state is stored per-user, it is possible that when
moving a shared mailbox users will have strange effects. The general
rule is that moving an INBOX will move the entire user (including all
sub-mailboxes to the INBOX, and seen state, and subscriptions, and
sieve scripts, etc). The seen state is merged with the seen state on
the new backend, so that no data is lost (seen state is also the only
part left behind on the source backend). In the case of any other
mailbox, however, only that individual mailbox is moved. If it is a
quota root, the new quota root is instantiated on the new server, but
otherwise quotas can appear to be violated, since each backend only
takes care of its own quota.

In general, it's better to leave trees of mailboxes on the same server,
and not move submailboxes of inboxes between servers.

Adding additional backend servers
---------------------------------

This is very easy to do, simply configure an empty backend server and
set its ``mupdate_server`` parameter to point at the mupdate master.
Then, issue mailbox creates to it as you would any other backend
server.

Distributing Mailboxes between Back Ends
----------------------------------------

Several options exist within :cyrusman:`imapd.conf(5)` to aid in the
distribution of new users and mailboxes within a murder; across servers
and partitions.  We recommend exploring these:

    .. include:: /imap/reference/manpages/configs/imapd.conf.rst
        :start-after: startblob partition_select_mode
        :end-before: endblob partition_select_mode

    .. include:: /imap/reference/manpages/configs/imapd.conf.rst
        :start-after: startblob partition_select_exclude
        :end-before: endblob partition_select_exclude

    .. include:: /imap/reference/manpages/configs/imapd.conf.rst
        :start-after: startblob partition_select_usage_reinit
        :end-before: endblob partition_select_usage_reinit

    .. include:: /imap/reference/manpages/configs/imapd.conf.rst
        :start-after: startblob partition_select_soft_usage_limit
        :end-before: endblob partition_select_soft_usage_limit

    .. include:: /imap/reference/manpages/configs/imapd.conf.rst
        :start-after: startblob serverlist
        :end-before: endblob serverlist

    .. include:: /imap/reference/manpages/configs/imapd.conf.rst
        :start-after: startblob serverlist_select_mode
        :end-before: endblob serverlist_select_mode

    .. include:: /imap/reference/manpages/configs/imapd.conf.rst
        :start-after: startblob serverlist_select_usage_reinit
        :end-before: endblob serverlist_select_usage_reinit

    .. include:: /imap/reference/manpages/configs/imapd.conf.rst
        :start-after: startblob serverlist_select_soft_usage_limit
        :end-before: endblob serverlist_select_soft_usage_limit


Backups
-------

.. :todo:
    xxx, need to write stuff. You don't need to really backup the data
    on the mupdate master or slaves, since this data can all be
    generated directly from the backends quite easily.
    
Gotchas
=======

**Clients dealing with a pool of frontend servers**
    Some clients may not be terribly efficient caching connections to a
    pool of imap servers, this isn't a problem, as such, but it may
    mean that you will see many more authentications than you are used
    to.
    
**Kerberos issues**
    If you are using kerberos authentication, you will want to ensure
    that all your machines are keyed properly, as we have seen problems
    with different clients trying to authenticate to different services
    (e.g. imap.imap-pool instead of imap.pool-frontend-1), so test the
    clients in use in your environment and be sure that they work with
    whatever keying scheme you use.

**Clients dealing with referrals**
    Some clients (we've had particular trouble with pine, though most
    of these issues have now been resolved and new versions should be
    OK (that is, pine > 4.44), but as referrals have not been
    extensively used by any IMAP server until now, referrals are very
    likely to not work correctly or have surprising effects.
    
**Clients dealing with getting a NO on LSUB commands**
    Some clients (Outlook, for example) may behave poorly if an LSUB
    command returns a NO, which may be the case if the backend server
    with the user's inbox is down. We have, for example, seen this
    result in the deletion of the disconnected message cache.
    
**Behavior of cyradm / some mailbox operations**
    The behaviour of some administrative commands might be slightly
    unexpected. For example, you can only issue a SETQUOTA to a
    frontend server if the entire mailbox tree underneath where you are
    setting the quota exists on the same backend server, otherwise you
    will need to connect directly to the backend servers to perform the
    needed changes. Similarly, mailboxes will be created on the same
    backend server that their parent is in. In order to create them on
    a different server (or to create a new top level mailbox) you will
    need to connect directly to the desired backend server.
    
**Subscriptions**
    If users want subscribe to a mailbox other than on their backend
    home server, they won't be able to, unless you set
    ``allowallsubscribe: t`` in the backend imapd.confs. This
    essentially lets any string be subscribed to successfully.
 
**Restarting the mupdate master**
    Because ``ctl_cyrusdb -r`` clears reservations on mailbox, if you
    restart the mupdate master (and run recovery), then this could (we
    suspect, very rarely) lead to inconsistencies in the mupdate
    database.

Troubleshooting 
===============

**Mailbox operations are being denied**
    This is an indication that the mupdate master may be down. Restart
    it.
    
**Mailbox operations are not being seen by one or more frontends**
    This indicates that the mupdate process on a slave may have died,
    you may need to restart master. Alternatively, mupdate will retry
    connections every 20 seconds or so for about 20 attempts if the
    master does go down.
    
**A frontend's mailboxes.db is corrupt or out of sync**
    Restart master on the frontend, and have the mupdate process
    resynch the local database. You may need to remove the local
    mailboxes database if the corruption is extreme.

**A mailbox's location keeps switching between two (or more) backend hosts.**
    It probably actually exists on both hosts. Delete the mailbox from
    all but one of the hosts, and run a ``ctl_mboxlist -m`` on the one
    where you want it to actually live.

**Databases are never created on the frontends/slaves**
    Check to ensure that the mupdate slave process is started, (is
    prefork=1)
