.. _murder:

=============================================
Cyrus Murder: Installation and Administration
=============================================

Architecture
============

:ref:`Overall structure of a Cyrus Murder <architecture_murder>`.

The Cyrus Murder provides the ability to horizontally scale your Cyrus 
IMAP environment across multiple servers. It is similar in nature to 
various proxy solutions such as nginx or perdition with the difference 
being that Murder offers a uniform namespace. If you're not currently 
using shared mailboxes and you don't intend to use shared mailboxes in 
the future, you should probably just consider using a simple proxy 
solution. 

Before you begin setting up a Cyrus Murder, it is strongly recommended
you review the :ref:`Cyrus Murder Concepts <murder_concepts>` guide.

Installation
============

You will need to build Cyrus IMAPd with the ``--enable-murder`` configure option. This builds the proxyds and the associated utilities.

Requirements
------------

    * At least one Cyrus IMAP server instance. If there are more than one, their namespaces must not conflict. That is, all the mailbox names must be unique (or in different namespaces)
    * At least one machine that will become the first Frontend Server.
    * One machine to become the MUPDATE master server. This can be the same as one of your frontend servers.
    
Configuring the MUPDATE Master
------------------------------

The mupdate master server needs to be running the mupdate service in master mode. You can have the MUPDATE master be one of your frontend machines; just do not configure a slave mupdate process on this machine.

To configure an mupdate master, you will want a cyrus.conf that includes a line similar to the following in the SERVICES section:
::

    mupdate       cmd="/usr/cyrus/bin/mupdate -m" listen=3905 prefork=1
    
Note the ``-m`` option to tell mupdate that it should start in master mode.

You will also need to configure at least a skeleton :cyrusman:`imapd.conf(5)` that defines the config directory, a bogus partition-default and the admins that can authenticate to the server. Slave mupdate servers as well as the backend servers will need to be able to authenticate as admins on the master. 

Here is a very simple :cyrusman:`imapd.conf(5)` for a master server:

::

    configdirectory: /imap/conf
    partition-default: /tmp

    admins: mupdateslave1 backend1
    
You will also need to configure SASL to properly allow authentication in your environment.

Setting up the backends to push changes to the MUPDATE Master
-------------------------------------------------------------

On the backends, configuration to be a part of a murder is easy. You just need to configure the backend to be a part of the murder. To do this, set the ``mupdate_server`` option in :cyrusman:`imapd.conf(5)`. Depending on what authentication mechanisms you are using, you may also want to set some or all of the following:

    * mupdate_username
    * mupdate_authname
    * mupdate_realm
    * mupdate_password
    
Once these settings are successfully made, any mailbox operation on the backend will be sent to the mupdate master for confirmation and entry into the mupdate database.

You must also configure at least one user/group using the ``proxyservers`` :cyrusman:`imapd.conf(5)` option. This user should not be an administrator, since this means that anyone who can get hold of your proxy servers now has full administrative control on your backend. Example:

::

    admins: cyrus
    proxyservers: murder
    
Keep in mind that you will need to create the proxy user(s) and be sure that they can authenticate to the backend as well. 

.. note::

    Do not set ``proxyservers`` on your frontends. It is also used to determine which servers to create mailboxes on.    

Importing the database from the backend
---------------------------------------

Importing the current mailboxes database is easy, as there is a :cyrusman:`ctl_mboxlist(8)` option to do so. To do the first synchronization, simply change to the cyrus user, and issue a ``ctl_mboxlist -m``.

You may wish to issue a ``ctl_mboxlist -mw`` first to be sure you understand all the operations that this command will perform, since it does require that all mailboxes are unique in the murder namespace.

If everything is configured properly, the mailbox database of the current host will dump to the mupdate master. If there are problems, the most likely cause is a misconfiguration of the authentication settings, or that mupdate might not be running on the master. Using :cyrusman:`mupdatetest(8)` may be helpful in this case (it establishes an authenticated connection to the mupdate server, if it can).

It is also useful to have the backends automatically resync the state of their local mailboxes database with the master on start up. You can configure this by adding the following to the START section of :cyrusman:`cyrus.conf(5)` on the backends:

::

    mupdatepush   cmd="ctl_mboxlist -m"
  
This will perform synchronization with the mupdate master each time the backend restarts, bringing the mupdate database up to date with the contents of the backend (and performing ACTIVATE and DELETES as needed to do so).

.. warning::

    If somehow a mailbox exists on two (or more) backend servers, each time one of them synchronizes its database that backend server will become authoritative. Though this should not happen during normal operation of the murder (because of the consistancy guarantees of the MUPDATE protocol, and the fact that mailbox operations are denied if the mupdate master is down), it is possible when first creating the mupdate database or when bringing a new backend server into the murder.
    
Configuring the frontends
-------------------------

Configuring the frontends is a two step process. First, you want to set mupdate_server (and friends) as you did for the backends above. However, because the frontends only talk to the mupdate master via a slave running on the local machine, you will also need to set up a slave on the same machine, in the SERVICES section of :cyrusman:`cyrus.conf(5)`, like so:

::

  # mupdate database service - must prefork at least 1
  mupdate       cmd="mupdate" listen=3905 prefork=1
  
As this is a threaded service, you must prefork at least 1 of them so that the database can be synchronized at startup. Otherwise, the service will not start running until after you recieve an mupdate client connection to the slave (which is not a recommended configuration at this point).

Also change all of your imapd entries to be proxyd, and all of your lmtpd entries to be lmtpproxyd. Your SERVICES section should look like this now:

::

  mupdate       cmd="/usr/cyrus/bin/mupdate" listen=3905 prefork=1

  imap          cmd="proxyd" listen="imap" prefork=5
  imaps         cmd="proxyd -s" listen="imaps" prefork=1
  pop3          cmd="pop3d" listen="pop3" prefork=0
  pop3s         cmd="pop3d -s" listen="pop3s" prefork=0
  kpop          cmd="pop3d -k" listen="kpop" prefork=0
  nntp          cmd="nntpd" listen="nntp" prefork=0
  nntps         cmd="nntpd -s" listen="nntps" prefork=0
  sieve         cmd="timsieved" listen="sieve" prefork=0
  lmtp          cmd="lmtpproxyd" listen="/var/imap/socket/lmtp" prefork=0
  
Note that timsieved does not need a proxy daemon, the managesieve protocol deals with the murder with referrals to the backends internally.

Additionally, you will need entries in :cyrusman:`imapd.conf(5)` to indicate the proxy auth name and passwords (if you are using a SASL mechanism that requires them) to the backends. For example, if your backends are ``mail1.andrew.cmu.edu`` and ``mail2.andrew.cmu.edu`` with passwords of ``foo`` and ``bar``, and an auth name of ``murder``::

    mail1_password: foo
    mail2_password: bar
    proxy_authname: murder
    
If your SASL mechanism does not require authnames or passwords (e.g. KERBEROS_V4), then this is not required. Note that we used the same authname as the configured in the proxyservers line in the backend's :cyrusman:`imapd.conf(5)` above.

When you start master on the frontend, a local mailboxes database should automatically synchronize itself with the contents of the mupdate master, and you should be ready to go. Your clients should connect to the frontends, and the frontends will proxy or refer as applicable to the backend servers.    

Additional backend configuration
--------------------------------

If your authentication system requires usernames, passwords, etc, to authenticate, then you will also need to specify proxy_authname (and friends) in the backend imapd.confs as well. This is so that the backends can authenticate to each other to facilitate mailbox moves. (Backend machines will need to be full admins).

Delivering mail
---------------

To deliver mail to your Murder, configure your MTA just as you did before, but instead of connecting directly to lmtpd, it should connect to lmtpproxyd. You can connect to the lmtpproxyd running on the frontend machines, or you can install master and lmtpproxyd on your SMTP servers.

Administration
==============

Keeping the database synced
---------------------------

Consistency in the database is maintained by pushing the current status of the backends to the master, and having the frontends stay up to date with the master's database. Since the frontends resync themselves entirely when they startup, downtime should not at all be a problem. (While they are up they should be continuously receiving database updates, as well as when they lose connection to the master, they will try to reconnect and resync their database upon reconnection)

Provided that the namespace of the backend servers is kept discrete (with no mailboxes existing on the same server), it is not a big deal to resync the mupdate master using ``ctl_mboxlist -m``. If two servers do have the same mailbox, this will need to be resolved before database consistency can be guaranteed.

Moving Mailboxes between backends
---------------------------------

There is currently no 100% foolproof way to do this, however, if you issue a rename command to a frontend (as you would to move a mailbox between partitions), and replace the partition name with the name of the new backend, it will move the mailbox to the indicated backend. You can also use the format ``backend.domain.com!partition`` to move to a specific partition (otherwise the default partition will be used). 

In cyradm, this looks like::

    cyrus.andrew.cmu.edu> rename user.bcyrus user.bcyrus mail2.andrew.cmu.edu!u2

Note that since seen state is stored per-user, it is possible that when moving a shared mailbox users will have strange effects. The general rule is that moving an INBOX will move the entire user (including all sub-mailboxes to the INBOX, and seen state, and subscriptions, and sieve scripts, etc). The seen state is merged with the seen state on the new backend, so that no data is lost (seen state is also the only part left behind on the source backend). In the case of any other mailbox, however, only that individual mailbox is moved. If it is a quota root, the new quota root is instated on the new server, but otherwise quotas can appear to be violated, since each backend only takes care of its own quota.

In general, it's better to leave trees of mailboxes on the same server, and not move submailboxes of inboxes between servers.

Adding additional backend servers
---------------------------------

This is very easy to do, simply configure an empty backend server and set its ``mupdate_server`` parameter to point at the mupdate master. Then, issue mailbox creates to it as you would any other backend server.

Backups
-------

.. :todo:
    xxx, need to write stuff. You don't need to really backup the data on the mupdate master or slaves, since this data can all be generated directly from the backends quite easily.
    
Gotchas
=======

**Clients dealing with a pool of frontend servers**
    Some clients may not be terribly efficient caching connections to a pool of imap servers, this isn't a problem, as such, but it may mean that you will see many more authentications than you are used to.
    
**Kerberos issues**
    If you are using kerberos authentication, you will want to ensure that all your machines are keyed properly, as we have seen problems with different clients trying to authenticate to different services (e.g. imap.imap-pool instead of imap.pool-frontend-1), so test the clients in use in your enviornment and be sure that they work with whatever keying scheme you use.

**Clients dealing with referrals**
    Some clients (we've had particular trouble with pine, though most of these issues have now been resolved and new versions should be OK (that is, pine > 4.44), but as referrals have not been extensively used by any IMAP server until now, referrals are very likely to not work correctly or have surprising effects.
    
**Clients dealing with getting a NO on LSUB commands**
    Some clients (Outlook, for example) may behave poorly if an LSUB command returns a NO, which may be the case if the backend server with the user's inbox is down. We have, for example, seen this result in the deletion of the disconnected message cache.
    
**Behavior of cyradm / some mailbox operations**
    The behaviour of some administrative commands might be slightly unexpected. For example, you can only issue a SETQUOTA to a frontend server if the entire mailbox tree underneath where you are setting the quota exists on the same backend server, otherwise you will need to connect directly to the backend servers to perform the needed changes. Similarly, mailboxes will be created on the same backend server that their parent is in. In order to create them on a different server (or to create a new top level mailbox) you will need to connect directly to the desired backend server.
    
**Subscriptions**
    If users want subscribe to a mailbox other than on their backend home server, they won't be able to, unless you set ``allowallsubscribe: t`` in the backend imapd.confs. This essentially lets any string be subscribed to successfully.
 
**Restarting the mupdate master**
    Because ``ctl_cyrusdb -r`` clears reservations on mailbox, if you restart the mupdate master (and run recovery), then this could (we suspect, very rarely) lead to inconsistencies in the mupdate database.  

Troubleshooting 
===============

**Mailbox operations are being denied**
    This is an indication that the mupdate master may be down. Restart it.
    
**Mailbox operations are not being seen by one or more frontends**
    This indicates that the mupdate process on a slave may have died, you may need to restart master. Alternatively, mupdate will retry connections every 20 seconds or so for about 20 attempts if the master does go down.
    
**A frontend's mailboxes.db is corrupt or out of sync**
    Restart master on the frontend, and have the mupdate process resynch the local database. You may need to remove the local mailboxes database if the corruption is extreme.

**A mailbox's location keeps switching between two (or more) backend hosts.**
    It probably actually exists on both hosts. Delete the mailbox from all but one of the hosts, and run a ``ctl_mboxlist -m`` on the one where you want it to actually live.

**Databases are never created on the frontends/slaves**
    Check to ensure that the mupdate slave process is started, (is prefork=1)    