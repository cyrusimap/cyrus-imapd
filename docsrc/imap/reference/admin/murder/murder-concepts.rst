.. _murder_concepts:

======================
Cyrus Murder: Concepts
======================

The Cyrus IMAP Aggregator transparently distributes IMAP and POP 
mailboxes across multiple servers. Unlike other systems for load 
balancing IMAP mailboxes, the aggregator allows users to access 
mailboxes on any of the IMAP servers in the system.

Note that although this document focuses on IMAP and POP, the same
concepts also apply to NNTP and HTTP (CalDAV, CardDAV, RSS).



Overview
========

Scaling a service usually takes one of two paths:

1. Buy bigger and faster machines
    This approach is obvious and (hopefully) easy, though at some point 
    software tuning becomes necessary to take advantage of the bigger 
    machines. However, if one of these large machines go down, then your 
    entire system is unavailable. 
2. Distribute the load across multiple machines. 
    The second approach has the benefit that there is no longer a single 
    point of failure and the aggregate cost of multiple machines may be 
    significantly lower than the cost of a single large machine. However, 
    the system may be harder to implement as well as harder to manage. 

In the IMAP space, the approach of buying a larger machine is pretty 
obvious. Distributing the load is a bit trickier since there is no 
concept of mailbox location in IMAP (excluding :rfc:`2193` mailbox 
referrals, which are not widely implemented by clients). Clients 
traditionally assume that the server they are talking to is the server 
with the mailbox they are looking for. 

The approaches to distributing the load among IMAP servers generally 
sacrifice the unified system image. For pure email, this is an 
acceptable compromise; however, trying to share mailboxes becomes 
difficult or even impossible. Specific examples can be found in `Appendix 
A: DNS Name Load Balancing`_ and `Appendix B: IMAP Multiplexing`_). 

We propose a new approach to overcome these problems. We call it the Cyrus
IMAP Aggregator. The Cyrus aggregator takes a :ref:`murder <def_murder>` of IMAP
servers and presents a server independent view to the clients. That is, 
**all the mailboxes across all the IMAP servers are aggregated to a single 
image**, thereby appearing to be only one IMAP server to the clients. 

Architecture
============

The Cyrus IMAP Aggregator has three classes of servers: 
    1. IMAP frontend, 
    2. IMAP backend, and 
    3. MUPDATE. 
    
The frontend servers act as the primary communication point between the 
end user clients and the backend servers. The frontends use the MUPDATE
server as an authoritative source for mailbox names, locations, and 
permissions. The backend servers store the actual IMAP data (and keep 
the MUPDATE server appraised as to changes in the Mailbox list). 

Backend Servers
--------------- 

The backend servers serve the actual data and are fully functional 
standalone IMAP servers that serve a set of mailboxes. Each backend 
server maintains a local mailboxes database that lists what mailboxes 
are available on that server. 

The imapd processes on a backend server can stand by themselves, so that 
each backend IMAP server can be used in isolation, without a MUPDATE 
server or any frontend servers. However, they are configured so that 
they won't process any mailbox operations (CREATE, DELETE, RENAME, 
SETACL, etc) unless the master MUPDATE server can be contacted and 
authorizes the transaction. 

In this mode, the imapd processes update the local mailboxes database 
themselves. Additionally, on a CREATE they need to reserve a place with 
the MUPDATE server to insure that other backend servers aren't creating 
the same mailbox before proceeding. Once the local aspects of mailbox 
creation are complete, the mailbox is activated on the MUPDATE server, 
and is considered available to any client through the frontends. 

Frontend Servers
-----------------

The frontend servers, unlike the backend servers, are fully 
interchangeable with each other and the frontend servers can be 
considered 'dataless'; any loss of a proxy results in no loss of data. 
The only persistent data that is needed (the mailbox list) is kept on 
the MUPDATE master server. This list is synchronized between the 
frontend and the MUPDATE master when the frontend comes up. 

The list of mailboxes in the murder is maintained by the MUPDATE server. 
The MUPDATE protocol is described at :rfc:`3656`. 

For IMAP service on a frontend, there are two main types of processes, 
the proxyd and the mupdate (slave mode) synchronization process. The 
proxyd handles the IMAP session with clients. It relies on a consistent 
and complete mailboxes database that reflects the state of the world. It 
never writes to the mailboxes database. Instead, the mailboxes database 
is kept in sync with the master by a slave mupdate process.

Mail Delivery
-------------

The incoming mail messages go to an lmtp proxy (either running on a 
frontend, a mail exchanger, or any other server). The lmtp proxy running 
on the frontend server uses the master MUPDATE server to determine the 
location of the destination folder and then transfers the message to the 
appropriate backend server via LMTP. If the backend is not up (or 
otherwise fails to accept the message), then the LMTP proxy returns a 
failure to the connected MTA. 

If a sieve script is present, the lmtp proxy server must do the 
processing as the end result of the processing may result in the mail 
message going to a different backend server than where the user's INBOX 
is. 

.. note::
    The current implementation runs SIEVE on the backend servers, and
    holds the requirement that all of a user's mailboxes live on the
    same backend.

Clients
-------

Clients that support :rfc:`2193` IMAP referrals can bypass the 
aggregator frontend. See `IMAP Referrals`_ for more details. 

Clients are encouraged to bypass the frontends via approved mechanisms. 
This should result in better performance for the client and less load 
for the servers.

.. Note::
    Sites choosing to locate front ends in a DMZ, or other isolated
    network segment, should disable IMAP Referrals which might lead
    clients to attempt impossible actions, such as direct access to
    back ends which are firewalled. Please consult
    :cyrusman:`imapd.conf(5)` for details of the
    ``proxyd_disable_mailbox_referrals`` setting.

Implementation
==============

Assumptions
-----------

* Operations that change the mailbox list are (comparatively) rare. 
  The vast majority of IMAP sessions do not manipulate the state of the
  mailbox list.

* Read operations on the mailbox list are very frequent.

* A mailbox name must be unique among all the back end servers.

* The MUPDATE master server will be able to handle the load from the
  frontend, backend, and LMTP proxy servers. Currently, the MUPDATE
  master can be a bottleneck in the throughput of mailbox operations,
  but as the MUPDATE protocol allows for slave server to act as
  replicas, it is theoretically possible to reduce the load of read
  operations against the master to a very low level.

* IMAP clients are not sensitive to somewhat loose mailbox tree
  consistency, and some amount of consistency can be sacrificed for
  speed. As is, IMAP gives no guarantees about the state of the mailbox
  tree from one command to the next. However, it's important to note
  that different IMAP sessions do communicate out of band: two sessions
  for the same client should see sensible results. In the Murder case,
  this means that the same client talking to two different frontends
  should see sensible results.

* A single IMAP connection should see consistent results: once an
  operation is done, it is done, and needs to be reflected in the
  current session. The straightforward case that must work correctly is
  (provided there is no interleaved DELETE in another session)::

    A001 CREATE INBOX.new
    A002 SELECT INBOX.new

* Accesses to non-existent mailboxes are rare.

Authentication
--------------

The user authenticates to the frontend server via any supported SASL 
mechanism or via plaintext. If authentication is successful, the front 
end server will authenticate to the backend server using a SASL 
mechanism (in our case KERBEROS_V4 or GSSAPI) as a privileged user. This 
user is able to switch to the authorization of the actual user being 
proxied for and any authorization checks happen as if the user actually 
authenticated directly to the backend server. Note this is a native 
feature of many SASL mechanisms and nothing special with the aggregator. 

To help protect the backends from a compromised frontends, all 
administrative actions (creating users, top level mailboxes, quota 
changes, etc) must be done directly from the client to the backend, as 
administrative permissions are not granted to any of the proxy servers. 
IMAP Referrals provide a way to accomplish this with minimal client UI 
changes.

Subscriptions
-------------

``[LSUB, SUBSCRIBE, UNSUBSCRIBE]``

The frontend server directs the LSUB to the backend server that has 
the user's INBOX. As such, the backend server may have entries in the 
subscription database that do not exist on that server. The frontend 
server needs to process the list returned by the backend server and 
either remove or tag with \\NoSelect the entries which are not currently 
active within the murder. 

If the user's INBOX server is down and the LSUB fails, then the 
aggregator replies with NO with an appropriate error message. Clients 
should not assume that the user has no subscriptions (though apparently 
some clients do this). 



Finding a Mailbox
-----------------

``[SETQUOTA, GETQUOTA, EXAMINE, STATUS]``

The frontend machine looks up the location of the mailbox, connects 
via IMAP to the backend server, and issues the equivalent command there.
A quota root is not allowed to span across multiple servers. 
At least, not with the semantics that it will be inclusive across the murder.

``[SELECT]``

    To SELECT a mailbox:

    1. proxyd: lookup foo.bar in local mailboxes database

    2. if yes, proxyd -> back end: send SELECT

    3. if no, proxyd -> mupdate slave -> mupdate master: send a ping
       along the UPDATE channel in order to ensure that we have received
       the latest data from the MUPDATE master.

    4. if mailbox still doesn't exist, fail operation

    5. if mailbox does exist, and the client supports referrals, refer
       the client. Otherwise continue as a proxy with a selected mailbox.

    SELECT on mailboxes that do not exist are much more expensive but
    the assumption is that this does not frequently occur (or if it
    does, it is just after the mailbox has been created and the
    frontend hasn't seen the update yet).

Operations within a Mailbox
---------------------------

``[APPEND, CHECK, CLOSE, EXPUNGE, SEARCH, FETCH, STORE, UID]``

These commands are sent to the appropriate backend server. 
The aggregator does not need to modify any of these commands 
before sending them to the backend server.

COPY
----

COPY is somewhat special as it acts upon messages in the currently
SELECT'd mailbox but then interacts with another mailbox.

In the case where the destination mailbox is on the same backend server 
as the source folder, the COPY command is issued to the backend
server and the backend server takes care of the command.

If the destination folder is on a different backend server, the 
frontend intervenes and does the COPY by FETCHing the messages from the 
source backend server and then APPENDs the messages to the destination server.

Operations on the Mailbox List
------------------------------

``[CREATE, DELETE, RENAME, SETACL]``

    These commands are all done by the backend server using the MUPDATE
    server as a lock manager. Changes are then propagated to the frontend
    via the MUPDATE protocol.

``[LIST]``

    LIST is handled by the frontend servers; no interaction is
    required with the backend server as the front ends have a local
    database that is never more than a few seconds out of date.

``[CREATE]``
    
    CREATE creates the mailbox on the same backend server as the
    parent mailbox. If the parent exists but exists on multiple backend 
    servers, if there is no parent folder, a tagged NO response is
    returned.

    When this happens, the administrator has two choices. He may
    connect directly to a backend server and issue the CREATE on that
    server. Alternatively, a second argument can be given to CREATE
    after the mailbox name. This argument specifies the specific host
    name on which the mailbox is to be created.

    The following operations occur for CREATE on the frontend:

    * proxyd: verify that mailbox doesn't exist in MUPDATE mailbox list.

    * proxyd: decide where to send CREATE (the server of the parent
      mailbox, as top level mailboxes cannot be created by the proxies).

    * proxyd -> back end: duplicate CREATE command and verifies that
      the CREATE does not create an inconsistency in the mailbox list
      (i.e. the folder name is still unique).

    The following operations occur for CREATE on the backend:

    * imapd: verify ACLs to best of ability (CRASH: aborted)

    * imapd: start mailboxes transaction (CRASH: aborted)

    * imapd may have to open an MUPDATE connection here if one doesn't
      already exist

    * imapd -> MUPDATE: set foo.bar reserved (CRASH: MUPDATE externally
      inconsistent)

    * imapd: create foo.bar in spool disk (CRASH: MUPDATE externally
      inconsistent, back end externally inconsistent, this can be
      resolved when the backend comes back up by clearing the state from
      both MUPDATE and the backend)

    * imapd: add foo.bar to mailboxes dataset (CRASH: ditto)

    * imapd: commit transaction (CRASH: ditto, but the recovery can
      activate the mailbox in mupdate instead)

    * imapd -> MUPDATE: set foo.bar active (CRASH: committed)

    Failure modes: Above, all backend inconsistencies result in the
    next CREATE attempt failing. The earlier MUPDATE inconsistency
    results in any attempts to CREATE the mailbox on another backend
    failing. The latter one makes the mailbox unreachable and
    un-createable. Though, this is safer than potentially having the
    mailbox appear in two places when the failed backend comes back
    up.

``[RENAME]``

    RENAME is only interesting in the cross-server case. In this case
    it issues a (non-standard) XFER command to the backend that
    currently hosts the mailbox, which performs a binary transfer of
    the mailbox (and in the case of a user's inbox, their associated
    seen state and subscription list) to the new backend. During this
    time the mailbox is marked as RESERVED in mupdate, and when it is
    complete it is activated on the new server in MUPDATE. The
    deactivation prevents clients from accessing the mailbox, and
    causes mail delivery to temporarily fail.

.. _imap_referrals:    

IMAP Referrals
--------------

If clients support IMAP Mailbox Referrals (:rfc:`2193`), the client can
improve performance and reduce the load on the aggregator by using the
IMAP referrals that are sent to it and going to the appropriate 
backend servers.

The frontend servers will advertise the ``MAILBOX-REFERRALS``
capability. The backend servers will also advertise this capability
(but only because they need to refer clients while a mailbox is moving
between servers).

Since there is no way for the server to know if a client supports
referrals, the Cyrus IMAP Aggregator will assume the clients do not
support referrals unless the client issues a RLSUB or a RLIST command.

Once a client issues one of those commands, then the aggregator will
issue referrals for any command for which the client may safely contact
the IMAP server directly. Most commands performing operations within
a mailbox (cf Section 3.3) fall into this category. Some commands will
not be possible without a referrals-capable client (such as most
commands done as administrator).

:rfc:`2193` indicates that the client does not stick the referred
server. As such the SELECT will get issued to the frontend server and
not the referred server. Additionally, CREATE, RENAME, and DELETE get
sent to the frontend which will proxy the command to the correct 
backend server.

POP
---

POP is easy given that POP only allows access to the user's INBOX. When
it comes to POP, the IMAP Aggregator acts just like a :ref:`multiplexor
<appendix-b-imap-multiplexing>`. The user authenticates to frontend
server. The frontend determines where the user's INBOX is located and
does a direct pass through of the POP commands from the client to the
appropriate backend server.

MUPDATE
-------

The mupdate (slave) process (one per frontend) holds open a MUPDATE
connection and listens for updates from the MUPDATE master server (as
backends inform it of updates). The slave makes these modifications on
the local copy of the mailboxes database.

Analysis
========

Mailboxes Database
------------------

A benefit of having the mailbox information on the frontend is that 
LIST is very cheap. The frontend servers can process this request 
without having to contact each backend server. 

We're also assuming that LIST is a much more frequent operation than any 
of the mailbox operations and thus should be the case to optimize. (In 
addition to the fact that any operation that needs to be forwarded to a 
backend needs to know to which backend it is being forwarded, so lookups 
in the mailbox list are also quite frequent). 

Failure Mode Analysis
---------------------

What happens when a backend server comes up?
#############################################

    Resynchronization with the MUPDATE server. Any mailboxes that exist
    locally but are not in MUPDATE are pushed to MUPDATE. Any mailboxes
    that exist locally but are in MUPDATE as living on a different
    server are deleted. Any mailboxes that do not exist locally but
    exist in MUPDATE as living on this server are removed from MUPDATE.

What happens when a frontend server comes up? 
##############################################

    The only thing that needs to happen is for the frontend to connect
    to the MUPDATE server, issue an UPDATE command, and resynchronize
    its local database copy with the copy on the master server.
    
Where's the true mailboxes file? 
################################

    The MUPDATE master contains authoritative information as to the
    location of any mailbox (in the case of a conflict), but the
    backends are authoritative as to which mailboxes actually exist.
    
Summary of Benefits
-------------------

* **Availability** - By allowing multiple frontends, failures of the
  frontend only result in a reduction of capacity. Users currently
  connected still lose their session but can just reconnect to get back
  online.
  
    * The failure of the backends will result in the loss of
      availability. However, given that the data is distributed among
      multiple servers, the failure of a single server does not result
      the entire system being down. Our experience with AFS was that
      this type of partitioned failure was acceptable (if not ideal).
    * The failure of the mupdate master will cause write operations to
      the mailbox list to fail, but accesses to mailboxes themselves (as
      well as read operations to the mailbox list) will continue
      uninterrupted.
    * At this point, there may be some ideas but no plans for providing
      a high availability solution which would allow for backend
      servers or the MUPDATE server to fail with no availability impact.
      
* **Load scalability** - No specific benchmarks have been run to
  show that this system actually performs better. However, it is clear
  that it scales to a larger number of users than a single server
  architecture would. Though, based on the fact that there are no further
  performance problems beyond when running a single machine,
  but handling about 20% more concurrent users, this is a success.
  
* **Management benefits** - As with AFS, administrators have the
  flexibility of placement of data on the servers, "live" move of data
  between servers,
  
* **User benefits** - The user only needs to know a single server name
  for configuration. The same name can be handed out to all users.
  
    * Users don't lose the ability to share their folders and those
      folders are visible to other users. A user's INBOX folder
      hierarchy can also exist across multiple machines.
    
Futures
=======

It would be nice to be able to replicate the messages in a mailbox
among multiple servers and not just do partitioning for availability.

We are also evaluating using the aggregator to be able to provide
mailboxes to the user with a different backup policy or even different
"quality of service." For example, we are looking to give users a
larger quota than default but not back up the servers where these
mailboxes exist.

There is possibility that LDAP could be used instead of MUPDATE.
However at this time the replication capabilities of LDAP are
insufficient for the needs of the Aggregator.

It would be nice if quotaroots had some better semantics with respect
to the murder (either make them first-class entities, or have them
apply across servers).

Appendices
==========

Appendix A: DNS Name Load Balancing
-----------------------------------

One method of load balancing is to use DNS to spread your users to 
multiple machines. 

One method is to create a DNS CNAME for each letter of the alphabet. 
Then, each user sets their IMAP server to be the first letter of their 
userid. For example, the userid 'tom' would set his IMAP server to be 
``T.IMAP.ANDREW.CMU.EDU`` and ``T.IMAP.ANDREW.CMU.EDU`` would resolve to 
an actual mail server. 

Given that this does not provide a good distribution, another option is 
to create a DNS CNAME for each user. Using the previous example, the 
user 'tom' would set his IMAP server to be ``TOM.IMAP.ANDREW.CMU.EDU`` 
which then points to an actual mail server. 

The good part is that you don't have all your users on one machine and 
growth can be accommodated without any user reconfiguration. 

The drawback is with shared folders. The mail client now must support 
multiple servers and users must potentially configure a server for each 
user with a shared folder he wishes to view. Also, the user's INBOX 
hierarchy must also reside on a single machine. 

.. _appendix-b-imap-multiplexing:

Appendix B: IMAP Multiplexing
-----------------------------

Another method of spreading out the load is to use IMAP multiplexing.
This is very similar to the IMAP Aggregator in that there are frontend
and backend servers. The frontend servers do the lookup and then
forward the request to the appropriate backend server.

The multiplexor looks at the user who has authenticated. Once the user
has authenticated, the frontend does a lookup for the backend server
and then connects the session to a single backend server. This provides
the flexibility of balancing the users among any arbitrary server but
it creates a problem where a user can not share a folder with a user on
a different backend server.

Multiplexors references:

    * `Netscape Messaging Multiplexor`_
    * `Paul Fleming's IMAP Proxy`_
    * `Perdition IMAP Proxy`_
    * `Mirapoint Message Director`_ - This is a hardware solution that
      also does content filtering.

.. _Netscape Messaging Multiplexor: http://docs.oracle.com/cd/E19079-01/nscp.mes.svr40/816-6037-10/
.. _Paul Fleming's IMAP Proxy: http://www.siumed.edu/~pfleming/development/email/
.. _Perdition IMAP Proxy: http://horms.net/projects/perdition/
.. _Mirapoint Message Director: http://owmessaging.com/Mirapoint_Message_Server

Appendix C: Definitions
-----------------------

IMAP connection
    A single IMAP TCP/IP session with a single IMAP server is a
    "connection".
    
client
    A client is a process on a remote computer that communicates with
    the set of servers distributing mail data, be they ACAP, IMAP,
    or LDAP servers. A client opens one or more connections to
    various servers.
    
mailbox tree
    The collection of all mailboxes at a given site in a namespace is
    called the mailbox tree. Generally, the user Bovik's personal data
    is found in ``user.bovik``.
    
mailboxes database
    A local database containing a list of mailboxes known to a
    particular server.
    
mailbox dataset
    The store of mailbox information on the ACAP server is the "mailbox
    dataset".
    
mailbox operation
    The following IMAP commands are "mailbox operations": CREATE,
    RENAME, DELETE, and SETACL.
    
MTA
    The mail transport agent (e.g. sendmail, postfix).
    
.. _def_murder:    

Murder of IMAP servers
    A grouping of IMAP servers. It sounded cool for crows so we decided
    to use it for IMAP servers as well.
    
quota operations
    The quota IMAP commands (GETQUOTA, GETQUOTAROOT, and SETQUOTA)
    operate on mailbox trees. In future versions of Cyrus, it is
    expected that a quotaroot will be a subset of a mailbox tree that
    resides on one partition on one server. For rationale, see section
    xxx.
