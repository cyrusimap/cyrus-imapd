Deployment Scenarios
====================

Depending on the target use of Cyrus IMAP, different features and architectures may be used to make optimal use of the Cyrus IMAP features. This chapter briefly touches different deployment scenarios.

Single Server Deployments
-------------------------

In a deployment scenario with a single server, use this checklist to make sure you get the right scalability and functionality;

* In the foreseeable future, might this deployment run for multiple domain name spaces?

* Is this deployment going to close in on it's maximum capacity?

* Is high-availability required?

If the answer to all of these questions is a consistent no, then please continue with the Installation Guide.

Multi Server Deployments
------------------------

A variety of options are available to scale up the deployment of Cyrus IMAP beyond a single server. Each of them has their own set of features, advantages, disadvantages and consequences on day-to-day administration, migration and capacity planning and support. Please consider a deployment that requires scaling up carefully.

Cyrus IMAP Murder
"""""""""""""""""

A Cyrus IMAP Murder groups Cyrus IMAP servers together, allowing the addition and removal of individual Cyrus IMAP servers to and from the group. Functionally, a Cyrus IMAP Murder consists of the following three components;

* one or more frontends, receiving the connections from the clients, authenticating them and depending on the type of Cyrus IMAP Murder, referring the client to the correct backend server, or proxying the connection.
* one or more backends, holding the actual mailbox spool(s).
* a master update server, where the information on the location and Access Control of the mailboxes is kept.

In a Cyrus IMAP Murder, access to mailboxes, regardless of which backend they reside on, is transparent to the user. As such, this particular type of deployment would be recommended for organizations that;

* (are likely to) grow a single Cyrus IMAP server beyond the capacity of said server,
* require shared mailboxes and user mailboxes to be shared regardless of any limitations to whether or not they reside on the same backend server,

Different types of Cyrus IMAP Murder deployments exist. Please see `Cyrus_IMAP_Murder`_ for a review of your options.

IMAP Proxy
""""""""""

An IMAP proxy like NGINX could sit in front of a number of stand-alone Cyrus IMAP servers, proxying client connections through to the correct stand-alone Cyrus IMAP server for a user.

Note that in this type of setup, it is the user authentication that directs the proxy to the correct stand-alone Cyrus IMAP server. As such, shared mailboxes can only exist on the stand-alone Cyrus IMAP server to which the user is proxied &ndash;in other words, on which the user's own mailbox is supposed to exist.


.. _cyrus_imap_murder:

Cyrus IMAP Murder
=================

The Discrete Murder
-------------------

A *discrete* murder - also known as a standard murder - characteristically uses separate frontend and backend servers. At the time of this writing, this is the recommended type of Cyrus IMAP Murder for deployments that require;

* load-balancing and/or high availability of their Cyrus IMAP deployments,
* the ability to take frontends out of rotation, and bring frontends (back) in to rotation without impact on the availability of mailbox spools.
* Authentication to take place before a connection is created or proxied to servers with data, such as would be the case of a perimeter network proxy,
* Have very large numbers of mailboxes, (this one's because of the mupdate RAM consumption)

It is worth noting that in a *discrete* murder, backends only know of the mailboxes that reside in their local mailbox spool(s). Since the user's subscription database is kept on the backend server that hosts their mailbox, should the deployment require that all users can subscribe to all mailboxes that they have permission to in the murder, the setting ``allowallsubscribe`` needs to be set to ``true`` (1). This, however, allows users to subscribe to non-existent mailboxes.

.. todo::
    VERIFY AFOREMENTIONED

The Unified Murder
------------------

A *unified* murder characteristically joins the functional aspects of a server being frontend and backend together onto one single Cyrus IMAP server. A Cyrus IMAP server in a unified murder can thus perform both as a frontend as well as a backend. All backends would thus have all information on all mailboxes on all other backends.

At the time of this writing, but subject to change in the near future, a participating node in a Cyrus IMAP Unified Murder cannot be made a dedicated frontend. This creates a disadvantage over a *discrete* murder, as the frontend function cannot be taken out of rotation without also losing the backend function.

Because in using mailbox creation and transfer routines a participating node cannot be excluded from selection for or availability of the (new) location of the (new) mailbox, no guarantee can exists the participating node does not hold any mailboxes. Short of a deployment specific interface to creating and transferring mailboxes that provides such guarantee, as a logical consequence, to shoot a participating node in a Cyrus IMAP Unified Murder in the head, all mailboxes must be transferred to other backends prior to service shutdown, or the availability of the mailboxes is impacted.

The unified murder also has some great advantages. Since all backends know about all mailboxes in the murder, administrators can choose to not permit subscriptions to non-existent folders. In a discrete murder, where backends know only of the mailboxes in the local mailbox spool(s), such permission is (often) required.

The Shared Murder
-----------------
.. todo:: What is a Shared Murder?

Cyrus Replication
=================

.. todo::
   Describe advantages and disadvantages of using replication (rather than how to configure it as this is described in the Administration Guide).

Hosted Environments
===================

.. todo::
   Describe some of the common ways that hosted Cyrus installations are setup, for example security for admin users, global sieve scripts, etc.

Mailbox Creation Distribution
=============================

By default, when creating a mailbox in Cyrus IMAP:

* the backend with the most free disk space is selected on the Murder frontend
* the partition with the most free disk space is selected on the backend

This may not be the most appropriate backend or partition to create the new mailbox on, and Cyrus IMAP therefor allows for a variety of additional modes of calculating and selecting the most appropriate backend and partition. The exact mode for the selection is controlled with the ``imapd.conf`` setting ``serverlist_select_mode`` on the frontend and ``partition_select_mode`` on the backend.

Alternatively, a default backend can be configured with the ``defaultserver`` setting on a frontend, and a default partition can be configured with the ``defaultpartition`` on a backend.

As usual, details and guidelines are available in the Administrator Guide and the Configuration Reference.

.. todo::
    Make the remark above a general one, and provide a link to the administrator guide and configuration reference ? (how ?)

