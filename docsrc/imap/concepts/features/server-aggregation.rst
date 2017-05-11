.. _imap-features-murder:

======================================
Cyrus IMAP Murder (Server Aggregation)
======================================

A Cyrus IMAP Murder consists of a group of Cyrus IMAP servers
functioning as one large, transparent IMAP cluster.

In a Cyrus IMAP Murder, one or more servers with a *frontend* role
receive client connections, and proxy connections through to one of the
servers with a *backend* role -- these host the payload for the cluster
-- on the basis of where the current mailbox selected resides.

This makes access to mailboxes transparent to the client, even though
different mailboxes to which the user has access reside on different
servers.

To illustrate, let John's IMAP client connect to ``imap.example.org``:

.. graphviz::

    digraph john {
            rankdir = LR;
            splines = true;
            overlab = prism;

            edge [color=gray50, fontname=Calibri, fontsize=11];
            node [shape=record, fontname=Calibri, fontsize=11];

            "Desktop Client" -> "imap.example.org" [label="Client Connection"];
        }

John's mailbox may not reside on the node that the client connects to,
though, and instead be located on a :term:`backend` node -- as is
typical for larger deployments.

The client connection is therefore to be proxied to the appropriate
:term:`backend` node.

.. graphviz::

    digraph john {
            rankdir = LR;
            splines = true;
            overlab = prism;

            edge [color=gray50, fontname=Calibri, fontsize=11];
            node [shape=record, fontname=Calibri, fontsize=11];

            "Desktop Client" -> "imap.example.org" [label="Client Connection"];
            "imap.example.org" -> "backend1.example.org" [label="Proxied Connection"];
        }

It is not at all uncommon to (reverse) proxy client connections like
this (a task that ``imap.example.org`` takes on in this example).

In the case of webservers for example, reverse proxying is an very
common practice:

.. graphviz::

    digraph www {
            rankdir = LR;
            splines = true;
            overlab = prism;

            edge [color=gray50, fontname=Calibri, fontsize=11];
            node [shape=record, fontname=Calibri, fontsize=11];

            "Desktop Browser" -> "http://www.example.org/" [label="Client Connection"];

            "http://www.example.org/" -> "assets1.example.org" [label="Static Content"];
            "http://www.example.org/" -> "www1.example.org" [label="Dynamic Content"];
        }

In the case of reverse web proxies, the proxy looks at (for example)
the request URI, and based on a set of rules, forwards (proxies) the
request on to the appropriate (internal) node. This architecture allows
application servers (www[0-9]+.example.org) to be scaled up and down by
application processing needs *separately* from the few web servers
typically needed to serve static files such as images and scripts (that
require no server-side processing).

In the case of IMAP, a commonly used IMAP proxy is NGINX. However,
NGINX can proxy John's connection to only one backend at a time. NGINX
allows an external script to respond with a target backend address
based on the authentication of the user [#]_.

As such, NGINX is a socket proxy, and not a fully-featured
application proxy:

.. graphviz::

    digraph joe {
            rankdir = LR;
            splines = true;
            overlab = prism;

            edge [color=gray50, fontname=Calibri, fontsize=11];
            node [shape=record, fontname=Calibri, fontsize=11];

            "imap.example.org" [label="imap.example.org\n(NGINX)"];
            "backend1.example.org" [label="backend1.example.org\n(user/john)"];
            "backend2.example.org" [label="backend2.example.org\n(user/jane)"];
            "Desktop Client" -> "imap.example.org" [label="Client Connection"];
            "imap.example.org" -> "backend1.example.org" [label="Proxied Connection",color="green"];
            "imap.example.org" -> "backend2.example.org" [label="Not Available",color="red"];
        }

This means that John could not open a mailbox that does not reside on
the same backend node his client connection is proxied to, and John nor
Jane can share their mailboxes with one another [#]_.

For the proxy to be fully-featured, the proxy would need to catch all
IMAP commands that John's client issues [#]_, and determine what is the
most appropriate backend to serve the request -- not unlike the
aforementioned web proxies.

So, when John's client issues a ``SELECT INBOX``, the connection is to
be proxied to ``backend1.example.org``, but when John's client is to
issue a ``SELECT "Other Users/jane"``, the connection is to be proxied
to ``backend2.example.org``.

**This** is where the Cyrus IMAP Murder functionality kicks in:

*   Mailbox location data is maintained through a central MUPDATE
    server.

    Each backend submits its list of local mailboxes when it starts up,
    and maintains new, renamed and deleted mail folders, and Access
    Control List (ACL) changes while running.

*   The MUPDATE server replicates its aggregated database from across
    all backends to all nodes with a :term:`frontend` role.

*   Nodes with a :term:`frontend` role capture connections on the
    protocol level and decide where the connection needs to be proxied
    to

*   Nodes with a :term:`frontend` role also arbiter between backends
    when a message is moved from John's ``INBOX`` to Jane's ``INBOX`` or
    vice-versa.

Use-Cases for the Cyrus IMAP Murder
===================================

*   Transparent access to content distributed over multiple (backend)
    nodes,

*   Sharing content distributed over multiple nodes (calendars, address
    books, mail folders),

*   High-availability and/or load-balanced frontends,

*   Transport Layer Security termination, so frontends do connection
    encryption and backends spend CPU cycles on mailboxes.

*   Access Control enforcement at the perimeter

Administrators of larger infrastructures will be aware of the fact that
vertical scaling a single node only stretches so far.

When mail environments are to serve many thousands of users' mailboxes
(or more), multiple nodes are put to purpose, effectively scaling
horizontally rather than vertically.

In such environments it is likely that multiple backends are used to
store mailboxes, and depending on the requirements for the environment,
users with mailboxes distributed over these backends may be required to
share content with one another -- shared folders.

Should John be required to be able to share one or more of his mailboxes
with Jane, or vice-versa, one could attempt to ensure both users'
mailboxes reside on the same backend node (read: both users' client
connections are proxied to the same backend node).

In larger environments however (again), users that are required to be
able to share content often results in groups of several dozens,
hundreds or even thousands, making it very, very hard to maintain.

Cyrus IMAP Murder Topologies
============================

A Cyrus IMAP Murder topology serves the need to **aggregate** the
mailboxes hosted by more than one Cyrus IMAP server with the *backend*
role.

Cyrus IMAP can do so in either one of three topologies:

#.  :ref:`imap-features-murder-discrete`

    The frontend and backend servers are separate.

#.  :ref:`imap-features-murder-replicated`

    All backends have access to all mailboxes.

#.  :ref:`imap-features-murder-unified`

    There's no distinction between backends and frontends, and all
    backends perform frontend roles, but not all frontends are
    automatically also backends.

.. NOTE::

    In the context of a Cyrus IMAP Murder, the terms *frontend* and
    *backend* are server roles, and while these roles may be performed
    by separate servers, such as in a
    :ref:`imap-features-murder-discrete`, but they need not be, such as
    in a :ref:`imap-features-murder-unified`.

All Cyrus IMAP Murder topologies exchange information about where
mailboxes reside through the MUPDATE protocol (:rfc:`3656`).

.. _imap-features-murder-discrete:

Discrete Murder
---------------

The simplest discrete murder topology puts each role on one or more
separate systems;

*   the MUPDATE master (m),

*   one or more frontend servers (f),

*   one or more backend servers (b).

Each of the systems communicates with one another via the following
connection model:

.. graphviz::
    :caption: Connection model for a Discrete Murder topology

    digraph {
            rankdir=LR;
            nodesep=2;

            splines = true;
            overlab = prism;

            edge [color=gray50, fontname=Calibri, fontsize=11];
            node [shape=record, fontname=Calibri, fontsize=11];

            "m" -> "f+" [dir=back];
            "m" -> "b+" [dir=back];

            "f+" -> "b+";
        }

(1) A frontend (f) connects to the mupdate (m) master server and
    receives updates from the mupdate master server.

    The frontend continues to receive updates about deleted, renamed or
    created mailboxes for as long as the connection from the frontend to
    the mupdate master server exists.

    The frontend reconnects if the connection is interrupted.

(2) A backend connects to the mupdate master server and pushes updates
    to the mupdate server.

    A backend reconnects to the mupdate master server as needed.

Murder Backend Startup Process
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. graphviz::
    :caption: Communication during Backend startup (1)

    digraph {
            rankdir=LR;
            nodesep=2;

            splines = true;
            overlab = prism;

            edge [color=gray50, fontname=Calibri, fontsize=11];
            node [shape=record, fontname=Calibri, fontsize=11];

            "m" -> "f+" [color=white];
            "m" -> "b+" [color=red,dir=back,label="(1)"];

            "f+" -> "b+" [color=white];
        }

.. graphviz::
    :caption: Communication during Backend startup (2)

    digraph {
            rankdir=LR;
            nodesep=2;

            splines = true;
            overlab = prism;

            edge [color=gray50, fontname=Calibri, fontsize=11];
            node [shape=record, fontname=Calibri, fontsize=11];


            "m" -> "f+" [color=red,label="(2)"];
            "m" -> "b+" [color=green,dir=back,label="(1)"];

            "f+" -> "b+" [color=white];
        }

(1) The backend (b) pushes its list of mailboxes to the mupdate master
    (m) using ``ctl_mboxlist -m``.

    The list of local mailboxes on the backend is routinely compared
    with the current state of the rest of the murder topology;

    *   Mailboxes that exist locally but are not in MUPDATE are pushed
        to the mupdate master server.

    *   Mailboxes that exist locally but for which the mupdate master
        server has an entry for the mailbox to live on a different
        server are deleted locally.

        .. NOTE::

            Additional options to
            :ref:`imap-reference-manpages-systemcommands-ctl_mboxlist` allow the deletion
            to be prevented.

    *   Mailboxes that do not exist locally but exists in MUPDATE as
        living locally are removed from the mupdate master server.

(2) The mupdate (m) master server pushes updates to the existing list of
    mailboxes to the frontend (f) server.

.. graphviz::

    digraph {
            rankdir=LR;
            nodesep=2;

            splines = true;
            overlab = prism;

            edge [color=gray50, fontname=Calibri, fontsize=11];
            node [shape=record, fontname=Calibri, fontsize=11];

            "m" -> "f+" [dir=both];
            "m" -> "b+" [dir=both];

            "f+" -> "b+" [dir=both];
        }

.. _imap-features-murder-replicated:

Replicated Murder
-----------------

.. NOTE::

    This section needs to be written. Would you like to :ref:`help out <contribute-docs>`?

.. todo:: Please write me.

.. _imap-features-murder-unified:

Unified Murder
--------------

.. NOTE::

    This section needs to be written. Would you like to :ref:`help out <contribute-docs>`?

.. todo:: Please write me.

Back to :ref:`imap-features`

.. rubric:: Footnotes

.. [#]

    See also: :ref:`imap-howto-nginx-proxy`.

.. [#]

    More literally speaking, John and Jane can *share*, just neither can
    make use of the privilege.

.. [#]

    Including but not limited to ``SELECT``, ``UID MOVE``, ``RENAME``,
    etc.

.. glossary::

    frontend
	  the user interface

.. glossary::

	backend
	  the server components
