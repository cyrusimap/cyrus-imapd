=================
Cyrus IMAP Murder
=================

A Cyrus IMAP Murder serves the need to **aggregate** the mailboxes
hosted by more than one :term:`backend`, so that the access for
clients is transparent.

To illustrate, let Joe's IMAP client connect to ``imap.example.org``:

.. graphviz::

    digraph joe {
            rankdir = LR;
            splines = true;
            overlab = prism;

            edge [color=gray50, fontname=Calibri, fontsize=11];
            node [shape=record, fontname=Calibri, fontsize=11];

            "Desktop Client" -> "imap.example.org" [label="Client Connection"];
        }

Joe's mailbox may not reside on the node that the client connects to,
though, and instead be located on a :term:`backend` node -- as is
typical for larger deployments.

The client connection is therefore to be proxied to the appropriate
:term:`backend` node.

.. graphviz::

    digraph joe {
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

In the case of reverse web proxies, an application looks at (for
example) the request URI, and based on a set of rules, forwards
(proxies) the request on to the appropriate (internal) node.

In the case of IMAP, a commonly used IMAP proxy is NGINX. However,
NGINX can proxy Joe's connection to only one backend at a time. NGINX
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
            "backend1.example.org" [label="backend1.example.org\n(user/joe)"];
            "backend2.example.org" [label="backend2.example.org\n(user/jane)"];
            "Desktop Client" -> "imap.example.org" [label="Client Connection"];
            "imap.example.org" -> "backend1.example.org" [label="Proxied Connection",color="green"];
            "imap.example.org" -> "backend2.example.org" [label="Not Available",color="red"];
        }

This means that Joe could not open a mailbox that does not reside on
the same backend node his client connection is proxied to, and Joe nor
Jane can share their mailboxes with one another.

For the proxy to be fully-featured, the proxy would need to catch all
IMAP commands that Joe's client issues, and determine what is the most
appropriate backend to serve the request -- not unlike the
aforementioned web proxies.

So, when Joe's client issues a ``SELECT INBOX``, the connection is to
be proxied to ``backend1.example.org``, but when Joe's client is to
issue a ``SELECT "Other Users/jane``, the connection is to be proxied
to ``backend2.example.org``.

**This** is where the Cyrus IMAP Murder functionality kicks in:

*   Mailbox location data is maintained through a central MUPDATE
    server.

    Each backend submits its list of local mailboxes when it starts up,
    and maintains new, renamed and deleted mail folders, and Access
    Control List (ACL) changes while running.

*   The MUPDATE server replicates its aggregated database to nodes with
    a :term:`frontend` role.

*   Nodes with a :term:`frontend` role capture connections on the
    protocol level and decide where the connection needs to be proxied
    to.

Use-Cases for the Cyrus IMAP Murder
===================================

*   Transparent access to content distributed over multiple nodes
*   Share content distributed over multiple nodes
*   High-availability and/or load-balanced frontends
*   Access Control enforcement at the perimeter

Administrators of larger infrastructures will be aware of the fact that
vertical scaling a single node only stretches so far.

When mail environments are to serve many thousands of users' mailboxes
(or more), multiple nodes are put to purpose, effectively scaling
horizontally rather than vertically.

In such environment likely multiple backends are used to store
mailboxes, and depending on the requirements for the environment, users
with mailboxes distributed over these backends may be required to share
content with one another -- shared folders.

Should Joe be required to be able to share one or more of his mailboxes
with Jane, or vice-versa, one could attempt to ensure both users'
mailboxes reside on the same backend node (read: both users' client
connections are proxied to the same backend node).

In larger environments however (again), users that are required to be
able to share content often results in groups of several dozens,
hundreds or even thousands, making it very, very hard to maintain.


Cyrus IMAP Murder Topologies
============================

#.  :ref:`devel-imap-murder-discrete`
#.  :ref:`devel-imap-murder-unified`
#.  :ref:`devel-imap-murder-replicated`

.. _devel-imap-murder-discrete:

Discrete Murder
===============

The simplest discrete murder topology splits the roles for the (M)UPDATE
master, one or more (F)rontend servers, and one or more (B)ackend
servers between different compute nodes or Cyrus IMAP instances [#]_.

Each of the systems communicates with one another via the following
connection model:

.. graphviz::
    :caption: Figure 1: Connection model for a Discrete Murder topology

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

(1) A frontend connects to the mupdate master server and receives
    updates from the mupdate master server.

(2) A backend connects to the mupdate master server and pushes updates
    to the mupdate server.

Backend Startup
---------------

A backend node (b) that starts the Cyrus IMAP service is expected to
push its local mailbox database to the MUPDATE server (m).

.. graphviz::
    :caption: Figure 2: Communication during Backend startup (1)

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

Should modifications to the mailbox list be included in this
communication, then the MUPDATE server (m) is responsible for
communicating said changes to frontend nodes (f).

.. graphviz::
    :caption: Figure 3: Communication during Backend startup (2)

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

(1) The backend node (b) pushes its list of mailboxes to (m) using
    ``ctl_mboxlist -m``.

(2) The MUPDATE node (m) pushes changes onward to frontend nodes (f).

Mailbox Creation
----------------

When a mailbox is created by a client (c), the ``CREATE`` command is issued against a
frontend node (f):

.. graphviz::
    :caption: Figure 4: Mailbox Creation (1)

    digraph {
            rankdir=LR;
            nodesep=2;

            splines = true;
            overlab = prism;

            edge [color=gray50, fontname=Calibri, fontsize=11];
            node [shape=record, fontname=Calibri, fontsize=11];

            "c" -> "f+" [color=green,label="(1)"];

            "m" -> "f+" [color=white];
            "m" -> "b+" [color=white];

            "f+" -> "b+" [color=white];
        }

The frontend node (f) proxies the command to the appropriate backend
node (b), under the following considerations:

*   For a new top-level mailbox -- ``user/john`` or ``shared/memo`` --,
    the frontend node selects a backend node using the selection
    criteria configured in :manpage:`imapd.conf(5)`.

*   For a sub-folder of an existing top-level mailbox --
    ``user/john/Spam`` -- the frontend node uses the backend associated
    with the top-level mailbox -- ``user/john``.

.. graphviz::
    :caption: Figure 5: Mailbox Creation (2)

    digraph {
            rankdir=LR;
            nodesep=2;

            splines = true;
            overlab = prism;

            edge [color=gray50, fontname=Calibri, fontsize=11];
            node [shape=record, fontname=Calibri, fontsize=11];

            "c" -> "f+" [color=red,label="(1)"];

            "m" -> "f+" [color=white];
            "m" -> "b+" [color=white];

            "f+" -> "b+" [color=green,label="(2)"];
        }

The backend node, having received a ``CREATE user/john`` command,
attempts to create a reservation in the Cyrus IMAP Murder using the
MUPDATE server (m), and:

*   Responds with an OK should the reservation be successful, or

*   Responds with a NO should the reservation not be successful;

    Reservations may not succeed because;

    1.  The mailbox already exists elsewhere in the Murder,

    2.  The MUPDATE server is not available,

    3.  Any other error for an IMAP server stand-alone or part of a
        murder -- such as no space left, I/O errors, etc.

.. graphviz::
    :caption: Figure 5: Mailbox Creation (2)

    digraph {
            rankdir=LR;
            nodesep=0.5;

            splines = true;
            overlab = prism;

            edge [color=gray50, fontname=Calibri, fontsize=11];
            node [shape=record, fontname=Calibri, fontsize=11];

            "c" -> "f+" [label="(1)"];
            "c" -> "f+" [label="(9)"];

            "m" -> "f+" [label="(8)"];
            "m" -> "b+" [dir=back,label="(3)"];
            "m" -> "b+" [label="(4)"];
            "b+" -> "b+" [label="(5)"];
            "m" -> "b+" [dir=back,label="(7.1)"];
            "f+" -> "b+" [dir=back,label="(7.2)"];

            "f+" -> "b+" [label="(2)"];
        }


.. _devel-imap-murder-unified:

Unified Murder
==============

.. _devel-imap-murder-replicated:

Replicated Murder
=================

.. rubric:: Footnotes

.. [#]

    See also: :ref:`howto-nginx-proxy`.

.. [#]

    Cyrus IMAP instances can create a multi-server topology on a fewer
    compute nodes.

