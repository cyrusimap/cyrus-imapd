.. _imap-features-quic-dispatch:

=========================
QUIC Connection Dispatch
=========================

:cyrusman:`master(8)` can dispatch QUIC services to worker processes,
one worker per connection, the same way it does for TCP. QUIC has no
equivalent of ``accept()`` at the socket layer, though, so this takes a
mechanism of its own. This page describes it: what problem it solves,
and how a worker ends up owning a connection.

The problem: QUIC has no ``accept()``
======================================

For every other service :program:`master` manages, one listening
socket per service is all it needs: the kernel hands each new TCP
connection its own file descriptor via ``accept()``, and
:program:`master` forks (or hands off to an already-forked, idle)
worker to own it from there.

QUIC runs over UDP, which has no such concept. Every QUIC connection
for a given service arrives as datagrams on the *same* rendezvous
socket, distinguished only by a Connection ID (CID) carried in each
packet's QUIC header -- not by a kernel-tracked 4-tuple the way TCP
connections are. So "accepting" a new QUIC connection means
:program:`master` itself has to inspect each incoming datagram,
decide whether it belongs to a connection already in progress or
starts a new one, and route it accordingly -- all before a worker
process ever sees it.

Handing a connection to a worker
=================================

Once :program:`master` has decided a datagram starts a new
connection, it picks (or forks) a worker and gives it everything
needed to carry on: a file descriptor for the connection's incoming
traffic, a second one to send its replies on, and the bytes of the
first datagram, which
:program:`master` already had
to read and parse off the rendezvous socket in order to make that
decision in the first place.

This travels over a dedicated handoff channel, ``QUIC_HANDOFF_FD``
(see ``master/service.h``) -- an ``AF_UNIX`` ``SOCK_SEQPACKET``
connected to the worker at fork time, distinct from the ``LISTEN_FD``
a normal TCP/UDP worker inherits. The payload is a ``struct
quic_handoff``: a pool of CIDs :program:`master` chose for this
connection (see below), the local and peer addresses, and the first
datagram's bytes -- with the descriptors themselves riding alongside
via ``SCM_RIGHTS``. A worker recognizes it's handling a
QUIC service via a ``CYRUS_SERVICE_PROTO=quic`` environment
variable set at fork time (its only way to learn this, since it has no
access to :program:`master`'s own parsed configuration), and if so,
blocks on ``QUIC_HANDOFF_FD`` instead of ``accept()``-ing on
``LISTEN_FD``.

.. graphviz::
    :caption: Handing off one QUIC connection

    digraph {
            rankdir = LR;
            splines = true;

            edge [color=gray50, fontname=Calibri, fontsize=11];
            node [shape=record, fontname=Calibri, fontsize=11];

            "QUIC Client" -> "master\n(rendezvous socket)" [label="first datagram"];
            "master\n(rendezvous socket)" -> "worker" [label="sendmsg()\n(over QUIC_HANDOFF_FD)"];
        }

The one ``sendmsg()`` sent over ``QUIC_HANDOFF_FD`` carries two different
kinds of things:

.. graphviz::
    :caption: What a QUIC_HANDOFF_FD message carries

    digraph {
            rankdir = LR;
            splines = true;

            edge [color=gray50, fontname=Calibri, fontsize=11];
            node [shape=record, fontname=Calibri, fontsize=11];

            msg [label="{sendmsg()|{<c>control|<d>data}}"];
            fd [shape=plaintext, label=<
                <TABLE BORDER="0" CELLBORDER="1" CELLSPACING="0" CELLPADDING="4" COLOR="green4">
                    <TR><TD BGCOLOR="gray85"><B>SCM_RIGHTS</B></TD></TR>
                    <TR><TD>recv_fd: this connection's socketpair end</TD></TR>
                    <TR><TD>send_fd: a dup of the rendezvous socket</TD></TR>
                </TABLE>>];
            payload [shape=plaintext, label=<
                <TABLE BORDER="0" CELLBORDER="1" CELLSPACING="0" CELLPADDING="4">
                    <TR><TD BGCOLOR="gray85"><B>struct quic_handoff</B></TD></TR>
                    <TR><TD>cids[] + ncids</TD></TR>
                    <TR><TD>local_addr + local_addrlen</TD></TR>
                    <TR><TD>peer_addr + peer_addrlen</TD></TR>
                    <TR><TD>pktlen + pkt[]</TD></TR>
                </TABLE>>];

            msg:c -> fd [color=green4];
            msg:d -> payload;
        }

The descriptors are the part that cannot travel as ordinary bytes:
each is a reference to a kernel object, so they ride in the control
message and arrive as new descriptors in the worker, numbered however
that worker's table happened to be arranged.  ``quic_send_handoff()``
takes them as arguments rather than in the struct, and
``quic_recv_handoff()`` returns the worker's numbers for them the same
way.  Both always travel: a connection's own descriptor is a
socketpair, which can't reach the network, so the socket to reply on
has to go with it (see "Sending replies" below).

The rest is a fixed-layout struct copied verbatim into the message
(``sizeof(struct quic_handoff)`` bytes, one ``iovec``), so nothing is
length-prefixed: each variable-length item is a fixed-size buffer with
a separate count beside it. The fields above are in declaration
order.

Relaying a connection's packets
================================

Routing is pure userspace (``master/quic/quic_relay.c``):
:program:`master` keeps the real rendezvous socket for a connection's
entire life and demultiplexes every arriving datagram by CID itself,
relaying each one to the owning worker over an ``AF_UNIX``
``SOCK_SEQPACKET`` socketpair. Every packet a client sends passes
through :program:`master` for the connection's whole life, not just
the first one. Outgoing packets don't: the worker sends those itself (see
"Sending replies" below).

Two hash tables, a CID-to-key-to-record indirection:
``quic_relay_conns`` holds the actual connection record, keyed by its
primary CID
(``quic_relay_add_conn()``), and ``quic_relay_aliases`` redirects
any other registered CID back to that primary key
(``quic_relay_add_alias()``). A connection's record holds its own
end of the socketpair and the client's current peer address (see
"Tracking a moving peer address" below).
``quic_relay_forward()`` looks a packet's DCID up in either table
and, on a hit, relays it -- on a miss, the caller treats the packet
as a possible new connection instead.

The aliases exist so that every CID a connection owns resolves to the
one record. Nothing forces the indirection -- a userspace table can
key on the CID directly -- but storing the record itself under each
of its CIDs would leave
several entries pointing at one socketpair fd, so teardown would need
refcounting to know which removal was the last. An alias holds only a
copy of the primary key, leaving exactly one owning entry. Only the
primary is looked up directly; the rest redirect to it:

.. graphviz::
    :caption: The two relay tables, with two connections registered

    digraph {
            rankdir = LR;
            splines = true;

            edge [color=gray50, fontname=Calibri, fontsize=11];
            node [shape=record, fontname=Calibri, fontsize=11];

            alias [shape=plaintext, label=<
                <TABLE BORDER="0" CELLBORDER="1" CELLSPACING="0" CELLPADDING="4">
                    <TR><TD BGCOLOR="gray85"><B>quic_relay_aliases (HASH)</B></TD></TR>
                    <TR><TD BGCOLOR="gray93"><I>alias CID -&gt; primary key</I></TD></TR>
                    <TR><TD PORT="a">A: cids[1..7]</TD></TR>
                    <TR><TD PORT="a2">A: client's own dcid</TD></TR>
                    <TR><TD PORT="b">B: cids[1..7]</TD></TR>
                    <TR><TD PORT="b2">B: client's own dcid</TD></TR>
                </TABLE>>];
            conns [shape=plaintext, label=<
                <TABLE BORDER="0" CELLBORDER="1" CELLSPACING="0" CELLPADDING="4">
                    <TR><TD BGCOLOR="gray85"><B>quic_relay_conns (HASH)</B></TD></TR>
                    <TR><TD BGCOLOR="gray93"><I>primary CID -&gt; record</I></TD></TR>
                    <TR><TD PORT="a">A: cids[0]</TD></TR>
                    <TR><TD PORT="b">B: cids[0]</TD></TR>
                </TABLE>>];
            reca [shape=plaintext, label=<
                <TABLE BORDER="0" CELLBORDER="1" CELLSPACING="0" CELLPADDING="4">
                    <TR><TD BGCOLOR="gray85"><B>struct quic_relay_conn</B></TD></TR>
                    <TR><TD>socketpair to worker A</TD></TR>
                    <TR><TD>client's current address</TD></TR>
                </TABLE>>];
            recb [shape=plaintext, label=<
                <TABLE BORDER="0" CELLBORDER="1" CELLSPACING="0" CELLPADDING="4">
                    <TR><TD BGCOLOR="gray85"><B>struct quic_relay_conn</B></TD></TR>
                    <TR><TD>socketpair to worker B</TD></TR>
                    <TR><TD>client's current address</TD></TR>
                </TABLE>>];

            alias:a  -> conns:a [color=green4];
            alias:a2 -> conns:a [color=green4];
            alias:b  -> conns:b;
            alias:b2 -> conns:b;
            conns:a -> reca [color=green4];
            conns:b -> recb;
        }

Traffic runs one way: :program:`master` writes relayed datagrams to
the socketpair and never reads from it. The write is
``MSG_DONTWAIT`` -- a worker that stopped reading drops packets
rather than stalling :program:`master` -- and the client's own
loss recovery covers it.

Every packet also waits in the rendezvous socket's receive queue until
:program:`master` reads it, so :program:`master` asks for a 4MB
receive buffer there, and reads up to 64 datagrams each time the
socket is readable.  Linux caps that buffer at ``net.core.rmem_max``,
208KB by default, and :program:`master` logs
``quic.listen.rcvbuf_capped`` when it got less.  To lift the cap, in a
file under ``/etc/sysctl.d``:

.. code-block:: none

    net.core.rmem_max = 4194304

.. graphviz::
    :caption: A connection's traffic, both directions, after handoff

    digraph {
            rankdir = LR;
            splines = true;
            nodesep = 0.6;

            edge [color=gray50, fontname=Calibri, fontsize=11];
            node [shape=record, fontname=Calibri, fontsize=11];

            "QUIC Client" -> "master\n(rendezvous socket)" [label="incoming", style=dashed, color=blue3];
            "master\n(rendezvous socket)" -> "worker" [label="incoming\n(over socketpair)", style=dashed, color=blue3];
            "worker" -> "QUIC Client" [label="sendto() directly"];
        }

Incoming and outgoing take different paths: a client's packets reach
the worker only by way of :program:`master`, while the worker's
replies go straight back to the client.

A connection's registration is dropped by the ordinary worker
accounting -- ``quic_centry_clear_cids()``, from ``reap_child()`` or
from the worker's next ``MASTER_SERVICE_AVAILABLE`` -- which also
closes :program:`master`'s end of the socketpair, so dispatch needs no
teardown path of its own.


Finding the CID in a packet
===========================

Routing starts by locating the Destination Connection ID, with
ngtcp2's ``ngtcp2_pkt_decode_version_cid()``. Bit 7 of the QUIC first
byte gives the header form, which decides where the DCID begins:

*   A **long header** (:rfc:`9000#section-17.2`) -- every packet of a
    connection's first flight -- describes itself: the first byte, four
    version bytes, then a DCID length byte, then the DCID.
*   A **short header** (:rfc:`9000#section-17.3`) -- everything after
    the handshake -- carries no length at all, because in QUIC the
    recipient is assumed to know how long the CIDs it handed out are.
    The DCID starts right after the first byte, and ``QUIC_CIDLEN``
    is assumed, which is exactly what :program:`master` generates.

The DCID is ``QUIC_CIDLEN`` bytes, which is what the lookup keys
on.

A packet no registered CID claims can start a new connection only if
``ngtcp2_accept()`` takes it for one -- an Initial of a version ngtcp2
supports, in a datagram of at least 1200 bytes, with a long enough
DCID -- the test a worker built on ngtcp2 applies to the same packet,
so the two agree. For a version ngtcp2 doesn't support,
:program:`master` answers a datagram of at least 1200 bytes with a
Version Negotiation packet (:rfc:`9000#section-6`) listing
``QUIC_ADVERTISED_VERSIONS`` (``master/quic/quic_handoff.h``), since
ngtcp2 can't list the versions it supports. Everything else is
dropped.

Sending replies
===============

The worker answers the client itself. Its connection descriptor is
one end of a socketpair and can't reach the network at all, so
:program:`master` passes a second one: a ``dup`` of the rendezvous
socket, the handoff's ``send_fd``.

A reply has to leave from the address and port the client addressed,
or the client won't accept it, and the rendezvous socket is by
definition bound there. Passing a ``dup`` of it, rather than having
the worker bind an equivalent socket of its own, is what keeps this
safe:

*   No second socket on the port. One bound there would have to join a
    ``SO_REUSEPORT`` group to get there at all, and would then be
    eligible for whatever incoming packets the kernel's default hash
    sent its way.

*   Routing stays CID-based. :program:`master` remains the only reader
    of the rendezvous socket and keeps demultiplexing every arriving
    packet by CID, so a client that migrates is still tracked exactly
    as :rfc:`9000#section-9` requires, and two connections sharing a
    source address are still told apart.

The descriptor is for sending only. A worker that read from it would
take packets belonging to other connections: it holds a handle on a
socket shared by every connection of the service, and is trusted not
to use it that way.

Holding it also keeps the socket alive past :program:`master`. That
doesn't arise in a clean shutdown, which reaps every child first, but
a :program:`master` killed outright leaves its workers holding a
rendezvous socket nobody reads. This is why the rendezvous socket is
bound *without* ``SO_REUSEPORT``: a replacement
:program:`master` then fails to start, rather than binding into a
group alongside the abandoned socket and losing roughly half of each
new connection's packets to it.

A spare CID pool for connection migration
===========================================

QUIC's connection migration (:rfc:`9000#section-9`) lets a client keep
a connection alive across a change of IP address or port, but requires
switching to a fresh, previously-unused CID when it does. This page
covers the dispatch layer's half of that. :program:`master` generates a small pool of CIDs per connection
(``QUIC_CID_POOL_SIZE``, see ``master/quic/quic_handoff.h``) and
registers every one before the connection is even handed off, all
pointing at the same connection. The whole pool travels in the handoff
too, so a consumer can hand out a fresh one each time it needs one,
with no further signal back to :program:`master` required.

The client's own originally-chosen CID is registered too, alongside
the pool, since a client keeps addressing its first flight (retransmits,
later ClientHello packets) to that CID rather than any pool CID -- without
this, those packets would each look like a new connection instead of a
retransmission of the one already being dispatched.

``cids[0]`` registers as the primary connection and every other pool
CID (plus the client's original DCID) registers as an alias of it --
see ``quic_relay_add_alias()``.

Tracking a moving peer address
================================

A worker's per-connection fd is just one end of an ``AF_UNIX``
socketpair, with no real network address of its own to learn a
client's current address from -- so :program:`master` has to tell it
explicitly. ``quic_relay_forward()`` tracks each connection's current
peer address, updating it whenever a registered CID's traffic arrives
from somewhere new -- covering plain NAT rebinding as well as
migration -- and prefixes every relayed datagram with a ``struct
quic_relay_pkt_hdr`` carrying that address, so a consumer reading from
the socketpair can recover each datagram's real arrival address. That
address is also what the worker sends its replies to, so a migration
it learns about this way takes effect in both directions at once.

Choosing a worker
=================

Worker reuse, preforking, and the status messages and counters behind
them are the ordinary ones, and work for a QUIC service exactly as
they do for a TCP one.

Only the choice itself differs. A TCP worker makes itself available by
blocking in ``accept()`` and the kernel picks one; a QUIC worker has no
``accept()`` to block in, so :program:`master` has to pick one and send
to it. ``Services[].quic_idle_workers``
(``master/quic/quic_idle_pool.c``) holds the identities behind the
``ready_workers`` count for that purpose: a worker joins it wherever a
TCP worker would be counted ready, and leaves it when dispatch picks
it.

A service's ``maxchild`` ceiling and fork rate gate only the forking
path, and are checked once a packet has been read and found to start a
new connection. They can't gate the rendezvous socket the way they do
a TCP listener: that socket carries every packet of every established
connection too, so refusing to read it
while at capacity would stall all of them, not just hold off new ones.
Reusing an idle worker costs no fork and isn't gated at all. A new
connection that arrives with no worker available is dropped, leaving
the client's loss recovery to retry it.

Related configuration
=======================

*   ``proto="quic"`` in a ``SERVICES`` entry of :cyrusman:`cyrus.conf(5)`
    marks a service as QUIC-dispatched, the same way ``proto="tcp"``
    or ``proto="udp"`` mark the traditional cases. ``quic4`` and
    ``quic6`` restrict the listener to one address family, matching
    ``tcp4``/``tcp6`` and ``udp4``/``udp6``.
*   ``--enable-quic`` at build time, on by default where possible: it
    needs libngtcp2, and a platform that can pass file descriptors over
    a ``SOCK_SEQPACKET`` socketpair.

Back to :ref:`imap-features`
