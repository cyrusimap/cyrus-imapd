.. _imap-features-quic-dispatch:

=========================
QUIC Connection Dispatch
=========================

:cyrusman:`master(8)` can dispatch QUIC services to worker processes,
one worker per connection, the same way it does for TCP. QUIC has no
equivalent of ``accept()`` at the socket layer, though, so this takes a
mechanism of its own. This page describes it: what problem it solves,
how a worker ends up owning a connection, and the two ways
:program:`master` can route a connection's traffic to it.

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
traffic -- what kind of descriptor depends on the dispatch backend,
below -- a second one to send on if that first descriptor can't carry
outgoing packets, and the bytes of the
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
                    <TR><TD>recv_fd: the connection's own descriptor</TD></TR>
                    <TR><TD>send_fd: a reply socket, under the relay</TD></TR>
                </TABLE>>];
            payload [shape=plaintext, label=<
                <TABLE BORDER="0" CELLBORDER="1" CELLSPACING="0" CELLPADDING="4">
                    <TR><TD BGCOLOR="gray85"><B>struct quic_handoff</B></TD></TR>
                    <TR><TD>cids[] + ncids</TD></TR>
                    <TR><TD>local_addr + local_addrlen</TD></TR>
                    <TR><TD>peer_addr + peer_addrlen</TD></TR>
                    <TR><TD>pktlen + pkt[]</TD></TR>
                    <TR><TD>odcid[] + odcidlen</TD></TR>
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
way.  ``send_fd`` is optional: the relay always passes one, its
connection descriptor being a socketpair that can't reach the network;
the eBPF backend passes none, its descriptor already being a real
socket (see "Sending replies" below).

The rest is a fixed-layout struct copied verbatim into the message
(``sizeof(struct quic_handoff)`` bytes, one ``iovec``), so nothing is
length-prefixed: each variable-length item is a fixed-size buffer with
a separate count beside it. The fields above are in declaration
order.

Finding the CID in a packet
===========================

Either backend has to locate the Destination Connection ID before it
can look anything up, and both follow the same RFC 9000 layout --
:program:`master` in userspace, with ngtcp2's
``ngtcp2_pkt_decode_version_cid()``, the eBPF backend's steering
program in the kernel. Bit 7 of the QUIC first byte gives the header
form, which decides where the DCID begins:

*   A **long header** (:rfc:`9000#section-17.2`) -- every packet of a
    connection's first flight -- describes itself: the first byte, four
    version bytes, then a DCID length byte, then the DCID.
*   A **short header** (:rfc:`9000#section-17.3`) -- everything after
    the handshake -- carries no length at all, because in QUIC the
    recipient is assumed to know how long the CIDs it handed out are.
    The DCID starts right after the first byte, and ``QUIC_CIDLEN``
    is assumed, which is exactly what :program:`master` generates.

Either way the DCID is ``QUIC_CIDLEN`` bytes, which is what the
lookup keys on.

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

Routing a connection's packets
===============================

Which kind of file descriptor a worker process gets,
and how every later datagram reaches it,
depends on the dispatch backend, selected by the
:imapdconf:`quic_use_ebpf` setting:

eBPF kernel steering
--------------------

``cyr_quic_steer`` (see ``master/quic/cyr_quic_steer.bpf.c``) is a
``BPF_PROG_TYPE_SK_REUSEPORT`` program, attached via
``SO_ATTACH_REUSEPORT_EBPF`` (``man 7 socket``) to one member of a
service's ``SO_REUSEPORT`` group. Unlike a TC classifier's
``bpf_sk_assign()``, which only *suggests* a socket at an earlier
point in the receive path and isn't reliably honored for an
unconnected UDP socket, this program *is* the kernel's own
``SO_REUSEPORT`` selection for that group -- there's nothing left
afterward to override it. ``configure`` disables this backend, the
same as any other missing eBPF dependency, if libbpf or libcap is
absent or the kernel headers are too old to declare ``CAP_BPF``.

Attachment is per-socket-group rather than per-interface, so each
QUIC service loads and attaches its own independent copy of
the program (its own maps, its own program instance) rather than
sharing one across every service the way a TC/interface-based
attachment would. Two maps per service do the actual steering: a
``BPF_MAP_TYPE_HASH`` from CID to a small integer index
(``quic_cid_index``), and a ``BPF_MAP_TYPE_REUSEPORT_SOCKARRAY``
from that index to the actual per-connection socket
(``quic_socks``) -- ``bpf_sk_select_reuseport()`` does the
selection once the CID lookup resolves an index. Every
per-connection socket shares the service's port via
``SO_REUSEPORT``. This is the fast path, but an opt-in one:
:imapdconf:`quic_use_ebpf` defaults to off, because :program:`master`
has to hold ``CAP_BPF``, ``CAP_NET_ADMIN`` and ``CAP_PERFMON`` for
its whole life to use it (see "Privileges" below).

Inside the kernel, ``ctx->data`` starts at the UDP header and RFC
9000's framing starts immediately after it, so the QUIC first byte is
at a fixed offset. The program reads the header form (see "Finding
the CID in a packet" above), bounds-checks against the end of the
packet (the BPF verifier rejects it otherwise), takes the DCID as
its key and looks it up. No per-packet state, no
loops, no parsing beyond the CID.

Every CID a connection owns shares its one index, so a client can
switch to any of them -- which is what makes the spare pool usable for
migration -- and still land on the same socket:

.. graphviz::
    :caption: The two steering maps, with two connections registered

    digraph {
            rankdir = LR;
            splines = true;

            edge [color=gray50, fontname=Calibri, fontsize=11];
            node [shape=record, fontname=Calibri, fontsize=11];

            cid [label="quic_cid_index (HASH)|CID -\> index|<a1>A: cids[0]|<a2>A: cids[1..7]|<a3>A: client's own dcid|<b1>B: cids[0]|<b2>B: cids[1..7]|<b3>B: client's own dcid"];
            sock [label="quic_socks (REUSEPORT_SOCKARRAY)|index -\> socket|<i0>0: rendezvous socket|<i1>1: worker A's socket|<i2>2: worker B's socket"];
            miss [label="CID not in the map\n(or packet not parsed)", shape=plaintext];

            cid:a1 -> sock:i1 [color=green4];
            cid:a2 -> sock:i1 [color=green4];
            cid:a3 -> sock:i1 [color=green4];
            cid:b1 -> sock:i2;
            cid:b2 -> sock:i2;
            cid:b3 -> sock:i2;
            miss -> sock:i0 [style=dashed];
        }

Index 0 is reserved for the rendezvous socket, so a packet the program
can't place goes to :program:`master` rather than to whichever socket
the kernel's default hash would have picked.

Two kinds of packet never reach a per-connection socket, and the
program sends both to the rendezvous socket:

*   **The CID parses but isn't registered** -- a new connection's
    first packet, or a retransmission that outraces :program:`master`'s
    own registration. The program explicitly selects index 0, the
    rendezvous socket, as described above.
*   **The packet doesn't parse here** -- too short to read a header
    from, or a long header claiming a DCID shorter than
    ``QUIC_CIDLEN``, which :program:`master` never issues. It
    selects index 0 as well.

    This is not just malformed input. ``ctx->data`` spans only the
    skb's linear area, and a padded Initial routinely isn't linear far
    enough to reach its DCID, so ordinary new connections land here.
    Returning without selecting would leave them to the kernel's
    default ``SO_REUSEPORT`` hash, which spreads them across the
    per-connection sockets -- where the worker that receives one has no
    matching connection and discards it, and the client never gets a
    reply. :program:`master` can always parse the packet properly in
    userspace, so anything this program can't classify goes there.

.. graphviz::
    :caption: Choosing a socket for one datagram, eBPF backend

    digraph {
            rankdir = LR;
            splines = true;

            edge [color=gray50, fontname=Calibri, fontsize=11];
            node [shape=record, fontname=Calibri, fontsize=11];

            datagram [label="datagram"];
            form [shape=diamond, label="first byte\nbit 7"];
            long [label="long header\nDCID length at +5\nDCID at +6"];
            short [label="short header\nDCID at +1\nlength assumed"];
            usable [shape=diamond, label="DCID in bounds\nand >= 8 bytes?"];
            known [shape=diamond, label="CID in\nquic_cid_index?"];
            worker [label="per-connection socket\n(a worker owns it)"];
            rendez [label="rendezvous socket\n(index 0)"];

            datagram -> form;
            form -> long [label="1"];
            form -> short [label="0"];
            long -> usable;
            short -> usable;
            usable -> rendez [label="no", style=dashed];
            usable -> known [label="yes"];
            known -> worker [label="hit", color=green4];
            known -> rendez [label="miss"];
        }

Privileges
~~~~~~~~~~

This backend needs two privileged things, and neither can be got out
of the way up front while :program:`master` is still root: binding
each new per-connection socket to the service's (likely privileged)
port, and loading the steering program, which attaches to a rendezvous
socket that isn't rebound as the Cyrus user until after the drop (see
below). So rather than drop all privilege the way
:cyrusman:`master(8)` does for every other service, :program:`master`
retains four capabilities across the drop:

*   ``CAP_NET_BIND_SERVICE``, since every new connection's
    per-connection socket must bind the same (likely privileged) port
    as its service's rendezvous socket, for as long as
    :program:`master` runs.
*   ``CAP_NET_ADMIN``, ``CAP_BPF`` and ``CAP_PERFMON``, which between
    them are what loading a networking BPF program takes: ``CAP_BPF``
    to load rather than merely attach, and ``CAP_PERFMON`` for the
    verifier's speculation-hardening relaxation that
    ``cyr_quic_steer.bpf.c``'s pointer arithmetic on the packet data
    needs. Because ``SO_ATTACH_REUSEPORT_EBPF`` is scoped to a
    socket's own ``SO_REUSEPORT`` group rather than to an interface,
    this load-and-attach happens per service, after the uid drop,
    from ``quic_rebind_rendezvous_sockets()``.

``CAP_SETUID`` and ``CAP_SETGID`` are dropped with everything else, so
this can't be used to regain root. It doesn't weaken worker security
either: every forked/exec'd service still drops all privilege on its
own, via its usual ``become_cyrus()``/``cyrus_init()`` startup path --
only :program:`master`'s own QUIC dispatch code keeps these.

One consequence of the privilege drop: every socket
sharing a ``SO_REUSEPORT`` group must be bound under the same effective
uid, or a later bind into that group fails ``EADDRINUSE``. Each rendezvous socket
was bound at startup while :program:`master` was still root, but its
own per-connection sockets are created as the Cyrus user -- so
:program:`master` closes and rebinds every rendezvous socket right
after dropping privilege, or every dispatch would hit that same
``EADDRINUSE``.

Userspace relay
---------------

The default, and a pure-userspace dispatch backend
(``master/quic/quic_relay.c``): used unless
:imapdconf:`quic_use_ebpf` is turned on, and used regardless of that
setting on a build with no eBPF support at all.
:program:`master` keeps the real rendezvous socket for a connection's
entire life and demultiplexes every arriving datagram by CID itself,
relaying each one to the owning worker over an ``AF_UNIX``
``SOCK_SEQPACKET`` socketpair -- no elevated privileges
needed at all, unlike eBPF, but every packet a client sends passes
through :program:`master` for the connection's whole life, not just
the first one. Outgoing packets don't: the worker sends those itself (see
"Sending replies" below).

Two hash tables, a CID-to-key-to-record indirection like the eBPF
backend's CID-to-index-to-socket one:
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
one record. Nothing forces the indirection here the way the kernel
forces it under eBPF -- a userspace table can key on the CID directly
-- but storing the record itself under each of its CIDs would leave
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

Nothing is retained for this backend: it loads no kernel program and
binds no new socket, so :program:`master` drops to the Cyrus user
through the ordinary ``become_cyrus()`` path, as for every other
service.

After the handoff
-----------------

Both backends answer the same question -- "which connection does
this packet belong to?" -- one in the kernel, one in
:program:`master`'s own event loop. The handoff itself is identical
between them; what differs is the descriptor the worker ends up with,
and the path every later datagram takes to reach it:

.. graphviz::
    :caption: A connection's traffic, both directions, after handoff

    digraph {
            rankdir = LR;
            splines = true;
            nodesep = 0.6;

            edge [color=gray50, fontname=Calibri, fontsize=11];
            node [shape=record, fontname=Calibri, fontsize=11];

            "QUIC Client" -> "master\n(rendezvous socket)" [label="relay: incoming", style=dashed, color=blue3];
            "master\n(rendezvous socket)" -> "worker" [label="relay: incoming\n(over socketpair)", style=dashed, color=blue3];
            "QUIC Client" -> "worker" [label="eBPF: kernel-steered\n", style=dashed, color=green4];
            "worker" -> "QUIC Client" [label="sendto() directly"];
        }

Outgoing packets take the same path under both backends: the worker
sends them itself. What differs is how a client's packets reach it --
steered by the kernel to the worker's own socket under eBPF, relayed
over the socketpair by :program:`master` under the relay backend.

A connection's registration is dropped by the ordinary worker
accounting -- ``quic_centry_clear_cids()``, from ``reap_child()`` or
from the worker's next ``MASTER_SERVICE_AVAILABLE`` -- which removes
its CIDs from whichever backend's tables hold them, and under the
relay also closes :program:`master`'s end of the socketpair. Neither
backend needs a teardown path of its own.


Sending replies
===============

Whichever backend routed a client's packets to a worker, the worker
answers the client itself. Under eBPF that falls out of the design:
the worker's descriptor *is* a UDP socket bound to the service's
address, so ``sendto()`` on it reaches the client with the right
source address. The relay backend's descriptor is
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
take packets belonging to other connections, which is the one
isolation property the eBPF backend's genuinely per-connection sockets
provide and this one does not: a worker holds a handle on a
socket shared by every connection of the service, and is trusted not
to use it that way.

Holding it also keeps the socket alive past :program:`master`. That
doesn't arise in a clean shutdown, which reaps every child first, but
a :program:`master` killed outright leaves its workers holding a
rendezvous socket nobody reads. This is why the relay backend's
rendezvous socket is bound *without* ``SO_REUSEPORT``, which only the
eBPF backend needs: a replacement :program:`master` then fails to
start, rather than binding into a group alongside the abandoned socket
and losing roughly half of each new connection's packets to it. The
eBPF backend has no such option -- reuseport is its steering
mechanism -- and is exposed to more of this, since its deliberately
unconnected per-connection sockets mean orphaned workers leave one
abandoned socket each rather than one in total.

A spare CID pool for connection migration
=========================================

QUIC's connection migration (:rfc:`9000#section-9`) lets a client keep
a connection alive across a change of IP address or port, but requires
switching to a fresh, previously-unused CID when it does. This page
covers the dispatch layer's half of that, for both backends:
:program:`master` generates a small pool of CIDs per connection
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

*   Under the eBPF backend, every pool CID is inserted into the
    steering map for the same per-connection socket, which is also
    deliberately never ``connect()``\ ed to the client's address, for
    the same reason: a connected UDP socket only accepts datagrams
    from the peer it is connected to, so it could not receive the
    migrated client's traffic from its new address at all.
*   Under the relay backend, ``cids[0]`` registers as the primary
    connection and every other pool CID (plus the client's original
    DCID) registers as an alias of it -- see
    ``quic_relay_add_alias()``.

Tracking a moving peer address
================================

Only the eBPF backend gets a migrating client's new source address for
free, from the kernel, the moment it uses an unconnected per-connection
socket. The relay backend's per-connection fd is just one end of an
``AF_UNIX`` socketpair, with no real network address of its own to
learn one from -- so :program:`master` has to tell the worker
explicitly. ``quic_relay_forward()`` tracks each connection's current
peer address, updating it whenever a registered CID's traffic arrives
from somewhere new -- covering plain NAT rebinding as well as
migration -- and prefixes every relayed datagram with a ``struct
quic_relay_pkt_hdr`` carrying that address, so a consumer reading from
the relay socketpair can recover each datagram's real arrival address
the same way the eBPF backend's worker would get it from
``recvfrom()``. That address is also what the worker sends its replies
to, so a migration it learns about this way takes effect in both
directions at once.

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
a TCP listener: under the relay backend that socket carries every
packet of every established connection too, so refusing to read it
while at capacity would stall all of them, not just hold off new ones.
Reusing an idle worker costs no fork and isn't gated at all. A new
connection that arrives with no worker available is dropped, leaving
the client's loss recovery to retry it.

Address validation
==================

A new connection costs a worker, perhaps a fork, until its handshake
completes or times out, and its first packet's source address proves
nothing: a flood of Initials with forged addresses could otherwise
use up ``maxchild``.  So, per :imapdconf:`quic_retry`,
:program:`master` can answer a new connection's Initial with a Retry
(:rfc:`9000` section 8.1) instead of dispatching it.  The client must
send its Initial again, carrying the Retry's token, and only that
Initial gets a worker.

:program:`master` keeps no state between the two.  The token is
encrypted with a key :program:`master` picks at startup, and binds the
client's address, the Retry's source CID (the new Initial's DCID) and
the DCID of the first Initial, which the worker needs for the
``original_dcid`` transport parameter and gets in the handoff.  A
token that doesn't verify -- expired after 10 seconds, from before a
restart, or for another address -- gets a CONNECTION_CLOSE with
INVALID_TOKEN rather than a second Retry, which the client would
ignore.

A Retry costs every connection it applies to a round trip, so by
default (``load``) :program:`master` sends one only while a service has
at least half its ``maxchild`` workers running.  It only stops forged
addresses: a flood from addresses that answer still needs other
limits.

Performance
============

A rough measure of each backend's own per-packet dispatch/relay
overhead: a minimal QUIC worker that echoes every datagram
straight back (no real QUIC/TLS), driven by a client that opens many
connections concurrently and exchanges an Initial packet and a
short-header packet on each. Loopback isn't representative for this
kind of measurement -- traffic needs to actually leave and re-enter
the kernel's networking stack for these dispatch paths to behave as
they would in production -- so this ran over a real ``veth`` pair
between two network namespaces instead.

Connection setup -- dispatch's first packet, forking or reusing an
idle worker -- costs about the same either way, since both backends
go through the identical fork/idle-pool path: at 300 concurrent
connections, median first-packet latency was 422 ms for eBPF and
416 ms for the relay backend, not meaningfully distinguishable at
this stage.

Steady-state per-packet latency (a connection's second and later
packets, once dispatch is done) is where the backends genuinely
differ, and by a wide margin. At 300 connections, 50 concurrent:

======  =======  ========
metric  eBPF     relay
======  =======  ========
median  1.0 ms   18.7 ms
p95     22.8 ms  128.2 ms
p99     39.6 ms  239.7 ms
======  =======  ========

The gap widens under heavier concurrency -- 1000 connections, 150
concurrent, steady state:

======  =======  ========
metric  eBPF     relay
======  =======  ========
median  0.4 ms   80.6 ms
p95     12.8 ms  272.3 ms
p99     21.6 ms  461.9 ms
======  =======  ========

This matches the two backends' shapes: eBPF only ever touches a
connection's very first packet -- everything after that is steered by
the kernel straight to the connection's own socket, with no
involvement from :program:`master` at all. The relay backend still
demultiplexes every packet a client sends, for the connection's whole
life, in one single-threaded :program:`master` process, so its
per-packet cost -- and its sensitivity to how many connections are
active at once -- is inherent to the design, not a tuning problem.

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
*   :imapdconf:`quic_use_ebpf` -- eBPF vs. userspace relay backend.
    Off by default; the relay needs no elevated privileges.
*   :imapdconf:`quic_retry` -- when to validate a new connection's
    address with a Retry: ``never``, under ``load`` (the default), or
    ``always``.

Back to :ref:`imap-features`
