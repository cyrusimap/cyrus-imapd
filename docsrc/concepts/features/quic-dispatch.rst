.. _imap-features-quic-dispatch:

=================================
HTTP/3 (QUIC) Connection Dispatch
=================================

Cyrus supports HTTP/3 by running QUIC (:rfc:`9000`) underneath
:cyrusman:`httpd(8)`. Making that work required teaching
:cyrusman:`master(8)` a new way of handing connections to worker
processes, because QUIC has no equivalent of ``accept()`` at the
socket layer. This page describes that mechanism: what problem it
solves, the two ways :program:`master` can solve it, and how a
worker process ends up owning a connection either way.

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
packet's payload -- not by a kernel-tracked 4-tuple the way TCP
connections are. So "accepting" a new QUIC connection means
:program:`master` itself has to inspect each incoming datagram,
decide whether it belongs to a connection already in progress or
starts a new one, and route it accordingly -- all before a worker
process ever sees it.

Two dispatch backends
======================

:program:`master` can solve this two ways, selected by the
:imapdconf:`quic_ebpf` setting:

eBPF/TC kernel steering
    An eBPF program (``cyr_quic_steer``, see
    ``master/quic/cyr_quic_steer.bpf.c``) is loaded and attached to
    the TC ingress hook of one or more network interfaces. A
    SOCKHASH map, keyed by CID, tells the kernel which
    per-connection socket each subsequent packet belongs to --
    ``bpf_sk_assign()`` redirects it there directly, in-kernel, with
    no further involvement from :program:`master` for the life of
    the connection. This is the fast path, and the default whenever
    the build has eBPF support (``libbpf``) compiled in.

Userspace relay
    A pure-userspace fallback (``master/quic/quic_relay.c``), used
    automatically when the build has no eBPF support, or when
    :imapdconf:`quic_ebpf` is explicitly disabled (a restricted
    container, a kernel without the needed BPF features, etc).
    :program:`master` keeps the real rendezvous socket for a
    connection's entire life and demultiplexes every datagram by CID
    itself, relaying each one to or from the owning worker over an
    ``AF_UNIX`` ``SOCK_DGRAM`` socketpair.

Both backends answer the same question -- "which connection does
this packet belong to?" -- one in the kernel, one in
:program:`master`'s own event loop. Everything past that point,
including how a connection is handed to a worker, is identical
between them.

Handing a connection to a worker
=================================

Once :program:`master` has decided a datagram starts a new
connection, it picks (or forks) a worker and gives it everything
needed to carry on: a file descriptor for the connection's traffic
(a real per-connection UDP socket under the eBPF backend, one end of
an ``AF_UNIX`` socketpair under the relay backend) and the bytes of
the first datagram, which :program:`master` already had to read and
parse off the rendezvous socket in order to make that decision in
the first place.

This travels over a dedicated handoff channel, ``QUIC_HANDOFF_FD``
(see ``master/service.h``) -- an ``AF_UNIX`` ``SOCK_SEQPACKET``
connected to the worker at fork time, distinct from the ``LISTEN_FD``
a normal TCP/UDP worker inherits. The payload is a ``struct
quic_handoff``: the CID :program:`master` chose for this connection,
the local and peer addresses, and the first datagram's bytes -- with
the connection's own fd itself riding alongside via ``SCM_RIGHTS``.
A worker recognizes it's handling a ``proto="quic"`` service via a
``CYRUS_SERVICE_PROTO=quic`` environment variable set at fork time
(its only way to learn this, since it has no access to
:program:`master`'s own parsed configuration), and if so, blocks on
``QUIC_HANDOFF_FD`` instead of ``accept()``-ing on ``LISTEN_FD``.

.. graphviz::
    :caption: Handing off one QUIC connection

    digraph {
            rankdir = LR;
            splines = true;

            edge [color=gray50, fontname=Calibri, fontsize=11];
            node [shape=record, fontname=Calibri, fontsize=11];

            "QUIC Client" -> "master\n(rendezvous socket)" [label="first datagram"];
            "master\n(rendezvous socket)" -> "httpd -3\n(worker)" [label="QUIC_HANDOFF_FD:\nfd + quic_handoff"];
            "QUIC Client" -> "httpd -3\n(worker)" [label="later datagrams", style=dashed, color=green4];
        }

The dashed edge above is where the two backends actually differ:
under eBPF it's the kernel steering later packets straight to the
worker's own socket; under the relay backend it's
:program:`master` receiving each one on the rendezvous socket and
forwarding it over the socketpair.

Idle worker reuse
==================

Forking and fully initializing a worker (TLS, SASL, etc.) is
expensive enough that paying that cost for every single connection
would be wasteful. Workers that finish a connection report
themselves idle instead of exiting, and :program:`master` keeps a
small pool of them per service (``Services[].quic_idle_workers`` --
see ``master/master.h``), handing each new connection to an idle
worker before falling back to forking a fresh one. A configured
number of idle workers are also kept forked ahead of demand, the
same way :program:`master` preforks ordinary TCP/UDP workers.

Connection migration is not supported
=======================================

QUIC's connection migration (:rfc:`9000#section-9`) lets a client
keep a connection alive across a change of IP address or port (for
example, moving from Wi-Fi to cellular). Cyrus does not support it:
neither dispatch backend tracks a connection's actual per-packet
arrival path, and neither registers the additional CIDs a migrating
client is required to switch to. Advertising support that isn't
there would just invite clients to attempt it and fail silently, so
``httpd -3`` sets the ``disable_active_migration`` QUIC transport
parameter to tell clients not to bother.

Attaching to multiple network interfaces
==========================================

The eBPF backend's steering program can be attached to more than one
network interface at once -- one loaded program and one set of maps,
shared across every attachment point, so a connection is steered
correctly regardless of which interface its packets arrive on.
:imapdconf:`quic_ebpf_iface` controls which interfaces:

*   Left unset (the default), every interface the host currently has
    is discovered automatically and attached to, best-effort -- one
    that fails (unusual, virtual, administratively down, ...) is
    logged and skipped rather than treated as fatal.
*   Set to an explicit, whitespace-separated list, only those
    interfaces are attached to, and every one of them is required to
    succeed -- a typo or a genuinely broken interface here is
    reported immediately, rather than silently leaving HTTP/3
    unreachable on just that one network.

Related configuration
=======================

*   ``proto="quic"`` in a ``SERVICES`` entry of :cyrusman:`cyrus.conf(5)`
    marks a service as QUIC-dispatched, the same way ``proto="tcp"``
    or ``proto="udp"`` mark the traditional cases.
*   :imapdconf:`quic_ebpf` -- eBPF vs. userspace relay backend.
*   :imapdconf:`quic_ebpf_iface` -- which interfaces to attach the
    eBPF steering program to.
*   :imapdconf:`quic_idle_timeout` -- the QUIC transport-level idle
    timeout, independent of :imapdconf:`httptimeout`/
    :imapdconf:`httpkeepalive`, which apply only to HTTP/1.1 and
    HTTP/2 over TCP.

Back to :ref:`imap-features`
