:tocdepth: 2

.. |product| replace:: Cyrus IMAP

.. _imap-deployment-storage:

======================
Storage Considerations
======================

Storage considerations are a complex matter as the various options
provide or restrict one's ability to adjust the necessary parameters as
the need arises. It is foremost a challenge to clearly articulate and
prioritize the criteria for storage, and map the theory on to a
practical implementation design.

This article intends to provide information and outline details, and
sometimes opinions and recommendations, but it is not a guide to
providing you with the storage solution that you want or require.

Generally, the most important considerations for storage include;

:ref:`imap-deployment-storage-redundancy`,

    because nothing is as humiliating as losing all your data.

:ref:`imap-deployment-storage-availability`,

    because nothing is more stressful than none of your data being
    available.

:ref:`imap-deployment-storage-performance`,

    because nothing is as annoying as waiting, followed by some more
    waiting.

:ref:`imap-deployment-storage-scalability`,

    because ``-ENOSPC`` is good only when it applies to your stomach.

:ref:`imap-deployment-storage-capacity`,

    because your data must be available, backed up and archived.

:ref:`imap-deployment-storage-cost`,

    because you can't buy a beer or feed a family with an empty wallet.

Storage is not a part of |product|, in that |product| does not ship
a particular storage solution as part of the product, and it has no
particular requirements for storage either.

As such, your SAN, NAS, local disk, local array of disks or network
share or even the flash drive of a Raspberry Pi could be used, although
the following considerations are important:

*   The Cyrus IMAP spool is I/O intensive (large volumes of data are read
    and get written).

*   The Cyrus IMAP spool consists of many small files.

As such, we recommend you take into account;

*   The available bandwidth between the IMAP server and the storage
    provider, if at all on the network,

*   The (network) protocol overhead, if any, should file-level read
    and/or write locking be required or implied.

*   Atomic file operations.

*   Parallel access (such as shared mailboxes or multi-client
    attendance).

General Notes on Storage
========================

The aforementioned considerations
:ref:`imap-deployment-storage-redundancy`,
:ref:`imap-deployment-storage-availability`,
:ref:`imap-deployment-storage-performance`,
:ref:`imap-deployment-storage-scalability`,
:ref:`imap-deployment-storage-capacity` and
:ref:`imap-deployment-storage-cost`
are not all of them equally important -- not to all organizations, and
not to all requirements when the priorities are set out against the
implied cost of the supposed ideal solution.

They are also not mutually exclusive in that, for example, redundancy
may partly address some of the availability concerns -- depending on the
exact nature of the final deployment of course, and backup/recovery
capabilities in turn may partly address redundancy requirements. Neither
necessarily directly addresses availability concerns, however.

What is deemed acceptable is another culprit -- more often then not,
operational cost, familiarity of staff with a particular storage
solution, or flexibility of a storage solution (or lack thereof) may get
in the way of an otherwise appropriate storage solution.

We believe that provided a sufficient amount of accurate information,
however, you are able to make an informed choice, and that an informed
choice is always better than an ill-informed one.

.. _imap-deployment-storage-redundancy:

Redundancy
==========

Storage redundancy is achieved through replication of data. It is
important to understand that, as a matter of design principle,
redundancy does not in and by itself provide increased availability.

How redundancy could increase availability depends on the exact
implementation, and the various options for practical implementation
each have their own set of implications for cases of failure and the
need to, under certain circumstances, failover and/or recover.

How redundancy is achieved in an "acceptable" manner is another subject
open to interpretation; it is sometimes deemed acceptable to create
backups daily, and therefore potentially accept the loss of up to one
day's worth of information from live spools -- which may or may not be
recoverable through different means. More commonly however is to not
settle for anything less than real-time replication of data.

While storage ultimately amounts to disks, it is important to understand
that a number of (virtual) devices, channels, links and interfaces exist
between an application operating data on disk [#]_, and the physical
sectors and blocks or cells of storage on that disk. In a way, this
number of layers can be compared with the `OSI model for networking`_ --
but it is not the same at all.

This section addresses the most commonly used levels at which
replication can be applied.

Storage Volume Level Replication
--------------------------------

When using the term :term:`storage volume level replication` we mean to
indicate the replication of :term:`disk volumes` as a whole. A
simplistic replication scenario of a data disk between two nodes could
look as follows:

.. graphviz::

    digraph drbd {
            rankdir = LR;
            splines = true;
            overlab = prism;

            edge [color=gray50, fontname=Calibri, fontsize=11];
            node [style=filled, shape=record, fontname=Calibri, fontsize=11];

            subgraph cluster_master {
                    label = "Master";

                    color = "#BBFFBB";
                    fontname = Calibri;
                    rankdir = TB;
                    style = filled;

                    "OS Disk 0" [label="OS Disk",color="green"];
                    "Data Disk 0" [label="Data Disk",color="green"];
                }

            subgraph cluster_slave {
                    label = "Slave";

                    color = "#FFBBBB";
                    fontname = Calibri;
                    rankdir = TB;
                    style = filled;

                    "OS Disk 1" [label="OS Disk",color="green"];
                    "Data Disk 1" [label="Data Disk",color="red"];
                }

            "Data Disk 0" -> "Data Disk 1" [label="One-Way Replication"];
        }

For a fully detailed picture of the internal structures, please see the
`DRBD`_ website, the canonical experts on this level of replication.

Normally storage-level replication occurs in such
fashion that it can be compared with a distributed version of a RAID-1
array. This incurs limitations that need to be evaluated carefully.

In a hardware RAID-1 array, storage is physically constrained to a
single node, and pairs of replicated disks are treated as one. In a
software RAID-1 array, it is the operating system's software RAID driver
that can (must) address the individual disks, but makes the array appear
as a single disk to all higher-level software. Here too, the disks are
physically constrained to one physical node.

In both cases, a *single point of control* exists with full and
exclusive access to the physical disk device(s), namely the interface
for *all higher-level software* to interact with the storage.

This is the underlying cause of the storage-level replication conundrum.

To illustrate the conundrum, we use a software RAID-1 array. The
individual disk volumes that make up the RAID-1 array are not hidden
from the rest of the operating system, but more importantly, direct
access to the underlying device is not prohibited. With an example pair
``sda2`` and ``sdb2``, nothing prevents you from executing ``mkfs.ext4``
on ``/dev/sdb2`` thereby corrupting the array -- other than perhaps not
having the necessary administrative privileges.

To further illustrate, position one disk in the RAID-1 array on the
other side of a network (such as is a `DRBD`_ topology, as illustrated).
Since now two nodes participate in nurturing the mirrored volume, two
points of control exist -- each node controls the access to its local
disk device(s).

Participating nodes are **required** to successfully coordinate their
I/O with one another, which on the level of entire storage volumes is a
very impractical effort with high latency and enormous overhead, should
more than one node be allowed to access the replicated device [#]_.

It is therefore understood that, using storage level replication;

*   Only one side of the mirrored volume can be active (master), and the
    other side must remain passive (slave),

*   The active and passive nodes therefore have a cluster solution
    implemented to manage application's failover and management of the
    change in replication topology (a slave becomes the I/O master, the
    former master becomes the replication slave, and other slaves, if
    any, learn about the new master to replicate from),

*   Failover implementations include fencing, the STONITH principle,
    ensuring no two nodes in parallel perform I/O on the same volume at
    any given time.

.. WARNING::

    Storage volume level replication does not protect against filesystem
    or payload corruption -- the replication happily mirrors the
    "faulty" bits as it is completely agnostic to the bits' meaning and
    relevance.

.. WARNING::

    For the reasons outlined in this section, storage volume level
    replication has only a limited number of |product| deployment
    scenarios for which it would be recommended -- such as *Disaster
    Recovery Failover*.

.. _imap-deployment-storage-integrated-storage-protocol-level-replication:

Integrated Storage Protocol Level Replication
---------------------------------------------

Integrated storage protocol level replication is a different approach to
making storage volumes redundant, applying the replication on a
different level.

Integrated storage protocol level replication isn't necessarily limited
to replication for the purposes of redundancy only, as it may already
include parallel access controls, distribution across multiple storage
nodes (each providing a part of the total storage volume available),
enabling the use of cheap commodity hardware to provide the individual
parts (called "bricks") that make up the larger volume.

Additional features may include the use of a geographically oriented set
of parameters for the calculation and assignment of replicated chunks of
data (ie. "brick replication topology").

.. graphviz::

    digraph {
            rankdir = TB;
            splines = true;
            overlab = prism;

            edge [color=gray50, fontname=Calibri, fontsize=11];
            node [style=filled, shape=record, fontname=Calibri, fontsize=11];

            "Storage Client #1" -> "Storage Access Point" [dir=back,color=green];
            "Storage Client #2" -> "Storage Access Point" [dir=back,color=green];
            "Storage Client #3" -> "Storage Access Point" [dir=back,color=green];
            "Storage Client #4" -> "Storage Access Point" [dir=back,color=green];

            subgraph cluster_storage {
                    color = green;
                    label = "Distributed and/or Replicated Volume Manager w/ Integrated Distributed (File-) Locking";

                    "Storage Access Point" [shape=point,color=green];

                    "Brick #1" [color=green];
                    "Brick #2" [color=green];
                    "Brick #3" [color=green];
                    "Brick #4" [color=green];

                    "Storage Access Point" -> "Brick #1" [color=green];
                    "Storage Access Point" -> "Brick #2" [color=green];
                    "Storage Access Point" -> "Brick #3" [color=green];
                    "Storage Access Point" -> "Brick #4" [color=green];
                }
        }

Current implementations of this type of technology include `GlusterFS`_
and `Ceph`_. Put way too simplistically, both technologies apply very
smart ways of storing individual objects, sometimes with additional
facilities for certain object types. How they work exactly is far beyond
the scope of this document.

Both technologies however are considered more efficient for fewer,
larger objects, than they are for more, smaller objects. Both storage
solutions also tend to be more efficient at addressing individual
objects directly, rather than hierarchies of objects (for listing).

This is meant to indicate that while both solutions scale up to millions
of objects, they facilitate a particular **I/O pattern** better than the
I/O pattern typically associated with a large volume of messages in IMAP
spools. More frequent and very short-lived I/O against individual
objects in a filesystem mounted directly causes a significant amount of
overhead in negotiating the access to the objects across the storage
cluster [2]_.

Both technologies are perfectly suitable for large clusters with
relatively small filesystems (see `Filesystems: Smaller is Better`_)
if they are mounted directly from the storage clients. They are
particularly feasible if not too many parallel write operations to
individual objects (files) are likely to occur (think, for example, of
web application servers and (asset-)caching proxies).

Alternatively, fewer larger objects could be stored -- such as disk
images for a virtualization environment. The I/O patterns internal to
the virtual machine would remain the same, but the I/O pattern of the
storage client (the hypervisor) is the equivalent of a single
lock-and-open when the virtual machine starts.

It is therefore understood that, especially in deployments of a larger
scale, one should not mount a GlusterFS or CephFS filesystem directly
from within an IMAP server, as an individual IMAP mail spool consists of
many very small objects each individually addressed frequently, and in
short-lived I/O operations, and consider the use of these distributed
filesystems for a different level of object storage, such as disk images
for a virtualization environment:

.. graphviz::

    digraph {
            rankdir = TB;
            splines = true;
            overlab = prism;

            edge [color=gray50, fontname=Calibri, fontsize=11];
            node [style=filled, shape=record, fontname=Calibri, fontsize=11];

            subgraph cluster_guests {
                    label = "Guest Nodes";

                    "Guest #1";
                    "Guest #2";
                    "Guest #3";
                }

            subgraph cluster_hypervisors {
                    label = "Virtualization Platform";

                    "Hypervisor #1";
                    "Hypervisor #2";
                }

            subgraph cluster_storage {
                    color = green;
                    label = "Distributed and/or Replicated Volume
 Manager w/ Integrated Distributed (File-) Locking";

                    subgraph cluster_replbricks1 {
                            label = "Replicated Bricks";

                            "Brick #1" [color=green];
                            "Brick #3" [color=green];
                        }

                    subgraph cluster_replbricks2 {
                            label = "Replicated Bricks";

                            "Brick #2" [color=green];
                            "Brick #4" [color=green];
                        }

                }

            "Guest #1" -> "Hypervisor #1" [dir=both,color=green];
            "Guest #2" -> "Hypervisor #1" [dir=both,color=green];
            "Guest #3" -> "Hypervisor #2" [dir=both,color=green];

            "Hypervisor #1" -> "Brick #4" [dir=both,label="Guest #1"];
            "Hypervisor #1" -> "Brick #3" [dir=both,label="Guest #2"];
            "Hypervisor #2" -> "Brick #3" [dir=both,label="Guest #3"];
        }

In this illustration, *Hypervisor #1* and *Hypervisor #2* are storage
clients, and replicated bricks hold the disk images of each guest.

Each hypervisor can, in parallel, perform I/O against each individual
disk image, allowing (for example) both *Hypervisor #1* and
*Hypervisor #2* to run guests with disk images for which *Brick #3* has
been selected as the authoritative copy.

.. _deployment-application-replication:

Application Level Replication
-----------------------------

Yet another means to provide redundancy of data is to use application-
level replication where available.

Famous examples include database server replication, where one or more
MySQL masters are used for write operations, and one or more MySQL
slaves are used for read operations, and LDAP replication.

Cyrus IMAP can also replicate its mail spools to other systems, such
that multiple backends hold the payload served to your users.

Shared Storage (Generic)
------------------------

Contrary to popular belief, all shared storage -- NFS, iSCSI and FC
alike -- are **not** storage devices. They are *network protocols* for
which the application just so happens to be storage -- with perhaps the
exception to the rule being Fiber-Channel not strictly cohering to the
`OSI model for networking`_, although its own 5-layer model equates.

iSCSI and Fiber-Channel LUNs however are *mapped* to storage devices by
your favorite operating system's drivers for each technology, or
possibly by a hardware device (an :term:`HBA`, or in iSCSI, an
*initiator*).

As such, use of these network protocols for which the purpose just so
happens to be storage does **not** provide redundancy.

It is imperitive this is understood and equally well applied in planning
for storage infrastructure, or that your storage appliance vendor or
consultancy partner is trusted in their judgement.

Shared Storage (NFS)
--------------------

Use of the Networked File System (NFS) in and by itself does **not**
provide redundancy, although the underlying storage volume might be
replicated.

For a variety of reasons, the use of `NFS is considered harmful`_ and is
therefore, and for other reasons,  most definitely not recommended for
|product| IMAP spool storage, or any other storage related to
functional components of |product| itself -- IMAP, LDAP, SQL, etc.

Most individual concerns can be addressed separately, and some should or
must already be resolved to address other potentially problematic areas
of a given infrastructure, regardless of the use of NFS.

A couple of concerns however only have *workarounds*, not solutions --
such as disabling locking -- and a number of concerns have no solution
at all.

One penalty to address is the inability for NFS mounted volumes to cache
I/O, known as in-memory buffer caching.

A technology called `FS Cache`_ can facilitate eliminating round-trip-
incurred network-latency, but is still a filesystem-backed solution
(for which filesystem the local kernel applies buffer caching), requires
yet another daemon, and introduces yet another layer of synchronisity to
be maintained -- aside from `other limitations <https://access.redhat.com/documentation/en-US/Red_Hat_Enterprise_Linux/6/html/Storage_Administration_Guide/fscachelimitnfs.html>`_.

An NFS-backed storage volume can still be used for fewer, larger files,
such as guest disk images.

Shared Storage (iSCSI or FC LUNs)
---------------------------------

Both iSCSI LUNs and Fiber-Channel LUNs facilitate attaching a networked
block storage device as if it were a local disk (creating devices
similar to ``/dev/sd{a,b,c,d}`` etc.).

Since such a LUN is available over a "network" infrastructure, it may be
shared between multiple nodes but when it is, nodes need to coordinate
their I/O on some other level.

With an example case of hypervisors, either `Cluster LVM`_ [#]_ or
`GFS`_ [#]_ could be used to protect against corruption of the LUN.

..
    Shared Storage (Disk Device)
    ----------------------------

    .. include:: needs-work.txt


.. _imap-deployment-storage-availability:

Availability
============

Availability of storage too can be achieved via multiple routes. In one
of the aforementioned technologies, replicated bricks both available
real-time and online, in a parallel read-write capacity, provided high-
availability through redundancy (see
:ref:`imap-deployment-storage-integrated-storage-protocol-level-replication`).

An existing chunk of storage you might have is likely backed by a level
of RAID, with redundancy through mirroring individual disk volumes
and/or the inline calculation of parity, and perhaps also some spare
disks to replace those that are kicked or fall out of line.

Further features might include battery-backed I/O controllers, redundant
power supplies connected to different power groups, a further UPS and
a diesel generator (you start up once a month, right?).

The availability features of a data center are beyond the scope of this
document, but when we speak of availability with regards to storage, we
intend to speak of immediate, instant, online availability with
automated failover (such as the RAID array) -- and more prominently,
without interruption.

Multipath
---------

Multipath is an enhancement technique in which multiple paths that are
available to the storage can be balanced, shaped and failed over
automatically. Imagine the following networking diagram:

.. graphviz::

    digraph {
            rankdir = TB;
            splines = true;
            overlab = prism;

            edge [color=gray50, fontname=Calibri, fontsize=11];
            node [style=filled, shape=record, fontname=Calibri, fontsize=11];

            "Node";

            "Switch #1"; "Switch #2";

            "Canister #1"; "Canister #2";

            "iSCSI Target #1", "iSCSI Target #2";

            "Node" -> "Switch #1" [dir=none]
            "Node" -> "Switch #2" [dir=none];

            "Switch #1" -> "Canister #1" [dir=none];
            "Switch #1" -> "Canister #2" [dir=none];

            "Switch #2" -> "Canister #1" [dir=none];
            "Switch #2" -> "Canister #2" [dir=none];

            "Canister #1" -> "iSCSI Target #1" [dir=none];
            "Canister #1" -> "iSCSI Target #2" [dir=none];

            "Canister #2" -> "iSCSI Target #1" [dir=none];
            "Canister #2" -> "iSCSI Target #2" [dir=none];
        }

The *null* situation is depicted in the previous wiring diagram. When
multipath kicks in, primary vs. secondary paths will be chosen for each
individual target (that is unique). However, the system maintains a list
of potential paths, and continuously monitors all paths for their
viability.

In the example, for *Node* attaching to *iSCSI Target #1* results in up
to 4 paths to *iSCSI Target #1* -- *4* paths, not *8*, because the
networking of *Switch #1* and *Switch #2* is not considered a path with
iSCSI -- *two nodes* and *two send targets each*.

Multipath chooses one path to the available storage:

.. graphviz::

    digraph {
            rankdir = TB;
            splines = true;
            overlab = prism;

            edge [color=gray50, fontname=Calibri, fontsize=11];
            node [style=filled, shape=record, fontname=Calibri, fontsize=11];

            "Node";

            "Switch #1" [color=green];
            "Switch #2";

            "Canister #1";
            "Canister #2" [color=green];

            "iSCSI Target #1" [color=green];
            "iSCSI Target #2";

            "Node" -> "Switch #1" [dir=none,color=green]
            "Node" -> "Switch #2" [dir=none];

            "Switch #1" -> "Canister #1" [dir=none];
            "Switch #1" -> "Canister #2" [dir=none,color=green];

            "Switch #2" -> "Canister #1" [dir=none];
            "Switch #2" -> "Canister #2" [dir=none];

            "Canister #1" -> "iSCSI Target #1" [dir=none];
            "Canister #1" -> "iSCSI Target #2" [dir=none];

            "Canister #2" -> "iSCSI Target #1" [dir=none,color=green];
            "Canister #2" -> "iSCSI Target #2" [dir=none];
        }

Should one port, bridge, controller, switch or cable fail, then the I/O
can fall back on to any of the remaining available paths.

As per the example, this might mean the following (with *Canister #2*
failing):

.. graphviz::

    digraph {
            rankdir = TB;
            splines = true;
            overlab = prism;

            edge [color=gray50, fontname=Calibri, fontsize=11];
            node [style=filled, shape=record, fontname=Calibri, fontsize=11];

            "Node";

            "Switch #1" [color=green];
            "Switch #2";

            "Canister #1" [color=green];
            "Canister #2" [color=red];

            "iSCSI Target #1" [color=green];
            "iSCSI Target #2";

            "Node" -> "Switch #1" [dir=none,color=green]
            "Node" -> "Switch #2" [dir=none];

            "Switch #1" -> "Canister #1" [dir=none,color=green];
            "Switch #1" -> "Canister #2" [dir=none,color=red];

            "Switch #2" -> "Canister #1" [dir=none];
            "Switch #2" -> "Canister #2" [dir=none];

            "Canister #1" -> "iSCSI Target #1" [dir=none,color=green];
            "Canister #1" -> "iSCSI Target #2" [dir=none];

            "Canister #2" -> "iSCSI Target #1" [dir=none,color=red];
            "Canister #2" -> "iSCSI Target #2" [dir=none];
        }

.. _imap-deployment-storage-performance:

Performance
===========

Storage Tiering
---------------

Storage tiering includes the combination of different types of storage
or storage volumes with different performance expectations within the
infrastructure, so that a larger volume of slower, cheaper storage can
be used for items that are not used that much, and/or are not that
important for day-to-day operations, while a smaller volume of faster,
more expensive storage can be used for items that are frequently
accessed and have significant importance to everyday use.

The |product| administrator guide has a section on using
:ref:`admin-tweaking-cyrus-imapd-storage-tiering` to tweak Cyrus IMAP
performance, to illustrate various opportunities to make optimal use of
your storage.

As a general rule of thumb, you could divide
:term:`operating system disks` and :term:`payload disks`; the operating
system disk could hold your base installation of a node, including
everything in the root (``/``) filesystem, while your payload disk(s)
hold the files and directories that contain the system's service(s)
payload (such as ``/var/lib/mysql/``, ``/var/spool/imap/``,
``/var/lib/imap/``, ``/var/lib/dirsrv/``, etc.).

Distributing what is and what is not frequently used may be a cumbersome
task for administrators. Some storage vendor's appliances offer
automated storage tiering, where some disks in the appliance are SSDs,
while others are SATA or SAS HDDs, and the appliance itself tiers the
storage.

A similar solution is available to Linux nodes, through `dm-cache`_,
provided they run a recent kernel.

Disk Buffering
--------------

Reading from a disk is considered very, very slow when compared to
accessing a node's (real) memory. While dependent on the particular I/O
pattern of an application, it is not uncommon at all for an application
to read the same part of a disk volume several times during a relatively
short period of time.

In |product|, for example, while a user is logged in, a mail
folder's :file:`cyrus.index` is read more frequently than it is
written to -- such as when refreshing the folder view, when opening a
message in the folder, when replying to a message, etc.

It is important to appreciate the impact of `memory-based buffer cache`_
for this type of I/O on the overall performance of the environment.

Should no (local) memory-based buffer cache be available, because for
example you are using a network filesystem (NFS, GlusterFS, etc.), then
it is extremely important to appreciate the consequences in terms of the
performance expectations.

Readahead
---------

Reading ahead is a feature in which -- in a future-predicting,
anticipatory fashion -- a chunk of storage is read in addition to the
chunk of storage actually being requested.

A common application of read-ahead is to record all files accessed
during the boot process of a node, such that later boot sequences can
read files from disk, and insert them in to the
`memory-based buffer cache`_ ahead of software actually issuing the call
to read the file. The file's contents can now be reproduced from the
faster (real) memory rather then from the slow disk.

Readahead generally does not matter for small files, unless read
operations work on a collective of aggregate message files. It does
however matter for attached devices on infrastructural components such
as hypervisors, where entire block devices (for the guest) are the files
or block devices being read.

The ideal setting for readahead depends on a variety of factors and can
usually only be established by monitoring an environment and tweaking
the setting (followed by some more monitoring).

..
    Writeback
    ---------

    `Linux Page Cache`_

.. _imap-deployment-storage-scalability:

Scalability
===========

When originally planning for storage capacity, a few things are to be
taken in to account. We'll point these out and address them later in
this section.

Generically speaking, when storage capacity is planned for initially,
a certain period of time is used to establish how much storage might be
required (for that duration).

However, let's suppose regulatory provisions dictate a period of 10
years of business communications need to be preserved. How does one
accurately predict the volume of communications over the next 10 years?

Let's suppose your organization is in flux, expanding or contracting as
businesses do at times, or budget cuts and unexpected extra tasks to
your organization might incur. Or when the organization takes over or
otherwise incorporates another.

Today's storage coming with a certain price-tag, and tomorrow's with a
different one, it can be an interesting exercise to plan for storage to
grow organicly as needed, rather than make large investments to provide
capacity that may only be used years from today, or not be used at all,
or turn out to still not be sufficient.

One may also consider planning for the future expansion of the storage
solution chosen today, possibly including significant changes in
requirements (larger mailboxes).

Data Retention
--------------

|product| by default does not delete IMAP spool contents from the
filesystem for a period of 69 days.

This means that when a 100 users each have 1 GB of quota, the actual
data footprint might grow way beyond 100 GB on disk.

Depending on the nature of how you use |product|, a reasonable
expectation can be formulated and used for calculating the likely amount
of disk space used in addition to the content that continues to count
towards quota.

For example, if a large amount of message traffic ends up in a shared
folder that many users read messages from and respond to (such as might
be the case for an info@example.org email address), then around triple
the amount of traffic per month will continue to be stored on disk, plus
what you decide is still current and not deleted by users (the "live
size").

Shared Folders
--------------

Shared folders (primarily those to which mail is delivered) do not, by
default, have any quota on them. They are also not purged by default. As
such, they could grow infinitely (until disks run out of space).

A busy mailing list used for human communications, such as
devel@lists.fedoraproject.org, can be expected to grow to as much as 1
GB of data foot print on disk over a period of 3 years -- at a message
rate of < ~100 a day and without purging.

A mailing list with automated messages generated from applications, such
as bugs-list@kde.org, which is notified of all ticket changes for KDE's
upstream Bugzilla, can be expected to grow to up to 3.5 GB over the same
period -- at a message rate of ~300 per day and without purging.

User's Groupware Folders
------------------------

Users tend not to clean up their calendars, removing old appointments
that have no bearing on today's views/operations any longer. Kolab
Groupware does not (yet) provide means to purge these items. They do
however count towards a user's quota.

.. _imap-deployment-storage-capacity:

Capacity
========

Regardless of the volume of storage in total, this section relates to
the volume of storage allocated to any one singular specific purpose in
|product|, and capacity planning in light of that (not the layer
providing the storage).

Archiving and e-Discovery notwithstanding, the largest chunks of data
volume you are going to find in |product| are the live IMAP
spools.

Let each individual IMAP spool be considered a volume, or part of a
volume if you feel inclined to share volumes across Cyrus IMAP backend
instances. Regardless, you need a filesystem **somewhere** (even if the
bricks building the volume are distributed) -- the recommended
restrictions you should put forth to the individual chunks of storage
lay therein.

Saturating the argument to make a point, imagine, if you will, a million
users with one gigabyte of data each. Just the original, minimal data
footprint is now around and about one petabyte.

Performing a filesystem check (:command:`fsck.ext4` comes to mind) on a
single one petabyte volume will be prohibitively expensive simply
considering the duration of the command to complete execution, let alone
successful execution, for your **million** users will not have access to
their data while the command has not finished -- again, let alone it
finished successfully.

**Solely therefore** would you require a second copy of the groupware
payload, now establishing a minimal data footprint to **two** petabyte.

.. NOTE::

    Also note that the two replicas of one petabyte would, if the
    replication occurs at the storage volume level, run the risk of
    corrupting both replicas' filesystems.

Your requirements for data redundancy aside, filesystem checks needing
to be performed at least regularly [#]_, if not for the level of
likelihood they need to happen because actual recovery is required,
should be restricted to a volume of data that enables the check to
complete in a timely fashion, and possibly (when no data redundancy is
implemented) even within a timeframe you feel comfortable you can hold
off your users/customers while they have no access to their data.

For filesystem checks to need to happen regularly, is not to say that
such filesystem checks require the node to be taken offline. Should you
use Logical Volume Management (LVM) for example, and not allocate 100%
of the volume group to the logical volume that holds the IMAP spool,
than intermediate filesystem checks can be executed on a snapshot of
said logical volume instead, and while the node remains online, to give
you a generic impression of the filesystem's health. Given this
information, you can schedule a service window should you feel the need
to check the actual filesystem.

A good article on filesystems, the corruption of data and their causes
and mitigation strategies has been written up by `LWN`_,
`The 2006 Linux Filesystem Workshop`_. This article also explains what
it is a filesystem check actually does, and why it is usually configured
to be ran after either a certain amount of delay or number of mounts.

..
    Using Bricks to Build a Larger Volume
    -------------------------------------

    500 bricks of 4 TB each would build a two petabyte storage volume with
    enough space for redundant storage, where individual bricks can be taken
    offline, its filesystem can be checked, and the brick can be brought
    back online, without interrupting data availability.

    Distributing Payload
    --------------------

    250 systems of 4 TB each would amount to one petabyte of total storage
    volume,

.. _imap-deployment-storage-cost:

Cost
====

When cost is of no concern, multiple vendors of storage solutions will
tell you precisely what you need to hear -- I think we've all been
there.

When cost is a concern, however, cheaper disks are often slower, fail
faster, and sometimes also do not provide the
:ref:`imap-deployment-storage-capacity` desired.

On the other hand, stuffing many consumer-grade SATA III disks in to
some commodity hardware likely raises run-time costs -- energy.

However, a chassis of a storage solution usually comes at a higher
price point, and therefore expands capacity with relatively large
chunks, which may not be what you require at that moment.

.. rubric:: Footnotes

.. [#]

    Applications may also operate on data not stored on disk at all,
    which is another common avenue potentially resulting in loss of data
    -- or *corruption*, which is merely a type of data-loss.

.. [#]

    With read operations, the other node(s) must be blocked from
    writing, and with write operations, the other node(s) must be
    blocked from reading and writing.

.. [#]

    When using ClusterLVM, you would use logical volumes as disks for
    your guests.

.. [#]

    When using GFS, you would mount the GFS filesystem partition on each
    hypervisor and use disk image files.

.. [#]

    Execute filesystem checks regularly to increase your level of
    confidence, that should emergency repairs need to be performed, you
    are able to recover swiftly.

    The :term:`MTBF` of a stable filesystem has most often been subject
    to the failure of the underlying disk, with the filesystem unable to
    recover (in time) from the underlying disk failing (partly).
	

.. _DRBD: http://www.drbd.org/
.. _OSI model for networking: http://en.wikipedia.org/wiki/OSI_model
.. _LWN: http://lwn.net
.. _The 2006 Linux Filesystem Workshop: http://lwn.net/Articles/190222/
.. _GlusterFS: http://www.glusterfs.org
.. _Ceph: http://ceph.com
.. _NFS is considered harmful: http://www.time-travellers.org/shane/papers/NFS_considered_harmful.html
.. _Filesystems\: Smaller is Better: https://access.redhat.com/site/documentation/en-US/Red_Hat_Enterprise_Linux/6/html/Global_File_System_2/ch-considerations.html#s2-fssize-gfs2

.. _Linux Page Cache: http://www.westnet.com/~gsmith/content/linux-pdflush.htm
.. _FS Cache: https://access.redhat.com/documentation/en-US/Red_Hat_Enterprise_Linux/6/html/Storage_Administration_Guide/ch-fscache.html
.. _Dovecot Oy: http://www.dovecot.fi
.. _memory-based buffer cache: http://www.tldp.org/LDP/sag/html/buffer-cache.html
.. _GFS: http://en.wikipedia.org/wiki/GFS2
.. _Cluster LVM: https://access.redhat.com/documentation/en-US/Red_Hat_Enterprise_Linux/6/html/Logical_Volume_Manager_Administration/LVM_Cluster_Overview.html
.. _dm-cache: http://en.wikipedia.org/wiki/Dm-cache
.. _Kolab Systems AG: https://kolabsys.com

.. glossary::
        MTBF
            Mean Time Between Failures

.. glossary::
        HBA
            Host Bus Adapter - connects a host system (computer) to other network and storage devices
