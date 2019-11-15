:tocdepth: 2

.. _imap-features-mailbox-distribution:

====================
Mailbox Distribution
====================

Prior to Cyrus IMAP version 2.5.0, when creating a mailbox, should no
target partition have been specified, the mailbox is either created on:

*   the configured ``defaultserver``, or

*   the server that is found to have the most free disk space, and

*   the configured ``defaultpartition``, or

*   the most fitting partition if ``defaultpartition`` is not
    configured.

New configuration options are available since Cyrus IMAP 2.5.0, that
allow more weighted and better balanced backend and partition
selection.

Partition Selection Mode
========================

Among the partitions, how the most fitting one is selected depends on
the configured selection mode, using the ``partition_select_mode``
setting in :cyrusman:`imapd.conf(5)`.

.. rubric:: Available Selection Modes

.. sidebar:: Example Scenario for Selection Modes

    Suppose that the partitions configured are:

    +-----------+---------+--------+-----+
    | Partition | Total   | Free   | %   |
    +===========+=========+========+=====+
    | ``part1`` | 1000 GB | 400 GB | 40% |
    +-----------+---------+--------+-----+
    | ``part2`` | 1000 GB | 600 GB | 60% |
    +-----------+---------+--------+-----+
    | ``part3`` |  100 GB |  30 GB | 30% |
    +-----------+---------+--------+-----+
    | ``part4`` |  100 GB |  70 GB | 70% |
    +-----------+---------+--------+-----+

*   **random**

    Choice is (pseudo-)random. Each partition has the same probability
    of being selected.

*   **freespace-most**

    The partition which has the most absolute free space (counted in KiB
    units) is selected.

    In the example scenario, ``part2`` would be selected as most
    fitting, since 600 GB of free space is the biggest of all
    partitions.

*   **freespace-percent-most**

    The partition which has the most relative free space (counted in
    percentiles) is selected.

    In the example scenario, ``part4`` would be selected as most
    fitting, since 70% of free space is the biggest of all partitions.

*   **freespace-percent-weighted**

    For each partition, the percentage of free space is its weight. Then
    a weighted choice is performed to select one of those partitions.

    As such, the more free space the partition has, the higher its
    chances to be selected.

    In the example scenario, the weight of each partition would be:

    *   40 for ``part1``
    *   60 for ``part2``
    *   30 for ``part3``
    *   70 for ``part4``

    The sum of all weights being 200, the probability for each
    partition to be selected as most fitting is:

    *   20% for ``part1``
    *   30% for ``part2``
    *   15% for ``part3``
    *   35% for ``part4``

    Out of 20 (hypothetically empty) mailboxes to be created,
    chances are:

    *   4 are created on ``part1``
    *   6 are created on ``part2``
    *   3 are created on ``part3``
    *   7 are created on ``part4``

    .. NOTE::

        In ``freespace-percent-weighted`` mode, partitions percentage
        usages converge towards 100%. So if they have different usages,
        those differences will stay and only really diminish upon
        reaching 100% of usage.

        You may also observe growing differences between partitions
        usage when those partitions do not have the same total disk
        space.

**freespace-percent-weighted-delta**

    As for ``freespace-percent-weighted``, a weight is associated to
    each partition. It is computed as follows:

    .. math::

        free - leastfree + 0.5

    Then a weighted choice is performed to select one of those
    partitions.

    As such, considering the percentages of usage, the more the
    partition is lagging behind the most used partition (which is the
    one with the lowest **percentage** of free space), the higher its
    chances are to be selected.

    .. NOTE::

        The added 0.5 in partitions weight causes the selection to get
        smoother the more partitions get close to each other.

    In the example scenario, the weight of each partition would be:

    *   For ``part1``: :math:`40 - 30 + 0.5 = 10.5`
    *   For ``part2``: :math:`60 - 30 + 0.5 = 30.5`
    *   For ``part3``: :math:`30 - 30 + 0.5 = 00.5`
    *   For ``part4``: :math:`70 - 30 + 0.5 = 40.5`

    The sum of all weights amounting to 82, the probability for each
    partition to be selected as most fitting would be:

    *   For ``part1``: 12.8%
    *   For ``part2``: 37.2%
    *   For ``part3``: 00.6%
    *   For ``part4``: 49.4%

    .. NOTE::

        In ``freespace-percent-weighted-delta`` mode, partitions
        percentage usages converge towards the most used one, after
        which partitions usages grow equally.

Special Cases
-------------

Q: What happens when two partitions are equal as most fitting?
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Suppose you are using the ``freespace-most`` selection mode, that two
(or more) partitions have the same free size, and that this freespace
happens to be the biggest one of all configured partitions.

In that case, only one of those partitions will be selected. You may not
know in advance which one will be: it depends of the order in which
configured partitions are stored in memory (``hashtable``). In
particular, it may not be the first one that appears listed in your
:cyrusman:`imapd.conf(5)` configuration file.

Also note that since the selected partition will now have less free
space, it shall not be seen as most fitting next time.

Q: What happens when two partitions point to the same device?
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Suppose you are using the ``freespace-most`` or
``freespace-percent-most`` selection mode, and that two (or more)
partitions actually point to a different directory on the same
filesystem.

In that case, only one of those partitions will be checked, as if the
others were not configured. Cyrus IMAP uses the device id of the
partition hierarchy for this. You may not know in advance which one will
be: it depends of the order in which configured partitions are stored in
memory (``hashtable``). In particular, it may not be the first one that
appears listed in your :cyrusman:`imapd.conf(5)` configuration file.

Excluding Partitions
--------------------

**partition_select_exclude**

    Partitions listed in the ``partition_select_exclude`` setting in
    :cyrusman:`imapd.conf(5)` are permanently excluded from being
    selected.

    Listed partition's names are separated by spaces and/or commas. Only
    configured partition names (and not paths) are expected.

    With the following configuration in :cyrusman:`imapd.conf(5)`,
    ``parta`` and ``partb`` would be permanently excluded from being
    selected:

    .. parsed-literal::

        partition-part1: /path/to/part1
        partition-part2: /path/to/part2
        partition-part3: /path/to/part3
        partition-part4: /path/to/part4
        partition-parta: /path/to/parta
        partition-partb: /path/to/partb

        partition_mode_exclude: parta partb

**partition_select_soft_usage_limit**

    When using a selection mode other than ``random``, partitions are
    automatically excluded if their usage percentage is beyond the
    ``partition_select_soft_usage_limit`` integer setting.

    If all partitions are beyond the configured value, this feature is
    automatically deactivated. A partition is thus selected as if the
    setting was not configured.

    In the example scenario, setting ``partition_mode_soft_usage_limit``
    to ``50`` would exclude partitions ``part1`` and ``part3`` since
    their disk usages are 60% and 70% respectively.

    But setting the option to ``20`` would have no immediate effect on
    the selection of a partition, since the usage of all partitions is
    beyond 20%.

.. IMPORTANT::

    **Exclusion is not absolute**

    Partitions are only excluded when creating a new user mailbox
    according to the configured selection mode.

    If you explicitly specify an excluded partition, the mailbox will
    be created on that partition.

    Mailboxes previously created on such partitions are of course still
    accessible, and subfolders are by default still created on the same
    partition as the parent folder.

Partition's Usage Information Reset
-----------------------------------

By default, partition's usage information is retrieved only once -- when
the service first initializes.

If you tend to use the same service instance for a long lapse of time
and performs a large amount of mailbox creations, it may be useful to
configure the ``partition_select_usage_reinit`` setting so that
each partition's usage information is refreshed after the configured
number of creation requests.

.. NOTE::

    This only concerns selection modes other than `random``.

Backend Selection Mode (Cyrus IMAP Murder)
==========================================

Upon creating a user mailbox, if the target server is not given as
extra parameter, the mailbox is created on either;

*   the configured ``defaultserver`` backend

*   the most fitting backend (partition) among the servers listed in the
    ``serverlist`` setting, if ``defaultserver`` is not configured.

.. rubric:: Related Settings

*   ``serverlist_select_mode``
*   ``serverlist_select_usage_reinit``
*   ``serverlist_select_soft_usage_limit``

Available Selection Modes on Frontend
-------------------------------------

**random**

    The selection is (pseudo-)random. Each backend has the same
    probability of being selected.

.. sidebar:: Example Scenario for Selection Modes

    Suppose that the partitions configured are:

    +---------+-----------+---------+---------+-----+
    | Backend | Partition | Total   | Free    | %   |
    +=========+===========+=========+=========+=====+
    | ``be1`` |           | 2000 GB | 1000 GB | 50% |
    +---------+-----------+---------+---------+-----+
    |         | ``part1`` | 1000 GB |  500 GB | 50% |
    +---------+-----------+---------+---------+-----+
    |         | ``part2`` | 1000 GB |  500 GB | 50% |
    +---------+-----------+---------+---------+-----+
    | ``be2`` |           | 2000 GB |  900 GB | 45% |
    +---------+-----------+---------+---------+-----+
    |         | ``part1`` | 1000 GB |  200 GB | 20% |
    +---------+-----------+---------+---------+-----+
    |         | ``part2`` | 1000 GB |  700 GB | 70% |
    +---------+-----------+---------+---------+-----+
    | ``be3`` |           |  200 GB |  110 GB | 55% |
    +---------+-----------+---------+---------+-----+
    |         | ``part1`` |  100 GB |   30 GB | 30% |
    +---------+-----------+---------+---------+-----+
    |         | ``part2`` |  100 GB |   80 GB | 80% |
    +---------+-----------+---------+---------+-----+

**freespace-most**

    The backend which has the most absolute free space (counted in KiB
    units) is selected.

    .. NOTE::

        The considered free space is the sum of the free space on all
        available partitions on the backend.

    In the example scenario, ``be1`` would be selected as most fitting,
    since 1000 GB of free space is the most of all backends.

**freespace-percent-most**

    On each backend, only the partition with the most percentage of free
    space is considered. The selected backend is the one whose partition
    has the highest percentage of free space.

    In the example scenario, ``be3`` would be selected as most fitting,
    since it has a partition with 80% of free space which is the
    highest of all backends.

**freespace-percent-weighted**

    On each backend, only the partition with the most percentage of free
    space is considered: this is the backend weight. Then a weighted
    choice is performed to select one of the backends.

    In the example scenario, the weight of each backend would be:

    *   50 for ``be1``
    *   70 for ``be2``
    *   80 for ``be3``

    The sum of all weights being 200, the probability for each backend
    to be selected as most fitting would be:

    *   25% for ``be1``
    *   35% for ``be2``
    *   40% for ``be3``

**freespace-percent-weighted-delta**

    On each backend, only the partition with the most percentage of free
    space is considered.

    Like with ``freespace-percent-weighted``, a weight is associated to
    each backend. It is computed as follows:

    .. math::

        free - leastfree + 0.5

    Then a weighted choice is performed to select one of the backends.

    In the example scenario, the weight of each backend would be:

    *   For ``be1``: :math:`50 - 50 + 0.5 = 0.5`
    *   For ``be2``: :math:`70 - 50 + 0.5 = 20.5`
    *   For ``be3``: :math:`80 - 50 + 0.5 = 30.5`

    Then the probability for each backend to be selected as most fitting would be:

    *   1.0% for ``be1``
    *   39.8% for ``be2``
    *   59.2% for ``be3``

Excluding Backends
------------------

When using a selection mode other than ``random``, backends are
automatically excluded if their considered usage percentage is beyond
the ``serverlist_select_soft_usage_limit`` integer setting.

Backend's Usage Information Reset
---------------------------------

By default backends usage data are retrieved only once upon service
initialization.

.. NOTE::

    This only concerns selection modes other than ``random``.

If you tend to use the same service instance for a long lapse of time
and performs a large amounts of mailbox creations, it may be useful to
configure the ``serverlist_select_usage_reinit`` so that the backend's
disk usage information is refreshed after the configured number of
creation requests.

Back to :ref:`imap-features`
