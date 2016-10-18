Mailbox Creation Distribution
=============================

By default, when creating a mailbox in Cyrus IMAP:

* the backend with the most free disk space is selected on the Murder frontend
* the partition with the most free disk space is selected on the backend

This may not be the most appropriate backend or partition to create the new mailbox on, and Cyrus IMAP therefor allows for a variety of additional modes of calculating and selecting the most appropriate backend and partition. The exact mode for the selection is controlled with the ``imapd.conf`` setting ``serverlist_select_mode`` on the frontend and ``partition_select_mode`` on the backend.

Alternatively, a default backend can be configured with the ``defaultserver`` setting on a frontend, and a default partition can be configured with the ``defaultpartition`` on a backend.


Prior to Cyrus IMAP version 2.5, when creating a mailbox, should no
target partition have been specified, the mailbox is either created on:

*   the configured ``defaultserver``, or

*   the server that is found to have the most free disk space, and

*   the configured ``defaultpartition``, or

*   the most fitting partition if ``defaultpartition`` is not
    configured.

New configuration options are available since Cyrus IMAP 2.5, that
allow more weighted and better balanced backend and partition
selection.

Selection Mode
--------------

Among the partitions, how the most fitting one is selected depends on the configured selection mode: ``partition_mode`` setting in ``/etc/imapd.conf``

Available Selection Modes
"""""""""""""""""""""""""

.. todo::

   See if this is the same as the section in the administrator guide - if so, just link there?

* random

    Choice is (pseudo-)random. Each partition has the same probability of being selected.

* freespace-most

    The partition which has the most free space (counted in KiB units) is selected.

    .. note:: 
        Example of ``freespace-most`` selection on backend

        Suppose that the configured partitions are:

        *   ``part1`` which has a 1000GiB capacity, 400GiB being free (that is, 40% free space)
        *   ``part2`` which has a 1000GiB capacity, 600GiB being free (that is, 60% free space)
        *   ``part3`` which has a 100GiB capacity, 30GiB being free (that is, 30% free space)
        *   ``part4`` which has a 100GiB capacity, 70GiB being free (that is, 70% free space)

        In that case ``part2`` will be selected as most fitting, since 600GiB of free space is the biggest of all partitions.

* freespace-percent-most

    The partition which has the most percentage of free space is selected.

    .. note::
        Example of ``freespace-percent-most`` selection on backend

        In the same conditions, ``part4`` would be selected as most fitting, since 70% of free space is the biggest of all partitions.

* freespace-percent-weighted

    For each partition, the percentage of free space is its weight. Then a weighted choice is performed to select one of those partitions.

    As such, the more free space the partition has, the more chances it has to be selected.

    .. note::
        Example of ``freespace-percent-weighted`` selection on backend

        In the same conditions, the weight of each partition would be:

        * 40 for ``part1``
        * 60 for ``part2``
        * 30 for ``part3``
        * 70 for ``part4``

        The sum of each weight being 200, the probability for each partition to be selected as most fitting would be:

        * 20% for ``part1``
        * 30% for ``part2``
        * 15% for ``part3``
        * 35% for ``part4``

Usage convergence
"""""""""""""""""

In ``freespace-percent-weighted`` mode, partitions percentage usages converge towards 100%. So if they have different usages, those differences will stay and only really diminish upon reaching 100% of usage.

You may also observe growing differences between partitions usage when those partitions do not have the same total disk space.

* freespace-percent-weighted-delta

As for ``freespace-percent-weighted``, a weight is associated to each partition. It is computed as follows: (*percentage of freespace of partition*) - (*lowest percentage of freespace of all partitions*) + 0.5

Then a weighted choice is performed to select one of those partitions.

As such, considering the percentages of usage, the more the partition is lagging behind the most used partition (which is the one with the lowest percentage of free space), the more chances it has to be selected.

Computed weight
"""""""""""""""

The added 0.5 in partitions weight is so that selection gets smoother when all partitions get close to each other.

.. note ::
    **Example of ``freespace-percent-weighted-delta`` Selection on Backend**

    In the same conditions, the weight of each partition would be:

    * 40 - 30 + 0.5 = 10.5 for ``part1``
    * 60 - 30 + 0.5 = 30.5 for ``part2``
    * 30 - 30 + 0.5 = 0.5 for ``part3``
    * 70 - 30 + 0.5 = 40.5 for ``part4``

    Then the probability for each partition to be selected as most fitting would be:

    * 12.8% for ``part1``
    * 37.2% for ``part2``
    * 0.6% for ``part3``
    * 49.4% for ``part4``

    **Usage convergence**

    In ``freespace-percent-weighted-delta`` mode, partitions percentage usages converge towards the most used one. And then partitions usages grow equally.

Special cases
-------------

What happens when two partitions are equal as most fitting?
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""

Suppose you are using the ``freespace-most`` selection mode, that two (or more) partitions have the same free size, and that this freespace happens to be the biggest one of all configured partitions.

In that case, only one of those partitions will be selected. You may not know in advance which one will be: it depends of the order in which configured partitions are stored in memory (``hashtable``). In particular, it may not be the first one that appears listed in your ``/etc/imapd.conf`` configuration file.

Also note that since the selected partition will now have less free space, it shall not be seen as most fitting next time.

What happens when two partitions point to the same device?
""""""""""""""""""""""""""""""""""""""""""""""""""""""""""

Suppose you are using the ``freespace-most`` or ``freespace-percent-most`` selection mode, and that two (or more) partitions actually point to the same device (that is the device id is the same).

In that case, only one of those partitions will be checked, as if the others were not configured. You may not know in advance which one will be: it depends of the order in which configured partitions are stored in memory (``hashtable``). In particular, it may not be the first one that appears listed in your ``/etc/imapd.conf`` configuration file.

Partitions Exclusion
--------------------

Partitions listed in the ``partition_mode_exclude`` setting are permanently excluded from being selected.

* partition_mode_exclude

    Listed partitions names are separated by space or comma. Only configured partition names (and not paths) are expected.

    .. note::
        Example of permanent partition exclusion

        With the following configuration in `/etc/imapd.conf`, ``parta`` and ``partb`` would be permanently excluded from being selected:

        partition-part1: /path/to/part1
        partition-part2: /path/to/part2
        partition-part3: /path/to/part3
        partition-part4: /path/to/part4
        partition-parta: /path/to/parta
        partition-partb: /path/to/partb

        partition_mode_exclude: parta partb
        

        When using a selection mode other than ``random``, partitions are automatically excluded if their usage percentage is beyond the ``partition_mode_soft_usage_limit`` integer setting.


* partition_mode_soft_usage_limit
    
    If all partitions are beyond the configured value, this feature is automatically deactivated. A partition is thus selected as if the setting was not set.

    .. note::
        Example of partition exclusion using ``partition_mode_soft_usage_limit``

        In the same conditions than <xref linkend="exam-Deployment_Guide-Available_Selection_Modes_on_Backend-Example_of_freespace_most_Selection_on_Backend" />, setting ``partition_mode_soft_usage_limit`` to ``50`` would exclude partitions ``part1`` and ``part3`` since their disk usage is respectively 60% and 70%.

        But setting the option to ``20`` would have no effect, since the usage of all partitions is beyond 20%.

    .. warning::

        **Exclusion is not absolute**

        Partitions are only excluded when creating a new user mailbox according to the configured selection mode.

        If you explicitly specify an excluded partition, the mailbox will be created on that partition.

        Mailboxes previously created on such partitions are of course still accessible, and subfolders are by default still created on the same partition as the parent folder.


Partitions Usage Data Reset
---------------------------

By default partitions usage data are retrieved only once upon service initialization. This only concerns selection modes other than ``random``.

If you tend to use the same service instance for a long lapse of time and performs a large amount of mailboxes creation, it may be useful to configure the ``partition_mode_usage_reinit`` so that partitions usage data are refreshed after the configured number of creation requests.


Mailbox Creation Distribution Through ``murder frontend``
---------------------------------------------------------

Upon creating a user mailbox, if the target server is not given as extra parameter, the mailbox is either created on

* the configured ``defaultserver`` backend
* the most fitting backend among the servers listed in the ``serverlist`` setting, if ``defaultserver`` is not configured


Selection Mode
""""""""""""""

Among the backends, how the most fitting one is selected depends on the configured selection mode: ``serverlist_mode`` setting in ``/etc/imapd.conf``.

The principle is similar to the mailbox creation distribution on backend (see <xref linkend="sect-Deployment_Guide-Mailbox_Creation_Distribution-On_backend" />).


Available Selection Modes on Frontend
"""""""""""""""""""""""""""""""""""""

* random

    Choice is (pseudo-)random. Each backend has the same probability of being selected.

* freespace-most

    The backend which has the most free space (counted in KiB units) is selected. The considered free space is the sum of all available partitions free space on the backend.

    .. note::
        Example of ``freespace-most`` Selection on Frontend

        Suppose that the configured backends are:

        * ``backend1`` which has a 2000GiB capacity, 1000GiB being free (that is, 50% free space), composed of 2 partitions
        * ``part1`` which has a 1000GiB capacity, 500GiB being free (that is, 50% free space)
        * ``part2`` which has a 1000GiB capacity, 500GiB being free (that is, 50% free space)

            * ``backend2`` which has a 2000GiB capacity, 900GiB being free (that is, 45% free space), composed of 2 partitions
            * ``part1`` which has a 1000GiB capacity, 200GiB being free (that is, 20% free space)
            * ``part2`` which has a 1000GiB capacity, 700GiB being free (that is, 70% free space)

                * ``backend3`` which has a 200GiB capacity, 110GiB being free (that is, 55% free space), composed of 2 partitions
                * ``part1`` which has a 100GiB capacity, 30GiB being free (that is, 30% free space)
                * ``part2`` which has a 100GiB capacity, 80GiB being free (that is, 80% free space)

        * In that case ``backend1`` will be selected as most fitting, since 1000GiB of free space is the biggest of all backends.

* freespace-percent-most

    On each backend, the partition with the most percentage of free space is considered. The selected backend is the one whose partition has the most percentage of free space.

    .. note::
        Example of ``freespace-percent-most`` Selection on Frontend
     
        In the same conditions than <xref linkend="exam-Deployment_Guide-Available_Selection_Modes_on_Frontend-Example_of_freespace_most_Selection_on_Frontend" /> ``backend3`` would be selected as most fitting, since it has a partition with 80% of free space which is the biggest of all backends.


* freespace-percent-weighted

    On each backend, the partition with the most percentage of free space is considered: it is the backend weight. Then a weighted choice is performed to select one of the backends.

    .. note::
        Example of ``freespace-percent-weighted`` Selection on Frontend

        In the same conditions than <xref linkend="exam-Deployment_Guide-Available_Selection_Modes_on_Frontend-Example_of_freespace_most_Selection_on_Frontend" />, the weight of each backend would be:

            * 50 for ``backend1``
            * 70 for ``backend2``
            * 80 for ``backend3``

        The sum of each weight being 200, the probability for each backend to be selected as most fitting would be:

            * 25% for ``backend1``
            * 35% for ``backend2``
            * 40% for ``backend3``

* freespace-percent-weighted-delta

On each backend, the partition with the most percentage of free space is considered. As for ``freespace-percent-weighted``, a weight is associated to each backend. It is computed as follows: (*percentage of freespace on backend*) - (*lowest percentage of freespace of all backends*) + 0.5

Then a weighted choice is performed to select one of the backends.

    .. note::
        **Example of ``freespace-percent-weighted-delta`` Selection on Frontend**

        In the same conditions than <xref linkend="exam-Deployment_Guide-Available_Selection_Modes_on_Frontend-Example_of_freespace_most_Selection_on_Frontend" />, the weight of each backend would be:

        * 50 - 50 + 0.5 = 0.5 for ``backend1``
        * 70 - 50 + 0.5 = 20.5 for ``backend2``
        * 80 - 50 + 0.5 = 30.5 for ``backend3``
     
        Then the probability for each backend to be selected as most fitting would be:

        * 1.0% for ``backend1``
        * 39.8% for ``backend2``
        * 59.2% for ``backend3``


Backends Exclusion
------------------

When using a selection mode other than ``random``, backends are automatically excluded if their considered usage percentage is beyond the ``serverlist_mode_soft_usage_limit`` integer setting.

* ``partition_mode_soft_usage_limit``
 
If all backends are beyond the configured value, this feature is automatically deactivated. A backend is thus selected as if the setting was not set.

    .. note::
        Example of partition exclusion using ``serverlist_mode_soft_usage_limit``

        In the same conditions than <xref linkend="exam-Deployment_Guide-Available_Selection_Modes_on_Frontend-Example_of_freespace_most_Selection_on_Frontend" />, using ``freespace-most`` selection mode, setting ``serverlist_mode_soft_usage_limit`` to ``49`` would exclude ``backend1`` and ``backend2`` since in that mode they have a disk usage of 50% and 55%. In other modes it would however only exclude ``backend1`` whose considered partition has a disk usage of 50%, while on ``backend2`` the considered partition has a disk usage of 30%.

    .. warning::

        **Exclusion is not absolute**
     
        Backends are only excluded when creating a new user mailbox according to the configured selection mode.

        If you explicitly specify an excluded backend, the mailbox will be created on that backend.

        Mailboxes previously created on such backends are of course still accessible.


Backends Usage Data Reset
-------------------------

By default backends usage data are retrieved only once upon service initialization. This only concerns selection modes other than ``random``.

If you tend to use the same service instance for a long lapse of time and performs a large amount of mailboxes creation, it may be useful to configure the ``serverlist_mode_usage_reinit`` so that backends usage data are refreshed after the configured number of creation requests.

