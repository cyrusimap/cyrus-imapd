====================
Mailbox Distribution
====================

In a Cyrus IMAP Murder, the backend server and/or partition on which a new mailbox is created, when created through a Cyrus IMAP Murder frontend, is traditionally selected by querying each of the configured backends (**serverlist** setting in :cyrusman:`imapd.conf(5)` on the Murder frontend) for the absolute amount of free disk space. The largest amount of absolute free disk space is used as the server and partition on which to create the new mailbox.

On a Cyrus IMAP Murder frontend, a default backend can be configured using the **defaultserver** setting in :cyrusman:`imapd.conf(5)`, and on a Cyrus IMAP Murder backend, a default partition can be configured with the **defaultpartition** setting in :cyrusman:`imapd.conf(5)`.

As of Cyrus IMAP 2.5, the server and/or partition on which new mailboxes are created is fully configurable, and provides a lot more option value with more intelligent selection routines available. Please note that the related settings can be changed at any time and without impact to existing mailboxes.

In Cyrus IMAP 2.5, the backend server and/or partition selection can be controlled with **serverlist_select_mode** for frontend server selection, and **partition_select_mode** for backend partition selection. The **partition_select_mode** naturally applies to stand-alone Cyrus IMAP 2.5 servers not part of a murder topology as well.

.. note:: **Only on Mailbox Creation**

    Please note that the settings only impact backend and partition selection during the creation of mailboxes. No automatic balancing of mailboxes by number, use or size during runtime is currently available, nor is any storage hierarchy concept. 

Selection Modes
===============

Selection modes configurable on frontend and backend share the same principles. In each case, a list of available items are considered: those are the backends when creating the mailbox through a frontend, and the partitions when being on the backend. Depending on the configured selection mode, each item has an associated (disk) capacity and free space which will be used to select the most fitting one.

.. note:: **Unified murder**
    Please remember that when using a unified murder configuration, a server is both a frontend and a backend: you can create and access local or remote mailboxes. Since configuration settings are distinct for each role the server can take, you can apply different selection modes for each role.

Available Selection Modes
-------------------------

**random**

    Choice is (pseudo-)random. Each item has the same probability of being selected.

**freespace-most**

    The item which has the most free space (counted in KiB units) is selected. That is the default selection mode.

    | Example: Suppose that the available items are:
    |
    | **item1** with 1000GB of capacity, 400GB being free (40% free space)
    | **item2** with 1000GB of capacity, 600GB being free (60% free space)
    | **item3** with 100GB of capacity, 30GB being free (30% free space)
    | **item4** with 100GB of capacity, 70GB being free (70% free space) 
    |
    | In this case **item2** will be selected as most fitting, since 600GB of free space is the biggest space of all.

**freespace-percent-most**

    The item which has the most percentage of free space is selected.

    | Example: Suppose that the available items are:
    |
    | **item1** with 1000GB of capacity, 400GB being free (40% free space)
    | **item2** with 1000GB of capacity, 600GB being free (60% free space)
    | **item3** with 100GB of capacity, 30GB being free (30% free space)
    | **item4** with 100GB of capacity, 70GB being free (70% free space) 
    
    | In this case **item4** would be selected as most fitting, since 70% of free space is the largest percentage of all.

**freespace-percent-weighted**

    For each item, the percentage of free space is its weight. Then a weighted choice is performed to select one of those items.
    As such, the more free space the item has, the more chances it has to be selected.

    | Example: 
    |
    | **item1** with 1000GB of capacity, 400GB being free (40% free space), weight is 40
    | **item2** with 1000GB of capacity, 600GB being free (60% free space), weight is 60
    | **item3** with 100GB of capacity, 30GB being free (30% free space), weight is 30
    | **item4** with 100GB of capacity, 70GB being free (70% free space), weight is 70 
    | 
    | The sum of the weights being 200, the probability for each item to be selected as most fitting would be::
    |
    | 100 * (40 / 200) = 20% for item1
    | 100 * (60 / 200) = 30% for item2
    | 100 * (30 / 200) = 15% for item3
    | 100 * (70 / 200) = 35% for item4 

.. note:: **Usage convergence**
    Using the freespace-percent-weighted mode, the percentage usages will converge towards 100%. So if they have different usages, those differences will stay and only really diminish upon reaching 100% of usage.
    
    You may also observe growing differences between items usages when they do not have the same total disk space. 

**freespace-percent-weighted-delta**

    As for **freespace-percent-weighted**, a weight is associated to each item. It is computed as follows: 
    
    ``(*percentage of freespace of item*) - (*lowest percentage of freespace of all items*) + 0.5``
    
    Then a weighted choice is performed to select one of those items.
    
    (The added 0.5 in item's weight is so that selection gets smoother when all items usage percentages get close to each other.)
    
    As such, considering the usage percentages, the more the item is lagging behind the most used one (which has the lowest percentage of free space), the more chances it has to be selected.
    
    | Example: In the same conditions as above, the weight of each item would be::
    |
    | 40 - 30 + 0.5 = 10.5 for item1
    | 60 - 30 + 0.5 = 30.5 for item2
    | 30 - 30 + 0.5 = 0.5 for item3
    | 0 - 30 + 0.5 = 40.5 for item4 

    | The sum of the weights being 82, the probability for each item to be selected as most fitting would be::
    |
    | 100 * (10.5 / 82) = 12.8% for item1
    | 100 * (30.5 / 82) = 37.2% for item2
    | 100 * (0.5 / 82) = 0.6% for item3
    | 100 * (40.5 / 82) = 49.4% for item4 

.. note:: **Usage convergence**
    Using the freespace-percent-weighted-delta mode, items percentage usages will converge towards the most used one. And then items usage will grow equally. 
    
Guidelines
----------

Which mode to use depends primarily on whether you are building the platform from scratch, or adding servers and partitions and if you plan to create a lot of empty mailboxes in a short period of time.

The Selection mode can be changed as needed.

If you plan to create a lot of empty mailboxes in a short period of time, use **random**. The other modes rely on the amount of freespace on backends and partitions, and thus would create most (if not all) the mailboxes at the same place, which will become an issue later as those mailboxes grow.

If you only care about the amount of free space, you can use the default mode (**freespace-most**) or **freespace-percent-most**.

Otherwise you should use **freespace-percent-weighted-delta**, which is generally good enough for situations where mailbox creation pace is slow, or **freespace-percent-weighted**.


Special cases
=============

What happens when two items are equal as most fitting ?
-------------------------------------------------------

The freespace-most and freespace-percent-most modes do select the item with the most free space or percent of free space. It may happen that two or more items do have the same value. If this value appears as most fitting, only one item will be selected, but you may not know in advance which one will be. In particular, it may not be the first one that appears listed in your configuration.

Also note that after the mailbox is created on the selected item, it will have less free space and thus shall not be seen as most fitting next time. 

What happens when two items are actually the same ?
---------------------------------------------------

Each item has an associated id:

* its name for a backend
* its device id for a partition 

If two or more items share the same id when using the freespace-most or freespace-percent-most mode, only one of those items will actually be checked, as if the others were not configured. You may not know in advance which one will be. 

Items Exclusion
---------------

When using a selection mode other than random, items can be automatically excluded if their usage percentage is beyond a configured integer setting:

* **serverlist_select_soft_usage_limit** on a frontend
* **partition_select_soft_usage_limit** on a backend 

.. note:: Soft usage limit
    If all items are beyond the configured value, this feature is automatically deactivated. An item is thus selected as if the setting was not set.

.. important:: Exclusion is not absolute
    Items are only excluded when creating a new user mailbox according to the configured selection mode.
    If you explicitly specify an excluded item, the mailbox will be created on that item.
    Mailboxes previously created there are of course still accessible, and subfolders are by default still created at the same place than the parent folder. 

Items Usage Data Reset
----------------------

By default items usage data are retrieved only once upon service initialization (that is when an imapd instance is created). This only concerns selection modes other than random.

If you tend to use the same service instance for a long lapse of time and perform a large amount of mailboxes creation, usage data will soon be out-of-date. For the cases where it is useful to refresh those data, you can configure the number of creation requests after which data are resetted:

* **serverlist_select_usage_reinit** for a frontend
* **partition_select_usage_reinit** for a backend 

Application
===========

What each item (disk) capacity and free space represents depends on the situation.

On backend
----------

On the backend a partition is represented by its disk capacity and free space. Each example listed in Available Selection Modes can be interpreted in a straightforward way by replacing references to item by partition. 

On frontend
-----------

.. todo:: There should be a chapter giving details on how backends are configured (next to the one about backend partitions). Maybe adding a link to there would be useful ?

On the frontend a backend is represented by its available partition with the most percentage of free space, except for the **freespace-most** mode where it is the sum of all its available partitions. Of course this does not apply to the **random** mode.

Example of backend representation on frontend
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

    Suppose that a backend has a 2000GiB capacity, 900GiB being free (45% free space), composed of 2 partitions

    * **part1** which has a 1000GiB capacity, 200GiB being free (20% free space)
    * **part2** which has a 1000GiB capacity, 700GiB being free (70% free space) 

    That backend would be represented by:

    * its partition **part2** for the **freespace-percent-most**, **freespace-percent-weighted** and **freespace-percent-weighted-delta** modes, since that partition has the most percentage of free space: that is a 1000GiB capacity, 700GiB being free (70% free space)
    * the sum of all its available partitions for the **freespace-most** mode: that is a 2000GiB capacity, 900GiB being free (45% free space) 

Keeping that in mind, you can refer to examples listed in Available Selection Modes to determine how most fitting backends are selected.

Backends Exclusion
------------------

For details on exclusion based on disk usage, see Section "Items Exclusion".

Example of backend exclusion using serverlist_select_soft_usage_limit
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The backend in  “Example of backend representation on frontend” would be excluded using the **freespace-most** selection mode and setting **serverlist_select_soft_usage_limit** to 50 since in that mode it is represented by a disk usage of 55%. In other modes it would not be excluded, since it would be represented by a disk usage of 30%. 

