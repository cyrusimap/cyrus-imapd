.. cyrusman:: dav_reconstruct(1)

.. _imap-reference-manpages-usercommands-dav_reconstruct:

===================
**dav_reconstruct**
===================

Rebuild the caldav and carddav database for a user/set of users.

Synopsis
========

.. parsed-literal::

    **dav_reconstruct** [ **-C** *alt_config*] [ **-A** *\<audit tool\>* ] [ **-a** ]
    [ **--repair** ] [ **--repair-uid-conflicts** ] [ **--really** ] *\<userid_list\>*

Description
===========

**dav_reconstruct** fixes up the dav internal sqlite database which is used for lots of the dav commands to make them more efficient. 

Any corruption to the dav database can cause the wrong stuff to be returned via caldav/carddav. Using dav_reconstruct can correct these faults.

The **--repair** options go further and fix the calendar data itself, using the
rebuilt database to find what is broken.  They report what they would do unless
**--really** is also given.  Note that **--repair** on its own is not a total
dry run: rewriting an index record that has a missing or duplicate
``createdmodseq``, and expunging one that a later record supersedes, is part of
rebuilding the database and happens on every run.

Repairs cannot be combined with **-A**, because the audit tool discards the
rebuilt database, which would leave the mailboxes changed and ``dav.db`` stale.

Options
=======

.. program:: dav_reconstruct

.. option:: -C  alt_config

    Alternative config file with cyrus settings.

.. option:: -a, --all

    Process all users on this store.

.. option:: -A audit-tool, --audit-tool=audit-tool

   Name of a program to take two sqlite databases and compare them. This option
   currently does not work.

.. option:: --repair

    Select every repair mode.  Future repairs join this option without changing
    its meaning.

.. option:: --repair-uid-conflicts

    Repair iCalendar UIDs that live in more than one CalDAV resource, which
    only ``caldav_put`` enforces and which several other write paths can break.
    One resource keeps its identity, its iCalendar UID and its ``createdmodseq``,
    and therefore the JMAP id clients already hold.  The others are merged into
    it where no component, per-user data, flag or annotation would be lost, and
    otherwise are split off whole under a fresh iCalendar UID, resource name and
    ``createdmodseq``, with the original UID recorded in an
    ``X-CYRUS-ORIGINAL-UID`` property.

    A split copy keeps its ORGANIZER and ATTENDEE properties under a UID the
    recipients have never seen, so editing or destroying it afterwards may
    schedule against that new UID.  The exposure is narrow, because a copy
    carrying scheduling state is preferred as the one that keeps its identity.

.. option:: --really

    Perform the selected repairs instead of only reporting them.  It is an
    error to give this without a repair option.

.. option:: userid_list

    List of users whose cal/card dav information you need to fix.



