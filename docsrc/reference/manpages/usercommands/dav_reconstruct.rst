.. cyrusman:: dav_reconstruct(1)

.. _imap-reference-manpages-usercommands-dav_reconstruct:

===================
**dav_reconstruct**
===================

Rebuild the caldav and carddav database for a user/set of users.

Synopsis
========

.. parsed-literal::

    **dav_reconstruct** [ **-C** *alt_config*] [ **-A** *\<audit tool\>* ] [ **-a** ] *\<userid_list\>*

Description
===========

**dav_reconstruct** fixes up the dav internal sqlite database which is used for lots of the dav commands to make them more efficient. 

Any corruption to the dav database can cause the wrong stuff to be returned via caldav/carddav. Using dav_reconstruct can correct these faults.

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

.. option:: userid_list

    List of users whose cal/card dav information you need to fix.



