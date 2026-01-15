.. cyrusman:: mknewsgroups(8)

.. _imap-reference-manpages-systemcommands-mknewsgroups:

================
**mknewsgroups**
================

Synopsis
========

.. parsed-literal::

    **mknewsgroups** 

Description
===========

mknewsgroups [-h] [-n] [-C <config-file>] [-f <active-file>] [-u <user>]
[-w <wildmats>] [-p <part>] [-a <acls>] <server>

Options
=======

.. program:: mknewsgroups

.. option:: -h

    Display help.
    
.. option:: -n  

    Print the IMAP commands, but don't execute them.
    
.. option:: -C  <config file>

    Use the config in <config-file> instead of /etc/imapd.conf
    
.. option:: -f <active-file>

    Use the newsgroups in <active-file> instead of ./active
    (get current file from ftp://ftp.isc.org/usenet/CONFIG/active)
    
.. option:: -u  <user>

    Authenticate as <user> instead of the current shell user

.. option:: -w <wildmats>

    Only create the newsgroups specified by <wildmats>.  <wildmats>
    is a comma-separated list of wildmat pattern (eg, \"*,!alt.*\")
    
.. option:: -p  <part>

    Create the newsgroup mailboxes on partition <part>

.. option:: -a <acls>

    Set <acls> on the newsgroup.  <acls> is a whitespace-separated list
    of cyradm-style userid/rights pairs (eg, \"anyone +p  news write\")
    