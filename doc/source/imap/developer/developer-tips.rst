.. _cyrus-hacking:
=========================
Tips for Hacking on Cyrus
=========================

Good Practices
==============

Migrating from http://www.cyrusimap.org/mediawiki/index.php/Cyrus_IMAP_Hacking 

File Locking
============

In order to guard against deadlocks, we want to maintain 
the same order of acquiring locks throughout the system 
(this may be violated in one or two places, but when it is it is 
commented as to why it is safe). As long as everyone plays 
by these rules, we can avoid deadlock.

In an ideal world, our locking order is::

    cyrus.header
    cyrus.index
    quota
    seen
    mailboxes file
    
These try to go from least general to most general, so we hold the largest locks for the shortest period of time.

.. todo::
    http://www.cyrusimap.org/mediawiki/index.php/Cyrus_IMAP_Hacking
    http://www.cyrusimap.org/mediawiki/index.php/Cyrus_IMAP_File_Locking
