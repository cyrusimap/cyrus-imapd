.. cyrusman:: arbitronsort.pl(8)

.. _imap-reference-manpages-systemcommands-arbitronsort.pl:

===================
**arbitronsort.pl**
===================

Takes the output of arbitron and prints out mailboxes in sorted order.

Synopsis
========

.. parsed-literal::

    **arbitronsort.pl** 

Description
===========

This script takes the output of :cyrusman:`arbitron(8)` (run without the ``-o`` option)
and prints out:

* a ranking of mailboxes by number of people who selected the mailbox
* a ranking of mailbox by number of subscribers.

Example
=======

.. parsed-literal::

    **arbitron -l \| arbitronsort.pl**

..    

See Also
========

:cyrusman:`arbitron(8)`