.. _imap-admin-systemcommands-sievec:

==========
**sievec**
==========

Script to compile a sieve script to bytecode.

Synopsis
========

.. parsed-literal::

    **sievec** [ **-C** *altconfig* ] *filename* *outputfile*

Description
===========

**sievec** compiles the given script at *filename* into bytecode, writing the file to the *outputfile* location.


Options
=======

.. program:: sievec

.. option:: -C altconfig

    |cli-dash-c-text|


See Also
========

:cyrusman:`masssievec(1)`, :cyrusman:`sieved(1)`
