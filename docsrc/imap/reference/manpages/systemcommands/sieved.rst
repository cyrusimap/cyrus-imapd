.. cyrusman:: sieved(8)

.. _imap-reference-manpages-systemcommands-sieved:

==========
**sieved**
==========

Tool to decompile a sieve script back from bytecode.

Synopsis
========

.. parsed-literal::

    **sieved** [OPTIONS] *bytcodefile*

Description
===========

**sieved** decompiles the given *bytecodefile*, writing output to stdout.

By default, the output is a descriptive version of the bytecode.  With the
**-s** option, an equivalent sieve script is produced instead.

Options
=======

.. program:: sieved

.. option:: -s, --as-sieve

   Produce a sieve script rather than describing the bytecode.

See Also
========

:cyrusman:`masssievec(8)`, :cyrusman:`sievec(8)`
