.. cyrusman:: cyr_buildinfo(8)

.. _imap-admin-systemcommands-cyr_buildinfo:

=================
**cyr_buildinfo**
=================

Cyrus build-configuration inspection tool
 
Synopsis
========

.. parsed-literal::

    **cyr_buildinfo** [ **-C** *config-file* ] [format]

Description
===========

**cyr_buildinfo** is a tool to inspect the build configuration of a Cyrus release.  The intent is to
provide compilation settings during runtime and testing.

**cyr_buildinfo** |default-conf-text|

Options
=======

.. program:: cyr_buildinfo

.. option:: -C config-file

    This option is ignored, but accepted for compatibility with other Cyrus tools.
    
.. option:: format

    Specify one of the following: 
    
       **pretty** - print the build configuration in indented JSON format. This is the default.
       
       **dense**  - print the build configuration in dense JSON format.
       
       **flat**   - print the build configuration as flattened properties. Note that the print order is non-deterministic.    

