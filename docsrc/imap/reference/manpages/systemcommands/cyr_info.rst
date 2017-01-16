.. cyrusman:: cyr_info(8)

.. _imap-reference-manpages-systemcommands-cyr_info:

==============
**cyr_info**
==============

General cyrus inspection tool

Synopsis
========

.. parsed-literal::

    **cyr_info** [ **-C** *config-file* ] [ **-M** *config-file* ] [ **-n** *servicename* ] *command*

Description
===========

**cyr_info** is a tool for getting information from Cyrus.  The intent
is to extend this tool with useful commands to make managing and
configuring Cyrus easier.

**cyr_info** |default-conf-text|

Options
=======

.. program:: cyr_info

.. option:: -C config-file

    |cli-dash-c-text|

.. option:: -M config-file

    Read service specifications from *config-file* (cyrus.conf format).

.. option:: -n servicename

    Read the configuration as if for the service named *name*.

Commands
========

*conf*

    Print only the configuration options which are not the same as
    default (regardless of whether you have specified them or not).

*conf-default*

    Print all default configuration options, ignoring those set locally.

*conf-all*

    Print ALL configuration options - including default options.  This
    command shows which options will be in effect at runtime.

*conf-lint*

    Print only configuration options which are NOT recognised.  This
    command should not print anything.  It uses cyrus.conf to find
    the names of configured services to avoid displaying any known
    configuration options for the named service.

*proc*

    Print all currently connected processes in the proc directory

Examples
========

.. parsed-literal::

    **cyr_info** *proc*

..

        List all the proc files and who they're logged in as.

.. only:: html

    ::

        1763345 imap imap.example.org [10.202.2.80] bettysue user.bettysue
        1796653 imap web1.example.org [10.202.2.211] bettysue user.bettysue.Drafts
        1796640 imap web2.example.org [10.202.2.212] johnsmith@johnsmith.net johnsmith.net!user.johnsmith
        1796663 imap web2.example.org [10.202.2.212] johnsmith@johnsmith.net johnsmith.net!user.johnsmith

.. parsed-literal::

    **cyr_info** *conf-lint*

..

        Lint the configuration for unrecognized settings.

.. only:: html

    ::

        duplicate_mailbox_mode: uniqueid
        archivepartition-default: /var/spool/cyrus/spool-archive
        rudolf_sync_host: 10.202.79.15
        prancer_sync_host: 10.206.51.80
        user_folder_limit: 5000

History
=======

|v3-new-command|

Files
=====

/etc/imapd.conf,
/etc/cyrus.conf

See Also
========
:cyrusman:`imapd.conf(5)`, :cyrusman:`cyrus.conf(5)`
