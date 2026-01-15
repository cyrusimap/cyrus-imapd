.. cyrusman:: ctl_zoneinfo(8)

.. author: Nic Bernstein (Onlight)

.. _imap-reference-manpages-systemcommands-**ctl_zoneinfo**:

================
**ctl_zoneinfo**
================

perform operations on the zoneinfo database

Synopsis
========

.. parsed-literal::

    **ctl_zoneinfo** [ **-C** *config-file* ] [ **-v** ] **-r** *version-string*

    **ctl_zoneinfo** [ **-C** *config-file* ] [ **-v** ] **-w** *file*

Description
===========

**ctl_zoneinfo** is used to perform various administrative operations on
the zoneinfo database.

**ctl_zoneinfo** |default-conf-text|

Options
=======

.. program:: **ctl_zoneinfo**

.. option:: -C config-file

    |cli-dash-c-text|

.. option:: -v, --verbose

    Enable verbose output.

.. option:: -r version-string, --rebuild=version-string

    Rebuild the zoneinfo database based on the directory structure of
    *configdirectory*/**zoneinfo**.  The database to be rebuilt will be
    in the default location of *configdirectory*/**zoneinfo.db** unless
    otherwise specified by the *zoneinfo_db_path* option in
    :cyrusman:`imapd.conf(5)`.  The *version-string* should describe the
    source of the timezone data (e.g. "Olson:2020a") and will be used
    by the *tzdist* module of :manpage:`httpd(8)`.  The *version-string*
    must contain a colon between the description and the version.

.. option:: -w file, --windows-zone-xml=file

    Reads Windows Zone XML file.

Examples
========

[NB: Examples needed]

History
=======

This command was introduced in version 2.5

Files
=====

/etc/imapd.conf,
<configdirectory>/zoneinfo.db

See Also
========

:cyrusman:`imapd.conf(5)`, :manpage:`httpd(8)`, :cyrusman:`master(8)`
