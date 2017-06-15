=========
Man pages
=========

(5) Configuration Files
=======================

.. toctree::
    :maxdepth: 1

    configs/cyrus.conf
    configs/imapd.conf
    configs/krb.equiv

(8) System Commands
===================

.. toctree::
    :maxdepth: 1

    systemcommands/arbitron
    systemcommands/backupd
    systemcommands/chk_cyrus
    systemcommands/ctl_backups
    systemcommands/ctl_conversationsdb
    systemcommands/ctl_cyrusdb
    systemcommands/ctl_deliver
    systemcommands/ctl_mboxlist
    systemcommands/ctl_zoneinfo
    systemcommands/cvt_cyrusdb
    systemcommands/cvt_xlist_specialuse
    systemcommands/cyr_backup
    systemcommands/cyr_buildinfo
    systemcommands/cyr_dbtool
    systemcommands/cyr_deny
    systemcommands/cyr_df
    systemcommands/cyr_expire
    systemcommands/cyr_info
    systemcommands/cyr_sequence
    systemcommands/cyr_synclog
    systemcommands/cyr_userseen
    systemcommands/cyr_virusscan
    systemcommands/cyradm
    systemcommands/cyrdump
    systemcommands/deliver
    systemcommands/fetchnews
    systemcommands/fud
    systemcommands/httpd
    systemcommands/idled
    systemcommands/imapd
    systemcommands/ipurge
    systemcommands/lmtpd
    systemcommands/lmtpproxyd
    systemcommands/masssievec
    systemcommands/master
    systemcommands/mbexamine
    systemcommands/mbpath
    systemcommands/mbtool
    systemcommands/mkimap
    systemcommands/mknewsgroups
    systemcommands/mupdate
    systemcommands/nntpd
    systemcommands/notifyd
    systemcommands/pop3d
    systemcommands/pop3proxyd
    systemcommands/ptdump
    systemcommands/ptexpire
    systemcommands/ptloader
    systemcommands/quota
    systemcommands/reconstruct
    systemcommands/restore
    systemcommands/rmnews
    systemcommands/sievec
    systemcommands/sieved
    systemcommands/smmapd
    systemcommands/squatter
    systemcommands/sync_client
    systemcommands/sync_reset
    systemcommands/sync_server
    systemcommands/timsieved
    systemcommands/tls_prune
    systemcommands/translatesieve
    systemcommands/unexpunge

(1) User Commands
=================

.. toctree::
    :maxdepth: 1
    :glob:

    usercommands/*

Work-in-Progress
================

For the following parts of the documentation, while they are a work-in-
progress, you may already have better documentation on your system, in
the form of actual man-pages.

.. toctree::
    :maxdepth: 1

    systemcommands/proxyd

.. These are all hidden because the files are possibly obsolete, or they
    don't match any active scripts/commands, or there's no info on what they
    do.

.. toctree::
    :maxdepth: 1
    :hidden:

    systemcommands/fixsearchpath.pl
    systemcommands/migrate-metadata
    systemcommands/mupdate-loadgen.pl
    systemcommands/rehash
    systemcommands/cvt_cyrusdb_all
    systemcommands/cyr_userseen
    systemcommands/dohash
    systemcommands/undohash
    systemcommands/upgradesieve
    systemcommands/template


..  systemcommands/template: this is just the template for new command files so it obeys man and html formatting.
.. translatesieve better version of convert-sieve (does this make convert-sieve obsolete?)]
