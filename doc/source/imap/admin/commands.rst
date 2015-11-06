===================================
Administrative Commands & Utilities
===================================

List of Configuration Files, Formats and Settings
=================================================

.. toctree::
    :maxdepth: 1

    configs/cyrus.conf
    configs/imapd.conf
    configs/krb.equiv

List of Command-line Utilities
==============================

.. toctree::
    :maxdepth: 1

    commands/arbitron
    commands/arbitronsort.pl    
    commands/chk_cyrus
    commands/ctl_cyrusdb
    commands/ctl_conversationsdb
    commands/ctl_deliver
    commands/ctl_mboxlist
    commands/ctl_zoneinfo
    commands/cvt_cyrusdb
    commands/cyradm
    commands/cyrdump    
    commands/cyrfetchnews
    commands/cyrus-master
    commands/cyr_dbtool
    commands/cyr_deny
    commands/cyr_df
    commands/cyr_expire
    commands/cyr_info
    commands/cyr_sequence    
    commands/cyr_synclog
    commands/deliver
    commands/fud
    commands/httpd
    commands/idled
    commands/imapd
    commands/imtest
    commands/installsieve
    commands/ipurge
    commands/lmtpd
    commands/lmtptest
    commands/masssievec    
    commands/master 
    commands/mbexamine
    commands/mbpath
    commands/mbtool
    commands/mkimap
    commands/mupdate
    commands/mupdatetest
    commands/nntpd
    commands/nntptest
    commands/notifyd
    commands/pop3d
    commands/pop3test
    commands/quota
    commands/reconstruct
    commands/rmnews
    commands/sievec
    commands/sieved    
    commands/sivtest
    commands/smmapd
    commands/smtptest
    commands/squatter
    commands/sync_client
    commands/sync_reset
    commands/sync_server
    commands/timsieved
    commands/tls_prune
    commands/unexpunge

Work-in-Progress
================

For the following parts of the documentation, while they are a work-in-
progress, you may already have better documentation on your system, in
the form of actual man-pages.

.. toctree::
    :maxdepth: 1

    commands/ptdump
    commands/ptexpire
    commands/ptloader

.. toctree::
    :maxdepth: 1
    :hidden:

    commands/compile_st.pl: ?

    commands/cyr_systemd_helper

    commands/fixsearchpath.pl
    commands/migrate-metadata: useful
    commands/mknewsgroups: useful
    commands/mupdate-loadgen.pl: ??
    commands/proxyd
    commands/rehash: useful

    commands/translatesieve:useful more better version of convert-sieve (does this make convert-sieve obsolete?)
    commands/convert-sieve.pl : probably bogus    
    
    commands/template: this is just the template for new command files so it obeys man and html formatting.
