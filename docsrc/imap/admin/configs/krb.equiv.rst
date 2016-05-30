.. cyrusman:: krb.equiv(5)

.. _imap-admin-configs-krb.equiv:

=============
**krb.equiv**
=============

Kerberos equivalences

Description
===========

**krb.equiv** contains zero or more lines, each of which describes a
mapping of a kerberos principal (*userid@host*) to a local user
(*userid* or alias). Each line of the file consists of two fields,
separated by at least one whitespace character; other blanks are
ignored.  The first field is the kerberos principal name to remap, and
the second is the name of the corresponding local user.

Examples
========

Sample file contents:

    ::

        tyq4@ANDY.CMU.EDU tyq4
        tyq4@DEANNA.ORG tyq4
        ty347@ECE.CMU.EDU tyq4
        jj12@ANDY.CMU.EDU tick
        tick@DEANNA.ORG tick
        jy9o@ANDY.CMU.EDU jyager
        jyager@CS.CMU.EDU jyager

Files
=====

/etc/imapd.conf,
<configdirectory>/krb.equiv

See Also
========

:cyrusman:`imapd.conf(5)`
