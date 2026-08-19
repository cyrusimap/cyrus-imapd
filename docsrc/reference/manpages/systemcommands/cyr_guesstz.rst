.. cyrusman:: cyr_guesstz(8)

.. _imap-reference-manpages-systemcommands-**cyr_guesstz**:

===============
**cyr_guesstz**
===============

build and query the timezone guessing database

Synopsis
========

.. parsed-literal::

    **cyr_guesstz** **-z** *zoneinfo* [ **-r** *timerange* ] *dbfile*

    **cyr_guesstz** **-p** [ **-r** *timerange* ] *dbfile*

    **cyr_guesstz** [ **-r** *timerange* ] *dbfile*

Description
===========

**cyr_guesstz** builds and queries the database that Cyrus uses to recognise
IANA timezone names in VTIMEZONE components which do have a non-IANA timezone
identifier.

Calendar clients sometimes send events with a made-up ``TZID`` such as
``Custom`` or ``GMT+0100 (Mitteleuropäische Zeit)``, along with the observance
rules that describe it.  JMAP CalendarEvent objects need an IANA name, so Cyrus
compares those rules against every timezone in this database and reports the
name whose observance onsets and UTC offsets match.

**make install** builds the database as
:imapdconf:`zoneinfo_dir`/**guesstz.db** from the time zone data it installs,
so most installations never need to run this command.  Run it by hand after
updating :imapdconf:`zoneinfo_dir` yourself -- an out-of-date database is not
an error, it just makes Cyrus fail to recognise recently changed timezones.

Two timezones are considered equal when their observances match over a time
range, so the database records a range rather than the whole of history.  The
range used to build a database is also the widest range that can be queried
against it.

Unlike most Cyrus commands, **cyr_guesstz** does not read
:cyrusman:`imapd.conf(5)`; name the database file explicitly.

Options
=======

.. program:: **cyr_guesstz**

.. option:: -z zoneinfo, --zoneinfo=zoneinfo

    Create the database from the VTIMEZONEs in the *zoneinfo* directory,
    which is searched recursively.  Files that do not parse as iCalendar are
    reported and skipped.  The IANA version is read from the **version** file
    in that directory, and recorded as "unknown" if there is none.

.. option:: -p, --print

    Print the database as JSON on standard output.

.. option:: -r timerange, --timerange=timerange

    The time range over which to expand observances, as two UTC date-times
    separated by a solidus, each formatted as defined by "FORM #2" in
    RFC 5545, Section 3.3.5.  The start time is part of the range and the
    end time is not, so an observance onset at exactly the end time is not
    expanded.

    The default range is ``20000101T000000Z/20640101T000000Z``: from the
    zero hour of January 1, 2000 up to, but not including, the zero hour of
    January 1, 2064.

Examples
========

.. parsed-literal::

    **cyr_guesstz -z /usr/share/cyrus-imapd/zoneinfo guesstz.db**

..

        Build a database from an installed zoneinfo directory.

.. parsed-literal::

    **cyr_guesstz guesstz.db < event.ics**

..

        Print the IANA name of each VTIMEZONE read from standard input, or
        ``unknown`` for those that match nothing.

.. parsed-literal::

    **cyr_guesstz -p guesstz.db | less**

..

        Inspect the contents of a database.

Files
=====

<zoneinfo_dir>/guesstz.db

See Also
========

:cyrusman:`ctl_zoneinfo(8)`, :cyrusman:`imapd.conf(5)`, :manpage:`httpd(8)`
