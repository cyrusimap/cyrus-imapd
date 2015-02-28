==========================
Introduction to Cyrus IMAP
==========================

Cyrus IMAP is a `Carnegie Mellon University`_ (CMU) software
development project for a highly scalable enterprise mail system.

The project started in 1994 and has its roots in replacing the Andrew
Mail System (AMS) that CMU had been using, and has replaced AMS
between 1998 and 2002.

The project name, Cyrus, comes from the inventor of the first modern
"packet-switching"-based mail system, the forerunner of every major
communication system we have today.

Cyrus the Great (c. 585-529 BC) founded the ancient Persian Empire,
and then needed superb messaging in order to run it. It is his famous
system of royal roads and postal couriers of which Herodotus writes, a
century later:

.. epigraph:: 

    Nothing mortal travels so fast as these Persian messengers. The
    entire plan is a Persian invention; and this is the method of it.

    Along the whole line of road there are men stationed with horses,
    in number equal to the number of days which the journey takes,
    allowing a man and horse to each day; and these men will not be
    hindered from accomplishing at their best speed the distance which
    they have to go, either by snow, or rain, or heat, or by the
    darkness of night. The first rider delivers his despatch to the
    second and the second passes it to the third; and so it is borne
    from hand to hand along the whole line...

    -- Herodotus

What is IMAP?
=============

The Internet Message Access Protocol (IMAP) is used to access a remote
message store using a client application, and is the de-facto standard
protocol for mailstore access.

Contrary to the Post Office Protocol (POP), IMAP by default maintains a
copy of the message on the server -- until it is explicitly deleted.

Cyrus IMAP supports both POP3 and IMAP4 access to the mail store.

.. seealso::

    *   Wikipedia on `IMAP`_.
    *   Wikipedia on `POP`_.

..
    Why would I (not) use Cyrus IMAP?
    =================================

    Cyrus IMAP is intended to run on sealed systems, meaning that normal
    users cannot login to the system. This eliminates the requirement for
    all mail users to hold POSIX account information attributes.

    The mail spool directory or directories are held privately by the
    Cyrus IMAP system, and can be accessed by users through IMAP, POP or
    KPOP protocols.

    The design concept vastly increases efficiency, scalability and
    security, and makes it easier to configure, maintain, troubleshoot and
    administer.

    A downside of running a sealed system is that the use of disk space by
    mailboxes does not count towards a user's filesystem quota. One of the
    reasons Dovecot is very popular with hosting providers is that it
    allows the space used by mail to count towards an account's filesystem
    quota.

.. _Carnegie Mellon University: http://www.cmu.edu
.. _IMAP: http://en.wikipedia.org/wiki/Internet_Message_Access_Protocol
.. _POP: http://en.wikipedia.org/wiki/Post_Office_Protocol#Comparison_with_IMAP
