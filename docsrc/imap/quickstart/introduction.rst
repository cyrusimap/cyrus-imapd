.. _imap:

==========================
Introduction to Cyrus IMAP
==========================

Cyrus IMAP is a `Carnegie Mellon University`_ (|CMU|) software
development project for a highly scalable enterprise mail system.

Cyrus IMAP is one of two primary software development projects
undertaken by the Cyrus project -- the other one being :ref:`cyrussasl:sasl-index`.

The project as a whole started in 1994 and has its roots in replacing
the Andrew Mail System (|AMS|) that |CMU| had been using, and has
replaced |AMS| between 1998 and 2002.

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

    *   `Wikipedia on IMAP`_.
    *   `Wikipedia on POP`_.

For a reference on supported features in the IMAP protocol, please check
out :ref:`imap-rfc-support`.

.. _Carnegie Mellon University: http://www.cmu.edu
.. _Wikipedia on IMAP: https://en.wikipedia.org/wiki/Internet_Message_Access_Protocol
.. _Wikipedia on POP: https://en.wikipedia.org/wiki/Post_Office_Protocol#Comparison_with_IMAP
