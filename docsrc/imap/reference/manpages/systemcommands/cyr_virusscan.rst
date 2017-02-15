.. cyrusman:: cyr_virusscan(8)

.. _imap-reference-manpages-systemcommands-cyr_virusscan:

=================
**cyr_virusscan**
=================

Scan mailbox(es) or messages for viruses using configured virus scanner
or provided search criteria.

Synopsis
========

.. parsed-literal::

    **cyr_virusscan** [ **-C** *config-file* ] [ **-s** *imap-search-string* ] [ **-r** [ **-n**] ] [ *mboxpattern1* ... ]

Description
===========

**cyr_virusscan** is used to scan the specified IMAP mailbox(es) with
the configured virus scanner (currently only ClamAV is supported).  If
no mboxpattern is given, **cyr_virusscan** works on all mailboxes.

Alternately, with the **-s** option, rather than **scanning** mailboxes
for virus, the IMAP SEARCH string will be used as a specification of
messages which are *assumed* to be infected, and will be treated as such.
Useful for removing messages without a distinct signature, such as
Phish.

A table of infected messages will be output.  However, with the remove
flag, **-r**, infected messages will be removed.

With the notify flag, **-n**, notifications with message digest
information will be appended to the inbox of the mailbox owner.  This
flag is only operable in combination with **-r**.

**cyr_virusscan** is may be configured to run periodically by cron(8)
via crontab(5) or your preferred method (i.e. /etc/cron.hourly), or by
:cyrusman:`master(8)` via the EVENTS{} stanza in
:cyrusman:`cyrus.conf(5)`.
    
**cyr_virusscan** |default-conf-text|

Options
=======

.. program:: cyr_virusscan

.. option:: -C config-file

    |cli-dash-c-text|

   
.. option:: -n

    Notify mailbox owner of deleted messages via email.  This flag is
    only operable in combination with **-r**.

.. option:: -r

    Remove infected messages.
    
.. option:: -s imap-search-string

    Rather than scanning for viruses, messages matching the search
    criteria will be treated as infected.

Examples
========

.. parsed-literal::

    **cyr_virusscan**

..

        Scan all mailboxes, printing report on the screen.  Do not
        remove infected messages.

.. only:: html

    ::

        Using ClamAV virus scanner
        Loaded 5789330 virus signatures.

        Mailbox Name                            	   Msg UID	Status	Virus Name
        ----------------------------------------	----------	------	--------------------------------------------------
        user.betty                              	    185395	  READ	Heuristics.Phishing.Email.SpoofedDomain
        user.betty.Bank stuff                   	         9	  READ	Html.Phishing.Bank-1172
        user.betty.Bank stuff                   	        10	  READ	Html.Phishing.Bank-1172
        user.betty.Bank stuff                   	        11	  READ	Html.Phishing.Bank-1172

        Mailbox Name                            	   Msg UID	Status	Virus Name
        ----------------------------------------	----------	------	--------------------------------------------------
        user.bovik                                	     17426	  READ	Email.Trojan.Trojan-1051

.. parsed-literal::

    **cyr_virusscan** -r -n user/bovik

..

        Scan mailbox *user/bovik*, removing infected messages and append
        notifications to bovik's inbox.

.. only:: html

    ::

        Mailbox Name                            	   Msg UID	Status	Virus Name
        ----------------------------------------	----------	------	--------------------------------------------------
        user.bovik                                	   17426	  READ	Email.Trojan.Trojan-1051

.. only:: html

        A message like this would end up in bovik's inbox:

    ::

        The following message was deleted from mailbox 'Inbox.bovik'
        because it was infected with virus 'Email.Trojan.Trojan-1051'

            Message-ID: <201308131519.r7DFJM9K083763@tselina.kiev.ua>
            Date: Tue, 13 Aug 2013 18:19:22 +0300 (EEST)
            From: ("FEDEX Thomas Cooper" NIL "thomas_cooper94" "themovieposterpage.com")
            Subject: Problem with the delivery of parcel
            IMAP UID: 17426

..

.. parsed-literal::

        **cyr_virusscan** -r -n -s 'SUBJECT "Fedex"' user/bovik

..

        Search mailbox user/bovik for messages which have Fedex in the
        subject line, removing them all, and appending notifications to
        Bovik's inbox.
        
.. only:: html

    ::

        Mailbox Name                            	   Msg UID	Status	Virus Name
        ----------------------------------------	----------	------	--------------------------------------------------
        user.bovik                                	   17185	  READ	Cyrus Administrator Targeted Removal (Phish, etc.)
        user.bovik                                	   17203	  READ	Cyrus Administrator Targeted Removal (Phish, etc.)
        user.bovik                                	   17338	  READ	Cyrus Administrator Targeted Removal (Phish, etc.)
        user.bovik                                	   17373	  READ	Cyrus Administrator Targeted Removal (Phish, etc.)
        user.bovik                                	   19238	  READ	Cyrus Administrator Targeted Removal (Phish, etc.)
        user.bovik                                	   19268	  READ	Cyrus Administrator Targeted Removal (Phish, etc.)

..

History
=======

Virus scan support was first introduced in Cyrus version 3.0.

Files
=====

/etc/imapd.conf

See Also
========

:cyrusman:`imapd.conf(5)`, :cyrusman:`master(8)`
