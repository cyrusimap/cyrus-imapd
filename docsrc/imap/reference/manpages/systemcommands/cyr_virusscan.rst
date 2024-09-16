.. cyrusman:: cyr_virusscan(8)

.. highlight:: none

.. author: Nic Bernstein (Onlight)

.. _imap-reference-manpages-systemcommands-cyr_virusscan:

=================
**cyr_virusscan**
=================

Scan for viruses using configured virus scanner or manage infected messages using search criteria.

Synopsis
========

.. parsed-literal::

    **cyr_virusscan** [ **-C** *config-file* ] [ **-s** *imap-search-string* ] [ **-r** [ **-n**] ] [**-v**] [ *mboxpattern1* ... ]

Description
===========

**cyr_virusscan** can be used to invoke an external virus scanner (currently
only `ClamAV <https://www.clamav.net/documents/installing-clamav>`_ is
supported) to scan specified IMAP mailboxes. If no mboxpattern is given,
**cyr_virusscan** works on all mailboxes.

Alternately, with the **-s** option, the IMAP SEARCH string will be used as a
specification of messages which are *assumed* to be infected, and will be
treated as such.  The virus scanner is not invoked. Useful for removing messages
without a distinct signature, such as Phish.

A table of infected messages will be output.

To remove infected messages, use the **-r** flag. Infected messages will be expunged
from the user's mailbox.

With the notify flag, **-n**, notifications will be appended to the inbox of
the mailbox owner, containing message digest information for the affected mail.
This flag only works in combination with **-r**.  The notification message
can by customised by template, for details see `Notifications`_ below.

**cyr_virusscan** can be configured to run periodically by cron(8)
via crontab(5) or your preferred method (i.e. /etc/cron.hourly), or by
:cyrusman:`master(8)` via the EVENTS{} section in
:cyrusman:`cyrus.conf(5)`.

**cyr_virusscan** |default-conf-text|

Note that Cyrus does not ship with any virus scanners: you need to install
one separately to make use of it with Cyrus.

Options
=======

.. program:: cyr_virusscan

.. option:: -C config-file

    |cli-dash-c-text|


.. option:: -n, --notify

    Notify mailbox owner of deleted messages via email.  This flag is
    only operable in combination with **-r**.

.. option:: -r, --remove-infected

    Remove infected messages.

.. option:: -s imap-search-string, --search=imap-search-string

    Rather than scanning for viruses, messages matching the search
    criteria will be treated as infected.

.. option:: -v, --verbose

    Produce more verbose output

Notifications
=============

When the **-n** flag is provided, notifications are sent to mailbox owners
when infected messages are removed.  One notification is sent per owner,
containing a digest of each message that was deleted from any of their
mailboxes.

The default notification subject is "Automatically deleted mail", which
can be overridden by setting ``virusscan_notification_subject`` in
:cyrusman:`imapd.conf(5)` to a UTF-8 value.

Each infected message will be described according to the following template::

	The following message was deleted from mailbox '%MAILBOX%'
	because it was infected with virus '%VIRUS%'

	    Message-ID: %MSG_ID%
	    Date: %MSG_DATE%
	    From: %MSG_FROM%
	    Subject: %MSG_SUBJECT%
	    IMAP UID: %MSG_UID%

To use a custom template, create a UTF-8 file containing your desired text
and using the same %-delimited substitutions as above, and set the
``virusscan_notification_template`` option in :cyrusman:`imapd.conf(5)` to
its path.

The notification message will be properly MIME-encoded at delivery. Do not
pre-encode the template file or the subject!

When **cyr_virusscan** starts up, if notifications have been requested (with
the **-n** flag), a basic sanity check of the template will be performed
prior to initialising the antivirus engine.  If it appears that the
resultant notifications would be undeliverable for some reason,
**cyr_virusscan** will exit immediately with an error, rather than risk
deleting messages without notifying.

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
        notifications to Bovik's inbox.

.. only:: html

    ::

        Mailbox Name                            	   Msg UID	Status	Virus Name
        ----------------------------------------	----------	------	--------------------------------------------------
        user.bovik                                	   17426	  READ	Email.Trojan.Trojan-1051

.. only:: html

        A message like this would end up in bovik's inbox:

    ::

        The following message was deleted from mailbox 'INBOX'
        because it was infected with virus 'Email.Trojan.Trojan-1051'

            Message-ID: <201308131519.r7DFJM9K083763@tselina.kiev.ua>
            Date: Tue, 13 Aug 2013 18:19:22 +0300 (EEST)
            From: "FEDEX Thomas Cooper" <thomas_cooper94@themovieposterpage.com>
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

:cyrusman:`imapd.conf(5)`, :cyrusman:`master(8)`, `ClamAV <https://www.clamav.net/documents/installing-clamav>`_
