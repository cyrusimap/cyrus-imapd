.. _architecture:

==================================
System Architecture
==================================

High Level Architecture
=======================

A birds-eye view of Cyrus.

.. image:: images/architecture.jpg
    :height: 400 px
    :width: 636 px
    :alt: High level architecture diagram.
    :align: center

Mail is delivered over smtp to the MTA_ (Message/Mail Transfer Agent). This then is delivered to **Cyrus imapd** over lmtp_ (Local Mail Transfer Protocol). 

Cyrus processes the inbound message and makes it available to the user over POP3, IMAP or even NNTP. Cyrus does not provide outbound SMTP services: these are hooked back into the MTA.

Cyrus usually uses **saslauthd** (Cyrus SASL) to provide authentication services. It is not the only way to provide authentication, but it is the usual option.

Cyrus stores the mailspool, indexes and search data on disk. While these are inherently files, their structure and function is database-centric and should be treated as such. *(Do not attempt to manually edit these files. That way lies madness.)* Cyrus itself provides no inherent backup capacity: this must be configured externally using tools best suited for your environment.

For administrative actions on your server - such as creating users, editing mailbox details, etc - use **cyradm**. This is a command, not a daemon, and it communicates with cyrus imapd via the IMAP protocol, and authenticating as an admin user.

For security between the user and cyrus, usually SSL is applied.

.. todo:
    - undecided on whether to include idled in here. At the moment I've left it out.
    
.. _MTA: https://en.wikipedia.org/wiki/Message_transfer_agent
.. _lmtp: https://en.wikipedia.org/wiki/Local_Mail_Transfer_Protocol
.. _nginx: http://nginx.org/en/
