.. _imap-index:

==========
Cyrus IMAP
==========

Welcome to Cyrus IMAP and SASL.

--------

What is Cyrus IMAP?
===================

Cyrus IMAP is an email, contacts and calendar server.

This is the documentation for the **development** version |imap_latest_development_version| of Cyrus IMAP.

Looking for the latest stable version of Cyrus IMAP? Documentation at :cyrus-stable:`/` for v|imap_current_stable_version|.

.. Update this when there is a changeover from stable to development.

Features
--------

This is the highlight reel of Cyrus's full list of :ref:`features <imap-features>`.

* **Security**: Cyrus runs on sealed servers, where normal users can't log in. Users access mail through IMAP/POP or KPOP.
* **Performance and scalability**: The mail spool uses a filesystem layout.
* **Filtering**: Server-side mail filtering via Sieve.
* **Efficiency**, ease of administration: The private mailbox database design gives Cyrus considerable advantages. Multiple concurrent read/write connections to the same mailbox are permitted. The server supports access control lists on mailboxes and storage quotas on mailbox hierarchies.
* **Beyond Email**: Support for CalDAV and CardDAV provides an integrated calendaring and email solution.
* **Scalability**: Cyrus Murder provides horizontal scalability: distributing the load across a pool of servers, without limiting to a particular subset of the IMAP namespace.
* **Authentication**: Supports X.509 PKI auth via STARTTLS and EXTERNAL. Plus all the Cyrus SASL options.

.. todo::
    Not sure how many of these are ok?
    * **Antispam**: ?? DNSBL	SURBL	Spamtraps	Greylisting	SPF	DKIM	DMARC	Tarpit	Bayesian filters	Regular expressions	Embedded Antivirus	Embedded Antispam

.. toctree::
    :maxdepth: 3
    :caption: Cyrus IMAP

    download
    quickstart
    overview
    setup
    operations
    developers
    support

..

    OLD INDEX

    quickstart
    download
    concepts
    reference
    developers
    support

--------

What is Cyrus SASL?
===================
Simple Authentication and Security Layer (SASL_) is a specification that describes how authentication mechanisms can be plugged into an application protocol on the wire. Cyrus SASL is an implementation of SASL that makes it easy for application developers to integrate authentication mechanisms into their application in a generic way.

The latest stable version of Cyrus SASL is |sasl_current_stable_version|.

Read more about :ref:`Cyrus SASL <cyrussasl:sasl-index>`.

.. _SASL: https://en.wikipedia.org/wiki/Simple_Authentication_and_Security_Layer

.. toctree::
    :caption: Cyrus SASL

    Cyrus SASL <http://www.cyrusimap.org/sasl>

--------

How can we help you?
====================

:ref:`Administrators <imap-admin>`, looking to install and maintain Cyrus.

:ref:`Contributors <imap-developer>`, looking to add to Cyrus. (We include testers and documenters too!)
