===========
Cyrus IMAP
===========

Welcome to Cyrus IMAP and SASL.

--------

What is Cyrus IMAP?
===================

Cyrus IMAP is an email, contacts and calendar server.

This documentation is for version |version|. The latest stable version of Cyrus IMAP is |imap_current_stable_version|. Looking for other
:ref:`versions <imap-release-notes>`?

Features
--------

This is the highlight reel of Cyrus's full list of features_.

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

.. _features: imap/features.html

.. toctree::
    :maxdepth: 1
    :caption: Welcome to Cyrus
    :glob:

    imap/introduction
    imap/features
    Support <feedback>
    About <overview/about_cyrus>

.. toctree::
    :maxdepth: 1
    :caption: Administrators

    imap/installation
    imap/deployment
    imap/admin
    imap/faq
    imap/release-notes/index

.. toctree::
    :maxdepth: 1
    :caption: Developers

    Contribute <contribute>
    imap/developer


.. toctree::
    :hidden:

    admin
    imap/index
    preface
    styles
    glossary

..  note to documentation contributors:

    The files included in the release notes glob are symbolic links to actual files deeper
    in the hierarchy of directories, so that the next version
    of the release notes can be worked on without getting in the way
    of the current release notes



--------

What is Cyrus SASL?
===================
Simple Authentication and Security Layer (SASL_) is a specification that describes how authentication mechanisms can be plugged into an application protocol on the wire. Cyrus SASL is an implementation of SASL that makes it easy for application developers to integrate authentication mechanisms into their application in a generic way.

The latest stable version of Cyrus SASL is |sasl_current_stable_version|.

Features
--------
Cyrus SASL provides a number of authentication plugins out of the box.

    Berkeley DB, GDBM, or NDBM (sasldb), PAM, MySQL, PostgreSQL, SQLite, LDAP, Active Directory(LDAP), DCE, Kerberos 4 and 5, proxied IMAP auth, getpwent, shadow, SIA, Courier Authdaemon, httpform, APOP and SASL mechanisms: ANONYMOUS, CRAM-MD5, DIGEST-MD5, EXTERNAL, GSSAPI, LOGIN, NTLM, OTP, PASSDSS, PLAIN, SR

Cyrus IMAP uses Cyrus SASL to provide authentication support to the mail server, however it is just one project using Cyrus SASL.

.. _SASL: https://en.wikipedia.org/wiki/Simple_Authentication_and_Security_Layer


.. toctree::
    :maxdepth: 1
    :caption: Cyrus SASL

    SASL Getting Started <sasl/getting_started>
    sasl/auxiliary_properties
    sasl/authentication_mechanisms
    sasl/pwcheck
    sasl/faq

.. toctree::
    :hidden:

    imap/rfc-support
    sasl/index

--------

How can we help you?
====================

:ref:`Administrators <imap-admin>`, looking to install and maintain Cyrus.

:ref:`Contributors <imap-developer>`, looking to add to Cyrus. (We include testers and documenters too!)
