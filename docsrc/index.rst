.. _imap-index:

===================
What is Cyrus IMAP?
===================

Cyrus IMAP is an email, contacts and calendar server. Cyrus is free and open source.


* This is the documentation for version |release| of Cyrus IMAP: **stable** branch.
* The latest development version |imap_latest_development_version| is at :cyrus-dev:`/`.


.. Update this when there is a changeover from stable to development.

Features
--------

* Speed
* Security
* Efficiency
* Search
* CardDAV and CalDAV support
* Robust data storage
* Replication
* Scalable for large installations
* Flexible filtering support through Sieve
* Supports antivirus and antispam toolkits
* Handles deliverability: SPF, DKIM, DMARC
* Extensive authentication options, through Cyrus SASL
* JMAP support
* Long list of supported standards

Read more in our full :ref:`list of features <imap-features>`.

Cyrus has been under active development since the year 1993 when the project was launched at Carnegie Mellon University. It's used in production
systems around the world, at universities and in private enterprise.

Need help? We have :ref:`active mailing lists <feedback-mailing-lists>`.

--------

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

--------

===================
What is Cyrus SASL?
===================
Simple Authentication and Security Layer (SASL_) is a specification that describes how authentication mechanisms can be plugged into an application protocol on the wire. Cyrus SASL is an implementation of SASL that makes it easy for application developers to integrate authentication mechanisms into their application in a generic way.

The latest stable version of Cyrus SASL is |sasl_current_stable_version|.

.. _SASL: https://en.wikipedia.org/wiki/Simple_Authentication_and_Security_Layer

.. toctree::
    :caption: Cyrus SASL

    Cyrus SASL <http://www.cyrusimap.org/sasl>
