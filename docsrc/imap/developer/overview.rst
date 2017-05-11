=========================================
Overview of Cyrus development environment
=========================================

The pre-requisites
==================

While Cyrus itself can be run under many operating systems, we recommend the following operating systems for development, because the dependencies and libraries are known. If you get a development environment working under a different operating system, we'd love to :ref:`hear about it <support>`.
    * Debian / Ubuntu
    * Fedora / Redhat

The components
==============

Source
------

Cyrus IMAPd
    Can't do anything without this!

    Follow the :ref:`Cyrus IMAP installation guide <setup>`.

Cyrus SASL
    Used for providing user authentication to the mail server.

    When developing against Cyrus, however, we assume that Cyrus SASL is a third party pre-built component. There is a separate section on compiling from source if you're interested in :ref:`contributing to Cyrus SASL <sasldevinstallguide>`.

Testing tools
-------------

Cassandane
    System test suite for Cyrus IMAPd.

    The :ref:`Cyrus testing guide <developer-testing>` has instructions for :ref:`installing Cassandane <install_cassandane>`.

Caldav Tester
    Testing tool for CalDAV and CardDAV.

    Installation information: http://calendarserver.org/wiki/CalDAVTester

IMAPTest
    Compliance and stress test tool for IMAP servers.

    Installation information: http://www.imapwiki.org/ImapTest

Development hub
---------------

GitHub
    We use GitHub for our collaboration and change tracking.

    Check out our :ref:`development process <devprocess>` for a guide on how to contribute your changes to the community.
