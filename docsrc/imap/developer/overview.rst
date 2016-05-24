=========================================
Overview of Cyrus development environment
=========================================

The pre-requisites
==================

While Cyrus itself can be run under many operating systems, we recommend the following operating systems for development, because the depencies and libraries are known. If you get a development environment working under a different operating system, we'd love to :ref:`hear about it <feedback>`.
    * Debian / Ubuntu
    * Fedora / Redhat
    
The components
==============

Source
------

Cyrus IMAPd
    Can't do anything without this!

    Follow the :ref:`Cyrus IMAP installation guide <imapinstallguide>`.
    
Cyrus SASL
    Used for providing user authentication to the mail server.
    
    When developing against Cyrus, however, we assume that Cyrus SASL is a third party pre-built component. There is a separate section on compiling from source if you're interested in :ref:`contributing to Cyrus SASL <sasldevinstallguide>`.
 
Testing tools
-------------

Cassandane
    System test suite for Cyrus IMAPd.
    
    The :ref:`Cyrus IMAP installation guide <imapinstallguide>` has instructions for :ref:`installing Cassandane <imapinstallguide_cassandane>`.
    
Caldav Tester
    Testing tool for CalDAV and CardDAV.
    
    Installation information: http://calendarserver.org/wiki/CalDAVTester
    
IMAPTest
    Compliance and stress test tool for IMAP servers.
    
    Installation information: http://www.imapwiki.org/ImapTest
    
Development hub
---------------    

Phabricator
    We use Phabricator_ for our collaboration and change tracking. Diffusion provides repository browsing, Differential provides code review, Maniphest provides bug tracking. Arcanist_ provides a command-line interface to Phabricator.
    
    Check out our :ref:`development process <devprocess>` for a guide on how to contribute your changes to the community.


.. _Arcanist: https://secure.phabricator.com/book/phabricator/article/arcanist/
.. _Phabricator: https://git.cyrus.foundation
