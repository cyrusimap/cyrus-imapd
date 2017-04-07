================
Quickstart Guide
================


.. toctree::

    imap/quickstart/introduction

Coming Soon
-----------

Quick install
#############

A quick guide to getting a basic installation of Cyrus up and running in 5 minutes.

The first place to start with a new installation of Cyrus IMAP is with
your OS distribution of choice and their packaging, where available.  If
there is no Cyrus IMAP 3.0 package available yet from your distro, 
download the `latest stable package`_ : version |imap_current_stable_version|.

.. _latest stable package: ftp://ftp.cyrusimap.org/cyrus-imapd/

We only provide limited options for reference packages, so use a
supported distribution.

Install the package as provided for in your distro.  Please see guides
here:

The packaging should pull along all necessary support libraries, etc..

Feature overview
################

The features (configuration options) supported in our reference
packages are:

Cyrus Server configured components

    * event notification: yes
    * gssapi:             no
    * autocreate:         yes
    * idled:              yes
    * httpd:              yes
    * kerberos V4:        no
    * murder:             yes
    * nntpd:              yes
    * replication:        yes
    * sieve:              yes
    * calalarmd:          no
    * jmap:               no
    * objectstore:        no
    * backup:             yes

External dependencies:

    * ldap:               yes
    * openssl:            yes
    * zlib:               yes
    * pcre:               no
    * clamav:             yes
    * caringo:            no
    * openio:             no
    * nghttp2:            no
    * brotli:             no
    * xml2:               yes
    * ical:               yes
    * icu4c:              yes
    * shapelib:           no

Database support:

    * mysql:              no
    * postgresql:         no
    * sqlite:             yes
    * lmdb:               no

Search engine:

    * squat:              yes
    * sphinx:             no
    * xapian:             yes
    * xapian_flavor:      vanilla

Installation directories:
    * prefix:             /usr
    * sysconfdir:         /etc
