.. _manage-dav:

============
HTTP modules
============

About http module support
=========================

This assumes you already have the relevant modules enabled in your Cyrus
:ref:`installation <setup>`, either via packages, or through a
manual installation.

CalDAV, CardDAV and WebDAV all provide their functionality through an http
server. Cyrus HTTP is NOT a general purpose HTTP server (such as Apache httpd).
Its feature set is limited to:

* Calendaring (CalDAV)
    * Acts as a calendar and scheduling server by using IMAP mailboxes as calendar
      collections and :rfc:`5322` messages to store iCalendar data.
    * Allows non-CalDAV/remote calendar clients to query freebusy information of
      Cyrus CalDAV users via freebusy URLs.
    * Allows scheduling transactions between separate calendaring and
      scheduling systems via the iSchedule protocol (currently only
      used within a Cyrus Murder).
    * Acts as a Time Zone Distribution Service by serving iCalendar
      (VTIMEZONE) data to client systems.
* Contacts (CardDAV)
    * Acts as a contacts server by using IMAP mailboxes as addressbook
      collections and :rfc:`5322` messages to store vCard data.
* File Storage (WebDAV)
    * Acts as a remote storage server server by using IMAP mailboxes as
      collections and :rfc:`5322` message to store files.
* JMAP support
    * Allows synchronization of mail clients via the JSON Mail Access Protocol (JMAP).
* Other (RSS, static content)
    * Serves static content (such as the RSS feed list template and the
      CalDAV/CardDAV web GUIs).
    * Serves IMAP mailboxes as RSS feeds.

HTTPD Configuration
===================

General configuration
---------------------

The Cyrus httpd service is configured using options in :cyrusman:`imapd.conf(5)`.

.. sidebar:: httpmodules

   .. include:: /imap/reference/manpages/configs/imapd.conf.rst
       :start-after: startblob httpmodules
       :end-before: endblob httpmodules

The support for RSS, CalDAV, and CardDAV is divided into separate modules which
run as part of the Cyrus httpd service. Selection of which module(s) are enabled
is done by setting the ``httpmodules`` option. **By default, no modules
are enabled.**

Cyrus httpd also can serve static content, the location of which is set by the
``httpdocroot`` option. Any content contained in the specified directory (including
sub-directories) will be served as static content only. Cyrus httpd does NOT
have the ability to execute any server-side scripts.


Authentication
--------------

As with other Cyrus services, the Cyrus httpd service uses
:ref:`Cyrus SASL <cyrussasl:sasl-index>` to perform its authentication.

.. sidebar:: allowplaintext

    |change-default-config|

   .. include:: /imap/reference/manpages/configs/imapd.conf.rst
       :start-after: startblob allowplaintext
       :end-before: endblob allowplaintext

Similar to plaintext login commands supported by the other Cyrus services (IMAP
LOGIN, POP3 USER/PASS), the Cyrus httpd service determines whether to advertise
the HTTP Basic authentication scheme based on the ``allowplaintext`` option and
whether the client has connected over a TLS protected connection (HTTPS). BASIC
authentication does not depend on a Cyrus SASL plugin.

The advertisement of the other HTTP authentication schemes is controlled by the
:ref:`SASL mech_list option <cyrussasl:options>` option. For Cyrus httpd
the DIGEST-MD5, GSS-SPNEGO, NTLM, SCRAM-SHA-1, and SCRAM-SHA-256 values enable
support for the Digest, Negotiate (Kerberos only), NTLM, SCRAM-SHA-1, and
SCRAM-SHA-256 authentication schemes respectively, provided that the plugins
are installed on the server.

Module-specific information
===========================

.. toctree::
    :maxdepth: 2

    http/caldav
    http/carddav
    http/webdav
    http/jmap
    http/rss

For end users
=============

Some information must be passed on to your end users so that they know how to
configure their clients in order to access their data on Cyrus. The list below
needs to be customized to your specific hostnames.

* CalDAV
    * Many clients find calendars automatically if you provide the correct server, username and password.
    * Otherwise, use the direct URL: ``https://<servername>/dav/calendars/user/<userid>/<calendar>/``
* Freebusy
    * ``https://<servername>/freebusy/user/<userid>`` - considers all CalDAV collections of the user
    * ``https://<servername>/freebusy/user/<userid>/<collection-name>`` - considers a single CalDAV collection
    * Query parameters can be added to the URL per Section 4 of
      `Freebusy Read URL <http://www.calconnect.org/pubdocs/CD0903%20Freebusy%20Read%20URL.pdf>`_.
* CardDAV
    * Many clients find addressbooks automatically if you provide the correct server, username and password.
    * Otherwise, use the direct URL:``https://<servername>/dav/addressbooks/<userid>/<addressbook>``
    * The address book(s) are automatically filtered based on the username and password supplied.
* WebDAV
    * ``https://<servername>/dav/drive/user/<userid>``
* RSS
    * ``https://<servername>/rss/``
    * Serves up all mailboxes (read-only) that the authenticated user has access to.
