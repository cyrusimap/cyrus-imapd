.. _cyrus_roadmap:

=============
Cyrus Roadmap
=============

This is a very general, high-level view of where the Cyrus project is heading
in the future, and the amount of code support you may expect to receive if
you're running an older version of Cyrus.

This is under your control! If there's a feature you'd like to see added, or
testing/documentation you'd like to see improved, we'd love to have your
involvement to help make it happen. We're here to support you.
:ref:`Contact us <support>` and take a look at the
:ref:`Contributor guides <contribute>`.

High Level Roadmap
==================

Future
------

* JMAP support (Contacts, calendars and emails)
* Improved CalDAV and CardDAV support
* Improved backup support
* Multi-master replication

3.0.x
-----

* Cross-folder conversations
* Support for fuzzy Xapian search.
* CalDAV and CardDAV support
* Better backup support - initial release
* Basic object storage
* Archive partition support

2.5.x
-----

* Support ANNOTATE (:rfc:`5257`)
* Support some of ESORT/ESEARCH (:rfc:`5256`)
* Support LIST-EXT STATUS (:rfc:`5819`)
* Support SORT=DISPLAY (:rfc:`5957`)
* Support SpecialUse (:rfc:`6154`)
* Autocreate/autosieve (needs to be -enabled in config)
* Complete compliance with all tests from ImapTest_ (integrated with Cassandane)
* cyr_info utility - configuration 'lint' and dumping tool.
* MESSAGE quota support (:rfc:`2087`)
* Some CalDAV calendaring support.
* Some CardDAV contact support.

.. _ImapTest: http://www.imapwiki.org/ImapTest

2.4.x
-----

* security backports only

2.3 and earlier
---------------

* unsupported

..
	This is woefully out of date.
