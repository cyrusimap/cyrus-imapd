.. _cyrus_roadmap:

=============
Cyrus Roadmap
=============

This is a very general, high-level view of where the Cyrus project is heading in the future, and the amount of code support you may expect to receive if you're running an older version of Cyrus.

This is under your control! If there's a feature you'd like to see added, or testing/documentation you'd like to see improved, we'd love to have your involvement to help make it happen. We're here to support you. :ref:`Contact us <support>` and take a look at the :ref:`Contributor guides <contribute>`.

High Level Roadmap
==================

Future
------

* JMAP support
* Improved backup support
* Multi-master replication

3.0.x
-----

* Better calendaring support through jmap
* Cross-folder conversations
* Support for fuzzy Xapian search.
* CardDAV support
* Better backup support - initial release
* Basic object storage
* Archive partition support

2.5.x
-----

* Support ANNOTATE (`RFC 5257`_)
* Support some of ESORT/ESEARCH (`RFC 5256`_)
* Support LIST-EXT STATUS (`RFC 5819`_)
* Support SORT=DISPLAY (`RFC 5957`_)
* Support SpecialUse (`RFC 6154`_)
* Autocreate/autosieve (needs to be -enabled in config)
* Complete compliance with all tests from ImapTest_ (integrated with Cassandane)
* cyr_info utility - configuration 'lint' and dumping tool.
* MESSAGE quota support (`RFC 2087`_)
* Some CalDAV calendaring support.
* Some CardDAV contact support.

.. _RFC 5257: http://tools.ietf.org/html/rfc5257
.. _RFC 5256: http://tools.ietf.org/html/rfc5256
.. _RFC 5819: http://tools.ietf.org/html/rfc5819
.. _RFC 5957: http://tools.ietf.org/html/rfc5959
.. _RFC 6154: http://tools.ietf.org/html/rfc6154
.. _RFC 2087: http://tools.ietf.org/html/rfc2087
.. _ImapTest: http://www.imapwiki.org/ImapTest

2.4.x
-----

* security backports only

2.3 and earlier
---------------

* unsupported

..
	This is woefully out of date.
