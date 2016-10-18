.. _cyrus_roadmap:

=============
Cyrus Roadmap
=============

This is a very general, high-level view of where the Cyrus project is heading in the future, and the amount of code support you may expect to receive if you're running an older version of Cyrus.

High Level Roadmap
==================

2.6 (Future)
------------

* Possibly calendaring support
* Possibly cross-folder conversations
* Multi-master replication
* More RFCs
* Better backup support

2.5
----

* Support ANNOTATE (`RFC 5257`_)
* Support ESORT/ESEARCH (`RFC 5256`_)
* Support LIST-EXT STATUS (`RFC 5819`_)
* Support SORT=DISPLAY (`RFC 5957`_)
* Support SpecialUse (`RFC 6154`_)
* Autocreate/autosieve
* Complete compliance with all tests from ImapTest_
* cyr_info utility - configuration 'lint' and dumping tool.
* Automatic BDB upgrades.
* MESSAGE quota support (`RFC 2087`_)

.. _RFC 5257: http://tools.ietf.org/html/rfc5257
.. _RFC 5256: http://tools.ietf.org/html/rfc5256
.. _RFC 5819: http://tools.ietf.org/html/rfc5819
.. _RFC 5957: http://tools.ietf.org/html/rfc5959
.. _RFC 6154: http://tools.ietf.org/html/rfc6154
.. _RFC 2087: http://tools.ietf.org/html/rfc2087
.. _ImapTest: http://www.imapwiki.org/ImapTest

2.4.x
-----

* bugfixes only

2.2.x and 2.3.x
---------------

* security backports only

pre 2.2
-------

* unsupported

.. 
	Detailed Roadmap - This used to be an extract out of bugzilla, but we're not using that any more. And maniphest/phabricator doesn't seem to have a field for what version an item is targeted to.
	
