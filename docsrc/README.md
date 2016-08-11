Welcome
=======

Cyrus IMAPd docs live here.

A packaged Cyrus release has the docs pre-built in ../doc/build/html and ../doc/build/man

But if you'd like to build your own, read on.

Building the docs
=============

If you want to build from source, you'll need sphinx and its dependencies. See: http://www.cyrusimap.org/imap/developer/documentation.html for the latest.

Pre-requisites
------------------

For basic reStructured Text operations, we are using Sphinx version 1.3.6:

- python-sphinx
- python-sphinxcontrib-programoutput
- python-sphinxcontrib.actdiag
- python-sphinxcontrib.blockdiag
- python-sphinxcontrib.nwdiag
- python-sphinxcontrib.phpdomain
- python-sphinxcontrib.seqdiag
- python-sphinxcontrib.spelling

You will also need the perl package, which is used to build some docs from their Perl source:

- Pod::POM::View::Restructured

Building
-----------

``make`` shows you the targets.

These all do what you'd expect, output into ./build.

- ``make clean``
- ``make man``
- ``make html``


Contact us
==========

Whether you have a success story to share, or a bug to file, or a 
request for help or a feature to add or some documentation to contribute 
or you'd just like to say hi, we want to hear from you! See 
http://www.cyrusimap.org/feedback.html for various ways you can get hold 
of us. 


