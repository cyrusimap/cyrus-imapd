<sup>master: </sup>[![Build Status:master](https://api.travis-ci.com/cyrusimap/cyrus-imapd.svg?branch=master)](https://travis-ci.com/cyrusimap/cyrus-imapd)
<sup> stable(3.6): </sup>[![Build Status:3.6](https://api.travis-ci.com/cyrusimap/cyrus-imapd.svg?branch=cyrus-imapd-3.6)](https://travis-ci.com/cyrusimap/cyrus-imapd)

-----

Welcome
=======

This is the Cyrus IMAP Server, stable version 3.6.

Versions 3.0 to 3.4 still receive security updates, and some non-security
bug fixes.

What is Cyrus
=============

Cyrus is an IMAP server, where IMAP (Internet Message Access Protocol)
is a protocol for accessing mail.

The Cyrus IMAP server differs from other IMAP server implementations in
that it is generally intended to be run on "sealed" servers, where
normal users are not permitted to log in. The mailbox database is stored
in parts of the filesystem that are private to the Cyrus IMAP system.
All user access to content is through JMAP, IMAP, NNTP, POP3, CalDAV, CardDAV,
and WebDAV protocols.

The private mailbox database design gives the server large advantages in
efficiency, scalability, and administrability. Multiple concurrent
read/write connections to the same mailbox are permitted. The server
supports access control lists on mailboxes and storage quotas on mailbox
hierarchies.

Cyrus goals
===========

To be the best open source secure, scalable mail server, providing
breadth and depth of functionality across email, contacts, calendar
and related messaging services!

How to get Cyrus
================

Cyrus comes in three flavours:

1. Our release source tarballs from https://github.com/cyrusimap/cyrus-imapd/releases
    * Recommended for most users.
    * These are packaged by the Cyrus team.
    * The docs are pre-built for you in doc/html.
    * They're definitively tagged to a particular release version with up to
      date release notes.
2. Raw source from https://github.com/cyrusimap/cyrus-imapd
    * Use this if you need a version of Cyrus that contains an unreleased
      patch/fix/feature.
    * These bundles require a lot more dependencies to build than a packaged
      tarball.
3. Operating System distribution packages.
    * Cyrus IMAP packages are shipped with every major distribution, including
      but not limited to Fedora, Red Hat Enterprise Linux, CentOS, Scientific
      Linux, Debian, Ubuntu, openSUSE, Gentoo, Mageia and ClearOS.
    * Please be aware that we don't maintain these packages and as such, some
      distributions are out of date.
    * If you run into problems with a packed distribution, please contact the
      source of the distribution.

How to install Cyrus from packaged releases
===============================================

Please be sure to read the documentation. The latest version is online
at https://www.cyrusimap.org, but the version current for this
distribution can be found in the doc/ subdirectory.

For Cyrus tarball releases, the basic installation instructions are:

    $ ./configure
    $ make
    $ sudo make install

For more detailed instructions see: doc/html/imap/installation.diy.html#from-tarball 

How to install Cyrus from git source
============================================

The Cyrus source is available at:

https://github.com/cyrusimap/cyrus-imapd

For version 3.0 or later, please first build Cyrus main dependencies
from source (see next section).

The latest development code is on the branch called 'master',
and the latest code destined for the stable release is on
the branch 'cyrus-imapd-$major.$minor'.  So the current
stable release is called cyrus-imapd-3.6

Unlike releases, the git repository doesn't have a pre-built
./configure script.  You need to generate it with autoreconf:

    $ autoreconf -i
    $ ./configure
    $ make
    $ sudo make install

GNU Make is required.  If you're not on Linux, it might be called 'gmake'.

If you need to build a local copy of the docs current to the version of the
code, these need to be built: see doc/README.docs

Read through doc/html/imap/developer.html for more detailed instructions on
building and contributing. The latest version is online at
https://www.cyrusimap.org/imap/developer.html

How to install Cyrus libraries from git source
==============================================
For version 3.0 or later, it is recommended to also build the main
dependencies from source.

If you intend to use Xapian for search, we strongly recommend to use the
custom Xapian fork in cyruslibs. However, if this is not an option
in your environment, please fetch the latest stable upstream Xapian release.
Cyrus will omit custom features such as word boundary analysis for Chinese,
Japanese and Korean.

The Cyrus dependencies source is available at:

https://github.com/cyrusimap/cyruslibs

To build and install the libraries, run

    $ ./build.sh

By default, all dependencies are installed in /usr/local/cyruslibs.
Before compiling Cyrus from git source, make sure to update your environment
variables, accordingly. For example:

    $ export CYRUSLIBS=/usr/local/cyruslibs
    $ export PKG_CONFIG_PATH="$CYRUSLIBS/lib/pkgconfig:$PKG_CONFIG_PATH"
    $ export LDFLAGS="-Wl,-rpath,$CYRUSLIBS/lib -Wl,-rpath,$CYRUSLIBS/lib/x86_64-linux-gnu"

For Xapian, either make sure to add $CYRUSLIBS/bin to your PATH, or call
Cyrus ./configure script as follows:

    $ ./configure XAPIAN_CONFIG="$CYRUSLIBS/bin/xapian-config-1.5" [...]

(If you do not use Xapian from cyruslibs, you'll need to locate the
`xapian-config` binary and substitute `XAPIAN_CONFIG` accordingly).

Then continue to install Cyrus.

Are you upgrading?
==================

Read doc/html/imap/download/upgrade.html

Think you've found a bug or have a new feature?
===============================================

Fantastic! We'd love to hear about it, especially if you have a patch to
contribute.

The best way to make contributions to the project is to fork
it on github, make your changes on your fork, and then send
a pull request.

Check https://github.com/cyrusimap/cyrus-imapd/issues/ for any
outstanding bugs.

Our guide at https://www.cyrusimap.org/support.html has all the
information about how to contact us and how best to get your change accepted.

Licensing Information
=====================

See the COPYING file in this distribution.

Contact us
==========

Whether you have a success story to share, or a bug to file, or a
request for help or a feature to add or some documentation to contribute
or you'd just like to say hi, we want to hear from you! See
https://www.cyrusimap.org/support.html for various ways you can get hold
of us.
