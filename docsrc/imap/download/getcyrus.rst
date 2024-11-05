.. _getcyrus:

=========
Get Cyrus
=========

Where and how do you want to get Cyrus?

Distribution Package
====================

Cyrus IMAP packages are shipped with every major distribution, including
but not limited to Fedora, Red Hat Enterprise Linux, CentOS, Scientific
Linux, Debian, Ubuntu, openSUSE, Gentoo, Mageia and ClearOS. They are not
guaranteed to be up to date.

.. toctree::
    :maxdepth: 1
    :glob:

    installation/distributions/*

Build and Install Yourself
==========================

Use a release packaged tarball
------------------------------

The Cyrus team produce packaged tarballs containing full source and
pre-built documentation.

Download a versioned tarball using `HTTPS`_. Latest stable
version is |imap_current_stable_version|.

Extract the tarball:

.. parsed-literal::

    $ :command:`tar xzvf cyrus-imapd-x.y.z.tar.gz`

.. _HTTPS: https://github.com/cyrusimap/cyrus-imapd/releases

Use the source from Git
-----------------------

Read our :ref:`Guide to GitHub <github-guide>` for details on how to
access our GitHub repository, and fork/clone the source.

Licensing
=========

All versions of the Cyrus IMAP server and Cyrus SASL library are now
covered by the following copyright message. However, please note that
in older distributions, there may still be files that have the old
copyright text.

::

    * Copyright (c) 1994-2017 Carnegie Mellon University.  All rights reserved.
    *
    * Redistribution and use in source and binary forms, with or without
    * modification, are permitted provided that the following conditions
    * are met:
    *
    * 1. Redistributions of source code must retain the above copyright
    *    notice, this list of conditions and the following disclaimer.
    *
    * 2. Redistributions in binary form must reproduce the above copyright
    *    notice, this list of conditions and the following disclaimer in
    *    the documentation and/or other materials provided with the
    *    distribution.
    *
    * 3. The name "Carnegie Mellon University" must not be used to
    *    endorse or promote products derived from this software without
    *    prior written permission. For permission or any legal
    *    details, please contact
    *      Office of Technology Transfer
    *      Carnegie Mellon University
    *      5000 Forbes Avenue
    *      Pittsburgh, PA  15213-3890
    *      (412) 268-4387, fax: (412) 268-7395
    *      tech-transfer@andrew.cmu.edu
    *
    * 4. Redistributions of any form whatsoever must retain the following
    *    acknowledgment:
    *    "This product includes software developed by Computing Services
    *     at Carnegie Mellon University (http://www.cmu.edu/computing/)."
    *
    * CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
    * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
    * AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
    * FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
    * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
    * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
    * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
