===========
Cyrus Works
===========

About Cyrus Works
=================

`Cyrus Works <https://cyrus.works>`_ is a domain redirection to the Cyrus IMAP
project's GitHub Actions dashboard.

Whenever the Cyrus team push changes to `the project repository
<https://github.com/cyrusimap/>`_, GitHub Actions automatically build the new
commits.  This also applies to pull requests submitted through the GitHub site.

How it works
============

`Cassandane <https://github.com/cyrusimap/cassandane>`_, the Cyrus IMAP test
framework gets pulled in to the
`Docker Container <https://github.com/cyrusimap/cyrus-docker>`_, confirms
existing functionality still works and no regression bugs have been introduced.
