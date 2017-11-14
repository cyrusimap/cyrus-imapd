===========
Cyrus Works
===========

About Cyrus Works
=================

Whenever the Cyrus team push changes to
`the project repository <https://github.com/cyrusimap/>`_, a notification is
sent to `Jenkins <https://jenkins.io/>`_ (open source automation server).
Our Jenkins server is called Cyrus Works and can be found at
https://www.cyrus.works.

Testing
=======

Once a week Cyrus.Works builds a complete image, fetching all upstream packages.

Interim builds during the week use the cached weekly image and apply the latest
Cyrus IMAP code changes from Git.

Email notifications of build results are sent to the development team.

Cyrus.works will fail is certain strings are found in the log files.  To view results and filter errors/warnings view:
https://cyrus.works/job/master-jessie/lastFailedBuild/parsed_console/

How it works
============

`Cassandane <https://github.com/cyrusimap/cassandane>`_, the Cyrus IMAP test
framework gets pulled in to the
`Docker Container <https://github.com/cyrusimap/cyrus-docker>`_, confirms
existing functionality still works and no regression bugs have been introduced.

You can find out more about Cyrus.Works in the `FastMail 2016 advent series blog post <https://blog.fastmail.com/2016/12/14/cyrus-works/>`_.

The code used to build Cyrus.works is available https://github.com/cyrusimap/cyrusworks.

Adding Rules
============

Instructions on how to add rules:
https://wiki.jenkins.io/display/JENKINS/Log+Parser+Plugin

The rules for Cyrus Works are stored within git: https://github.com/cyrusimap/cyrusworks/blob/master/Scripts/cyrusworksrules

You need to add rules to two places:

1. **Git**: so when cyrus.works is reinstalled those rules are not lost

2. **The server**: so they’re actually used. Changed pushed to git aren’t pushed to the server. This is for security reasons (we don’t want anyone on the internet to be able to push changes to a live server).
``root@cyrus.works:/cyrusworks/source/Scripts/cyrusworksrules``
