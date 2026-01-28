.. _faqs-o-telemetry:

How to enable telemetry
-----------------------

To enable telemetry logging for a user, create a directory on disk for that user. Cyrus will automatically write logging information to this directory for all new connections. You don't need to restart Cyrus; closing the mail client and restarting it will do the trick.


The directory path is:

.. code-block:: bash

    mkdir $configdirectory/log/$userid/             # for example /var/imap/log/darth
    chown cyrus $configdirectory/log/$userid/       # The cyrus user needs write access to this directory.

If you have virtdomains enabled, then the username is the login name. In this case if you login as ``darth@vader.net``, then the path is ``/var/imap/log/darth@vader.net/``

The folder will contain files called ``imapd-$pid``, e.g. imapd-12345.  It might also have pop3 files, httpd files, one for each daemon.  The first part of the name is the service name from :cyrusman:`cyrus.conf(5)`.

.. warning::

    These log files won't contain passwords, but may contain other confidential user data such as the content of emails. Check them before sharing publicly!