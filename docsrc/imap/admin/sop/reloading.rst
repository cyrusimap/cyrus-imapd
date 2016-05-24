.. _sop_reloading:

Reloading Cyrus IMAP Services
=============================

After a change has been applied to **/etc/cyrus.conf**, the Cyrus IMAP process **master** will need to be signalled to reload it's configuration file.

Such can be performed by sending a SIGHUP signal to the running process.

When changes to **/etc/imapd.conf** have been applied however, some options are available to have the new configuration be read.

.. note::
    All newly spawned processes (controlled by the **master** process) read in the configuration when they start.

Wait for existing processes to be "cycled", or restarted by the **master** process. The default number of connections to cause a process to be cycled is 250.

Touch the binary file for the process, for example **/usr/lib/cyrus-imapd/imapd**. When the process is idle, it will detect the modification timestamp on its binary file has changed and restart.

.. note::
    Touching the binary file for the process is an easy way to make sure all imapd processes read in the new configuration as soon as they have the chance, but modifies the modification timestamp on the file, potentially causing package file verification (such as RPM Package Management's ``rpm -qV``) to fail.

