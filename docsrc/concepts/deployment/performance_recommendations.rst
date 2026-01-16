Performance Recommendations
===========================

This chapter lists a variety of options to increase the Cyrus IMAP performance.

Databases on Temporary Filesystems
----------------------------------

Some databases and files and directory trees can be moved into a temporary filesystem, which may be an in-memory filesystem.

In-memory filesystems are faster then disk filesystems, but are limited in space and volatile as well. The following list includes configuration settings that could make the corresponding databases, files and directory trees be created and maintained on a temporary filesystem.

* ``proc_path``: /dev/shm/cyrus-imapd/proc
* ``mboxname_lockpath``: /dev/shm/cyrus-imapd/mboxname_lock
* ``duplicate_db_path``: /dev/shm/cyrus-imapd/duplicate_db
* ``statuscache_db_path``: /dev/shm/cyrus-imapd/statuscache_db

.. important::
    Cyrus IMAP requires the parent directories to exist, and be writeable by the POSIX user account Cyrus IMAP runs under, prior to starting the ``master`` process.


Certificates
------------
Cyrus IMAP can be configured to provide as server two kind of certificates: EC and RSA.  The EC certificates are only sent to the client, if the client supports them.  EC certificates have the advantage of requiring less computational resources compared to RSA, while offering comparatively the same security.
