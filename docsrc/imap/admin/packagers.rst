Notes for Packagers
===================

Services in ``/etc/services``
-----------------------------

Listing named services through ``/etc/services`` aids in cross-system consistency and cross-platform interoperability. Furthermore, it enables administrators and users to refer to the service by name (for example in ``/etc/cyrus.conf``, 'listen=mupdate' can be specified instead of 'listen=3905').

Some of the services Cyrus IMAP would like to see available through ``/etc/services`` have not been assigned an IANA port number, and few have configuration options.

The following lists services Cyrus IMAP should have available in ``/etc/services``:

* **csync**

    The Cyrus IMAP synchronisation server port, for replication clients to connect to.

    * Description: *Cyrus IMAP Replication Daemon*
    * Suggested Port(s): **2005/tcp**

.. note::
    **Default in /etc/imapd.conf**

    While **2005/tcp** is the suggested default port for **csync**, the value of the port number is specified through the **sync_port** option in ``/etc/imapd.conf`` (generated from ``lib/imapoptions``). Note that when changing the suggested port for **csync** we recommend you also patch ``lib/imapoptions`` prior to building Cyrus IMAP. 

* **lmtp**

    Some platforms do not specify the service port for LMTP –like Solaris and Debian. Fedora-based Linux distributions allocate port **24/tcp** for LMTP Mail Delivery, however. Whatever port packagers choose to use, please note they should be the same across all platforms deployed in a single environment.

    * Description: *LMTP Mail Delivery*
    * Suggested Port(s): **24/tcp** (Fedora-based platforms), **2003/tcp** (other platforms) 

* **mupdate**

    The Cyrus IMAP Murder Mailbox Update protocol (MUPDATE) ensures mailboxes

    * Description: *Mailbox Update (MUPDATE) protocol*
    * Recommended Port(s): **3905/tcp**

.. note::
    Default in ``/etc/imapd.conf``

    **3905/tcp** is the suggested default port for mupdate, as it is the default value specified for the **mupdate_port** option available in ``/etc/imapd.conf`` (generated from ``lib/imapoptions``). Note that when changing the suggested port for mupdate we recommend you also patch ``lib/imapoptions`` prior to building Cyrus IMAP. 

* **sieve**

    * Description: *ManageSieve protocol*
    * IANA Port: **4190/tcp**

.. note::
    **Port 2000/tcp**

    **2000/tcp** is actually sieve-filter with description *Sieve Mail Filter Daemon*.

* **smmap**

    * Description: *Cyrus smmapd (quota check) service*
    * Suggested Port(s): **/tcp**

