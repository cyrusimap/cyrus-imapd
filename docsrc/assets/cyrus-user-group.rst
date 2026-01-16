Now let's create a **special user account just for the Cyrus server**
to sandbox Cyrus: called ``cyrus``. We'll also create a ``mail`` group
as well. This allows Cyrus to give other programs some permissions if
they are run under the ``mail`` group, again, without causing a Cyrus
bug to delete all of your cat pictures. Disaster!

If you have installed from packages, your package vendor may have
already done this for you.  To check, use these commands::

    $ getent group mail
    mail:x:8:

::

    $ getent passwd cyrus
    cyrus:x:999:8:Cyrus IMAP Server:/var/lib/imap:/bin/bash

Example group and user creation commands for GNU/Linux::

    groupadd -fr mail
    useradd -c "Cyrus IMAP Server" -d /var/lib/imap -g mail -s /bin/bash -r cyrus

The ``var/lib/imap`` directory above is an example. Use the same directory
specified in the ``configdirectory`` option in :cyrusman:`imapd.conf(5)`.

.. sidebar:: configdirectory

    |change-default-config|

    .. include:: /reference/manpages/configs/imapd.conf.rst
        :start-after: startblob configdirectory
        :end-before: endblob configdirectory


If your installation uses system locations for things like SSL
certificates (i.e. ``/etc/ssl/certs /etc/ssl/private``), then you should
also add the ``cyrus`` user to the appropriate group to gain access to
the PKI files.  On Debian/Ubuntu systems, for example, this group is
``ssl-cert``::

    usermod -aG ssl-cert cyrus
