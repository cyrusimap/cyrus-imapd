Running Cyrus IMAP Services on Non-Standard Ports
=================================================

Globally changing the service port
----------------------------------

When running on non-standard ports, for example lmtp on port 26,
update ``/etc/services`` and change the default '24' to '26'. This should
work correctly if everything on the system needs to know the new port number.

::

    lmtp            24/tcp                          # LMTP Mail Delivery
    lmtp            24/udp                          # LMTP Mail Delivery

becomes::

    lmtp            26/tcp                          # LMTP Mail Delivery
    lmtp            26/udp                          # LMTP Mail Delivery

Changing the service port just for Cyrus
----------------------------------------

If you need to run a service on a non-standard port **without changing the port for this service system-wide**, you can add a new service to ``/etc/services`` and reference this new service name within ``cyrus.conf``

If you were migrating mail on a server from a different imapd to Cyrus, you might need to run the Cyrus imapd on port 1143 while the original imapd is still on the normal port of 143. To do this, add a new service name to ``/etc/services``.

::

    imapnew         1143/tcp            # Temporary imap port

and in ``cyrus.conf`` the line::

  imap      cmd="imapd" listen="imap" prefork=5

would become::

  imap      cmd="imapd" listen="imapnew" prefork=5

You may wish to make Cyrus only listen on the loopback interface until the migration is complete. If this is the case, you would use ``listen="127.0.0.1:imapnew"``

Security Enhanced Linux
-----------------------
When running SELinux there are extra steps to take, ...

verify label for the port with semanage port -l <port>
label the port used: semanage port -a -t <type> -p tcp <port> 

.. todo:: Document this fully with example output!

