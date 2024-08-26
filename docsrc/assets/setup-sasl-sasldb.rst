Now, let's set up **SASL**. This will allow you to connect to your
local IMAP server and login, just like any IMAP user would before
checking for new emails.

Create a ``saslauth`` group and add the ``cyrus`` user to the group, so
Cyrus can access SASL. (on Debian, this group is called 'sasl': adjust
the following commands to suit.)

::

    groupadd -fr saslauth
    usermod -aG saslauth cyrus

Change the default SASL configuration in ``/etc/default/saslauthd``.
    1. Make sure that the ``START`` option is set to *yes*
       ``(START=yes)`` and
    2. Set the``MECHANISMS`` option to **sasldb**
       ``(MECHANISMS="sasldb")``.

Start the SASL auth daemon:

::

    /etc/init.d/saslauthd start

Now, we'll create the IMAP user inside SASL. This is the user you'll
use to login to the IMAP server later on.

::

    echo 'secret' | saslpasswd2 -p -c imapuser

You can replace ``secret`` with a more suitable password you want and
``imapuser`` with the username you want. Once this is done, check that
the user exists and is set up correctly:

::

    testsaslauthd -u imapuser -p secret -f /var/run/saslauthd/mux

You should get an ``0: OK "Success."`` message.
