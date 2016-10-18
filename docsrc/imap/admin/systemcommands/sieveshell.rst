.. _imap-admin-systemcommands-sieveshell:

==============
``sieveshell``
==============

The ``sieveshell`` utility allows users to manipulate their scripts on a remote server. Placing a script and activating it on the server also compiles the script to bytecode for faster execution. 

Sieveshell works via MANAGESIEVE, a work in progress.

.. rubric:: Synopsis

.. parsed-literal::

    sieveshell [--user=user] [--authname=authname] [--realm=realm] [--exec=script] server[:port]
    
    sieveshell --help

.. rubric:: Command-Line Options

.. program:: sieveshell

.. option:: -u, --user <user>

    The authorization name to request; by default, derived from the authentication credentials.

.. option:: -a, --authname=<authname>

    The user to use for authentication (defaults to current user).

.. option:: -r, --realm=<realm>

    The realm to attempt authentication in.

.. option:: -e, --exec=<script>

    Instead of working interactively, run commands from script, and exit when done.

.. _imap-admin-systemcommands-sieveshell-list:

list
----

List scripts on server.

.. parsed-literal::

    > :command:`list`
    
.. _imap-admin-systemcommands-sieveshell-put:

put
---

Uploads <filename> script to server.

.. parsed-literal::

    > :command:`put <filename>`

.. _imap-admin-systemcommands-sieveshell-get:

get
---

Fetches a script from the server. If no <filename> is provided, display script contents to stdout.

.. parsed-literal::

    > :command:`get <name> [<filename>]` 

.. _imap-admin-systemcommands-sieveshell-delete:

delete
------

Deletes a script from the server.

.. parsed-literal::

    > :command:`delete <name>` 

.. _imap-admin-systemcommands-sieveshell-activate:

activate
--------

Activates the script on the server.

.. parsed-literal::

    > :command:`activate <name>` 

.. _imap-admin-systemcommands-sieveshell-deactivate:
    
deactivate
----------

deactivate deactivate all scripts.

.. parsed-literal::

    > :command:`deactivate` 

