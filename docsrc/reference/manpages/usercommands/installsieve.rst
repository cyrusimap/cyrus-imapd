.. cyrusman:: installsieve(1)

.. author: Nic Bernstein (Onlight)

.. _imap-reference-manpages-usercommands-installsieve:

================
**installsieve**
================

User utility for managing sieve scripts

Synopsis
========

.. parsed-literal::

    **installsieve** [ **-v** *name* ] [ **-l** ] [ **-p** *port* ] [ **-i** *file* ]
        [ **-a** *name* ] [ **-d** *name* ] [ **-m** *mechanism* ] [ **-g** *name* ]
        [ **-u** *user* ]

Description
===========

**installsieve** is a utility that allows users to manage their sieve scripts kept on
the server.

.. Note:: This program is deprecated. Please use sieveshell

Options
=======

.. program:: installsieve

.. option:: -v  name

    View script with the given name. The script if retrieved successfully
    is output to standard output.

.. option:: -l

    List all of the scripts currently on the server. If one of the
    scripts is active an arrow is printed indicating that it is the
    active script.

.. option:: -p  port

    Port to connect to. If left off this defaults to **sieve** as
    defined in ``/etc/services``.

.. option:: -i  file

    Install a file onto the server. If a script with the same name
    already exists on the server it is overwritten. Upon successfully
    putting the script on the server the script is set active.

.. option:: -a  name

    Set *name* as the active script. The list of available names can be
    obtained from the **-l** option.

.. option:: -d  name

    Delete the sieve script on the server with *name*.

.. option:: -m  mechanism

    Force **installsieve** to use *mechanism* for authentication. If
    not specified the strongest authentication mechanism supported by
    the server is chosen.  Specify *login* to use the LOGIN command
    instead of AUTHENTICATE.

.. option:: -g  name

    Get the sieve script with *name* and save it to disk with a
    ".script" extension. If a file with that name already exists it is
    overwritten.

.. option:: -u  userid

    Userid/Authname to use for authentication; by default, the current
    user.

History
=======

.. Note:: This program is deprecated. Please use sieveshell

See Also
========

:cyrusman:`sieveshell(1)`
