.. _faqs-o-gdb:

How to run gdb on Cyrus components
----------------------------------

.. sidebar:: What is a service daemon?

    A service daemon is any program based around master/service.c. This includes
    imapd, lmtpd (and some others), but does *not* include the command line
    tools.

An easy way to debug something in a service daemon is to write a
:ref:`Cassandane test <developer-testing>` that tries to reproduce the
bug. Cassandane has a ``[gdb]`` section in cassandane.ini which allows for
starting service daemons in a debugger.

The cassandane.ini.example in the cassandane repository contains examples and
instructions.

For programs that aren't service daemons, there are two options:

If they are installed, run them with gdb. You might need to use ``sudo``
depending on permissions. If they haven't been installed (and you're in the
source/build tree), you need to run gdb from ``libtool`` in order for everything
to work.

For example, if you wanted to debug cyr_virusscan:

.. code-block:: bash

    $ libtool --mode=execute gdb imap/cyr_virusscan

Command line arguments for a tool you're debugging, must be given to gdb before
you run. Use something like `set args [ ... ]
<https://sourceware.org/gdb/current/onlinedocs/gdb/Arguments.html#Arguments>`_.

`More information on gdb <http://sourceware.org/gdb/current/onlinedocs/gdb/>`_.
