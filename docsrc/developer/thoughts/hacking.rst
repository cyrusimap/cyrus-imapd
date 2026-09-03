.. _imap-developer-guidance-hacking:

..  Note: This document was converted from the original by Nic Bernstein
    (Onlight).  Any formatting mistakes are my fault and not the
    original author's.

Cyrus IMAP Server: Hacking
==========================

What's left of an old grab-bag of Cyrus coding notes.  The parts that described
our C style, the memory and string conventions, and the rules about process
startup and shutdown have moved to :ref:`the C style page <developer-c-style>`,
which is current; these two sections are what hadn't been rewritten yet.

..  warning::

    This document has not been reviewed in a long time.  If you're looking at
    the code and it doesn't seem to match this, don't assume the code is wrong.

map_refresh and map_free
------------------------

*   In many cases, it is far more effective to read a file via the
    operating system's mmap facility than it is to via the traditional
    ``read()`` and ``lseek`` system calls.  To this end, Cyrus provides
    an operating system independent wrapper around the ``mmap()``
    services (or lack thereof) of the operating system.

*   Cyrus currently only supports read-only memory maps, all writes back
    to a file need to be done via the more traditional facilities. This
    is to enable very low-performance support for operating systems
    which do not provide an ``mmap()`` facility via a fake userspace
    ``mmap``.

*   To create a map, simply call ``map_refresh`` on the map (details
    are in lib/map.h).  To free it, call ``map_free`` on the same map.

*   Despite the fact that the maps are read-only, it is often useful
    to open the file descriptors O_RDWR, especially if the file
    descriptors could possibly be used for writing elsewhere in the
    code. Some operating systems REQUIRE file descriptors that are
    ``mmap()``-ed to be opened O_RDWR, so just do it.

Network Functions
-----------------

*   Cyrus abstracts socket stream access to a concept we refer to as
    "prot streams"  Prot Streams take care of all of the necessary
    SASL and TLS/SSL encryption that may need to happen before data
    goes out/comes in from the network.  The API is documented in
    lib/prot.h
