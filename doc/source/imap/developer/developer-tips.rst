.. _cyrus-hacking:

=========================
Tips for Hacking on Cyrus
=========================

Memory Allocation
=================

All Cyrus memory allocation should be done through the ``libcyrus`` functions. These are all written to correctly call fatal() in the event of an out-of-memory condition.

In addition to xmalloc and xrealloc, we provide replacements for strdup, strndup, and a malloc that will guarantee zeroed block of memory (xzmalloc).

If you are going to need to do a large number of small allocations, and then free them all at once, you should look at the memory pool routines, which are much faster, but will leak memory until you free the entire pool at once.

strlcpy vs strncpy vs memcpy
============================

Use strlcpy when the size of the buffer is known, e.g.::

    char buf[50];
    strlcpy(buf, src, sizeof(buf));

Use memcpy to truncate a string into a buffer you know is large enough. Note that the resulting buffer will NOT BE NULL TERMINATED.

::

    memcpy(buf, src, 4);  
    buf[5] = '\0'

Try to avoid strncpy, since it is much slower than memcpy (it zero-fills the rest of the buffer) and isn't as safe as strlcpy.

Use of the functions in this way will reduce the confusion involved in their various behaviours. This avoids things that look like::
 
    strncpy(buf, src, sizeof(buf)-1);
    buf[sizeof(buf)-1] = '\0';

map_refresh and map_free
========================

In many cases, it is far more effective to read a file via the operating system's mmap facility than it is to via the traditional read() and lseek system calls. To this end, Cyrus provides an operating system independent wrapper around the mmap() services (or lack thereof) of the operating system.

Cyrus currently only supports read-only memory maps, all writes back to a file need to be done via the more traditional facilities. This is to enable very low-performance support for operating systems which do not provide an mmap() facility via a fake userspace mmap.

To create a map, simply call map_refresh on the map (details are in lib/map.h). To free it, call map_free on the same map.

Despite the fact that the maps are read-only, it is often useful to open the file descriptors O_RDWR, especially if the file decriptors could possibly be used for writing elsewhere in the code. Some operating systems REQUIRE file descriptors that are mmap()ed to be opened O_RDWR, so just do it.

Network Functionality
=====================

Read about :ref:`Cyrus IMAP Prot Layer <admin-protlayer>`.

Authorization modules
=====================

**TO DO:**

    Describe what the authorization modules do, what API needs to be implemented, etc. Also possibly discuss the auth_pts module.

.. :todo:

    Describe what the authorization modules do, what API needs to be implemented, etc. Also possibly discuss the auth_pts module.

Other
=====

* Command line apps should link cli_fatal.o so they all fatal() in the same way, unless there is a really good reason they need to do something unique.

* If you call config_init() you must call cyrus_done() before you exit.
    No one should ever call DB->init() or DB->done() cyrusdb functions except for in libcyrus_init()

* Try to keep #include statements for libcyrus and libimap alphabetical, and below any system includes.

* Don't exit at the bottom of main with exit(x) use return instead.
    For all the command line utilities that need to be sure that they are running as cyrus, it should be the first thing they do, and they should exit with an appropriate fatal() call

* All services should have a shut_down call. It should be the ONLY way of exiting the application (every "clean" exit from the system should be via shut_down()). fatal() should always make an attempt to call shut_down() if it can (though it should have a recursive fatal() trap just in case). Similarly, commandline utilities probably don't need a shut_down().
    
File Locking
============

In order to guard against deadlocks, we want to maintain 
the same order of acquiring locks throughout the system 
(this may be violated in one or two places, but when it is it is 
commented as to why it is safe). As long as everyone plays 
by these rules, we can avoid deadlock.

In an ideal world, our locking order is::

    cyrus.header
    cyrus.index
    quota
    seen
    mailboxes file
    
These try to go from least general to most general, so we hold the largest locks for the shortest period of time.

.. todo::
    http://www.cyrusimap.org/mediawiki/index.php/Cyrus_IMAP_Hacking
    http://www.cyrusimap.org/mediawiki/index.php/Cyrus_IMAP_File_Locking
