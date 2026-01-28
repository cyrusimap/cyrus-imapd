.. _imap-developer-guidance-hacking:

..  Note: This document was converted from the original by Nic Bernstein
    (Onlight).  Any formatting mistakes are my fault and not the
    original author's.

Cyrus IMAP Server: Hacking
==========================

This file aims to be a guide to Cyrus coding style/conventions/useful
utilities for people trying to approach the code in a sane way.  It's
not well organized right now but hopefully that will improve with time
;)

..  warning::

    This document is woefully out of date.  While some parts of it are still
    accurate, it has not been reviewed in quite a while.  If you're looking at
    the code and it doesn't seem to match this, don't assume the code is wrong.
    Talk to the developers!  We'll revise this document, but don't hold your
    breath right now.  (This comment written August 5, 2021.)

Memory Allocation
-----------------

*   All cyrus memory allocation should be done through the libcyrus
    functions.  These are all written to correctly call ``fatal()`` in
    the event of an out-of-memory condition.
*   In addition to ``xmalloc`` and ``xrealloc``, we provide replacements
    for ``strdup``, ``strndup``, and a ``malloc`` that will guarantee
    zeroed block of memory (``xzmalloc``).
*   If you are going to need to do a large number of small allocations,
    and then free them all at once, you should look at the memory pool
    routines, which are much faster, but will leak memory until you
    free the entire pool at once.

strlcpy vs strncpy vs memcpy
----------------------------

*   use ``strlcpy`` when you know the size of the buffer, e.g.:

::

    char buf[50];
    strlcpy(buf, src, sizeof(buf));

*   use ``memcpy`` to truncate a string into a buffer you know is large
    enough. Note that when you do this the resulting buffer will NOT BE
    NULL TERMINATED:

::

    memcpy(buf, src, 4);
    buf[5] = '\0'

*   you should try to avoid ``strncpy``, since it is much slower than
    ``memcpy`` (it zero-fills the rest of the buffer) and isn't as safe
    as ``strlcpy``.

*   Use of the functions in this way will reduce the confusion involved
    in their various behaviors. In other words, this avoids things that
    look like:

::

    strncpy(buf, src, sizeof(buf)-1);

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

(todo) Authorization Modules
----------------------------

General Hints
-------------

Some general hints that all made it into my 11/15 16:47 commit that I
think may be generally useful to people hacking on the cyrus source:

*   Command line apps should link cli_fatal.o so they all fatal()
    in the same way, unless there is a really good reason they need to
    do something unique.

*   If you call ``cyrus_init()`` you must call ``cyrus_done()`` before
    you exit.

*   No one should ever call ``DB->init()`` or ``DB->done()`` cyrusdb
    functions except for in ``libcyrus_init()``.

*   I've been trying to keep ``#include`` statements for libcyrus and
    libimap alphabetical, and below any system includes, but this is
    merely my personal style

*   Don't exit at the bottom of ``main`` with ``exit(x)`` use
    ``return`` instead.

*   For all the command line utilities that need to be sure that they
    are running as the cyrus user, it should be the first thing they
    do, and they should exit with an appropriate ``fatal()`` call.

*   All services should have a ``shut_down`` call.  It should be the
    ONLY way of exiting the application.  ``fatal()`` should always
    make an attempt to call ``shut_down()`` if it can (though it should
    have a recursive ``fatal()`` trap just in case).  Similarly,
    command line utilities probably don't need a ``shut_down()``.


Coding Standards
----------------

These are the generally agreed upon coding standards as thrashed
out on the cyrus-devel list in June 2010.

*   Spacing is 4 characters with soft tabs at 8 - mixed tabs and spaces
    This corresponds to the vi settings `sw=4 sts=4 ts=8` etc.

*   Group the '\*' character with the variable not the type, i.e.

::

    char *foo;  /* correct */
    char* foo;  /* WRONG */

*   The keywords 'if', 'for', and 'while' take a space after the keyword.
    The parentheses around the following expression are not closely
    connected to the expression without any spaces.  The ';' inside
    the 'for' expression have a space after them and not before.
    For example:

::

    if (condition)              /* correct */
    if(condition)               /* WRONG */
    if( condition )             /* WRONG */

    for (i = 0; i < x; i++)     /* correct */
    for(i = 0; i < x; i++)      /* WRONG */
    for (i = 0 ;i < x ;i++)     /* WRONG */
    for(i = 0 ;i < x ;i++)      /* WRONG */

    while (foo)                 /* correct */
    while(foo)                  /* WRONG */
    while( foo )                /* WRONG */

*   Use spaces around the double-character logical operator
    '||' but don't use spaces around single-character bitwise
    operator '|'.

::

    int flags = FOO|BAR;        /* correct */
    int flags = FOO | BAR;      /* WRONG */
    if (itchy || scratchy)      /* correct */
    if (itchy||scratchy)        /* WRONG */

*   Function definitions are followed by a brace on a line by itself,
    all other braces are inline.  Return types are inline with function
    definition.  Old K&R style function definitions are not allowed.

::

    void thing(int val)         /* correct */
    {                           /* correct */
        ...body...
    }                           /* correct */

    void                        /* WRONG */
    thing(int val)              /* WRONG */
    {                           /* WRONG */
        ...body...
    }                           /* WRONG */

    void                        /* WRONG */
    thing(                      /* WRONG */
        int val)                /* WRONG */
    {                           /* WRONG */
        ...body...
    }                           /* WRONG */

    void                        /* WRONG */
    antique(val)                /* WRONG */
        int val;                /* WRONG */
    {                           /* WRONG */
        ...body...
    }                           /* WRONG */

    void thing(int val) {       /* WRONG */
        ...body...
    }                           /* WRONG */

    void noargs(void)           /* correct */
    {                           /* correct */
        ...body...
    }                           /* correct */

    void noargs()               /* WRONG */
    {                           /* WRONG */
        ...body...
    }                           /* WRONG */


*   Long argument lists should be split across multiple lines,
    with the second and subsequent lines indented so that they
    line up with the start of the first line of arguments.

::

    void toomanyargs(int arg1, const char *arg2,        /* correct */
                     struct whatever *arg3, int arg4)   /* correct */
    {                                                   /* correct */
        ...body...
    }                                                   /* correct */

    void toomanyargs(int arg1, const char *arg2,        /* WRONG */
    struct whatever *arg3, int arg4)                    /* WRONG */
    {                                                   /* WRONG */
        ...body...
    }                                                   /* WRONG */

    void toomanyargs(                                   /* WRONG */
        int arg1,                                       /* WRONG */
        const char *arg2,                               /* WRONG */
        struct whatever *arg3,                          /* WRONG */
        int arg4)                                       /* WRONG */
    {                                                   /* WRONG */
        ...body...
    }                                                   /* WRONG */

*   Within a function, braces are used in old-fashioned K&R style.
    Specifically:

    *   open braces are placed at the end of the line containing the
        statement (such as an 'if') to which they belong, after a
        single space.

    *   closing braces are placed on a line by themselves, aligned
        with the start of the statement to which their matching
        open brace belongs.

    *   this applies even when the closing brace is followed by
        an 'else' keyword.

..

    Yes, it's ugly and hard to read, but you get used to it and
    most of the code is currently like that.  Deal with it.

::

    while (cond) {              /* correct */
        ...body...              /* correct */
    }                           /* correct */

    while (cond){               /* WRONG */
        ...body...              /* WRONG */
    }                           /* WRONG */

    while (cond) { ...body... } /* WRONG */

    while (cond) {              /* WRONG */
        ...body... }            /* WRONG */

    while (cond)                /* WRONG */
    {                           /* WRONG */
        ...body...              /* WRONG */
    }                           /* WRONG */

    while (cond)                /* WRONG */
      {                         /* WRONG */
        ...body...              /* WRONG */
      }                         /* WRONG */

    if (cond) {                 /* correct */
        ...body...              /* correct */
    }                           /* correct */
    else if (othercond) {       /* correct */
        ...body...              /* correct */
    }                           /* correct */
    else {                      /* correct */
        ...body...              /* correct */
    }                           /* correct */

    if (cond) {                 /* WRONG */
        ...body...              /* WRONG */
    } else if (othercond) {     /* WRONG */
        ...body...              /* WRONG */
    } else {                    /* WRONG */
        ...body...              /* WRONG */
    }                           /* WRONG */

    if (cond)                   /* WRONG */
    {                           /* WRONG */
        ...body...              /* WRONG */
    }                           /* WRONG */
    else if (othercond)         /* WRONG */
    {                           /* WRONG */
        ...body...              /* WRONG */
    }                           /* WRONG */
    else                        /* WRONG */
    {                           /* WRONG */
        ...body...              /* WRONG */
    }                           /* WRONG */

*   The braces around a block used in an 'if'...'else if'...'else'
    may be omitted if the statement is very simple and clear, such
    as a single function call.  This is a judgement call though,
    so play it safe and use braces.

::

    if (cond)                   /* correct, maybe */
        function();             /* correct, maybe */
    else                        /* correct, maybe */
        other_function();       /* correct, maybe */

*   The 'goto' keyword needs to be used very very sparingly and only
    with forethought.  The only clearly good example is to goto
    a label at the end of a function to do cleanup under error
    conditions.

::

    void foo(struct bar *b)     /* correct */
    {                           /* correct */
        char *x = xmalloc(...); /* correct */

        if (b == NULL)          /* correct */
            goto error;         /* correct */

        if (b->quux != 42)      /* correct */
            goto error;         /* correct */

        ...do useful things...  /* correct */
    error:                      /* correct */
        free(x);                /* correct */
    }                           /* correct */

..

    Very occasionally, it may be permissable to use 'goto' from within
    a complicated or multiply-nested loop, to the top of a loop, but
    only if using another control structure is *less* clear.

*   Generally, zero return is SUCCESS and integer return is an error code.

*   Use "``const char *``" where possible.

::

    int is_tacky(const char *name)              /* correct */
    {                                           /* correct */
        return !strcmp(name, "britney");        /* correct */
    }                                           /* correct */

    int is_tacky(char *name)                    /* WRONG */
    {                                           /* WRONG */
        return !strcmp(name, "britney");        /* WRONG */
    }                                           /* WRONG */

*   Use "``struct buf``" for variable length strings where possible.

*   RAII http://en.wikipedia.org/wiki/Resource_Acquisition_Is_Initialization
    In practice, this means each structure should have a single cleanup
    function which handles all possible states of the structure and
    is called whenever the structure needs cleaning up.  Likewise,
    any resources allocated during a function should be cleaned up
    in the same function, in a single code block at the end of the
    function (see the comments on 'goto').

*   If you find yourself passing the same multiple parameters through many
    functions, create a struct and pass around a pointer to that instead.

*   DON'T EVER REUSE THE SAME VARIABLE FOR TWO DIFFERENT PURPOSES IN THE SAME
    FUNCTION.  IN FACT, DON'T REUSE THE SAME VARIABLE _NAME_ FOR DIFFERENT
    PURPOSES.  KTHXBYE.  (note: this doesn't apply to 'i', 'n', etc which are
    used in multiple loops.  It applies to using the same name for an absolute
    offset and a "within this mmap" offset though, and it also applies to
    using the same variable name for native order and network order numbers,
    which is where I've seen it a few times and been super frustrated!)

*   Write RFCs in comments capitalized with space after the RFC, like
    ``RFC 1234``, not like ``rfc 1234`` or ``RFC1234``.
