.. _imap-developer-unit-tests:

..  Note: This document was converted from the original by Nic Bernstein
    (Onlight).  Any formatting mistakes are my fault and not the
    original author's.

Unit Tests
==========

Table of Contents
-----------------

-  `1. Introduction <#introduction>`__
-  `2. What Is A Unit Test? <#what-is-a-unit-test>`__
-  `3. Running The Tests <#running-the-tests>`__

   -  `3.1. Setting Up The Machine <#setting-up-the-machine>`__
   -  `3.2 Configure Script <#configure-scripts>`__
   -  `3.3 Make <#running-the-tests>`__
   -  `3.4 Using Valgrind <#using-valgrind>`__
   -  `3.5 The Tests Are Failing <#the-tests-are-failing>`__
   -  `3.6 Debugging A Test <#debugging-a-test>`__

-  `4. Adding Your Own Tests <#adding-your-own-tests>`__

   -  `4.1 Where To Put Your Tests <#where-to-put-your-tests>`__
   -  `4.1 Adding A New Suite <#adding-a-new-suite>`__
   -  `4.2 Adding A Test To A Suite <#adding-a-test-to-a-suite>`__
   -  `4.3 Suite Init And Cleanup <#suite-init-and-cleanup>`__

1. Introduction
---------------

Recently, a set of regression unit tests has been added to Cyrus. This
document explains the purpose implementation of those unit tests, and
gives an example of how to add more unit tests (because there are never
enough unit tests!).

2. What Is A Unit Test?
-----------------------

The `definition on Wikipedia <http://en.wikipedia.org/wiki/Unit_test>`__
sheds some light:

    ...\ **unit testing** is a method by which individual units of
    source code are tested to determine if they are fit for use. A unit
    is the smallest testable part of an application.

In other words, unit testing is about verifying that small pieces of
code, like individual functions, modules, or classes, work in isolation.
It is **not** about testing the system as a whole.

The tests implemented here are also **regression tests**, which in
`Wikipedia's words <http://en.wikipedia.org/wiki/Regression_testing>`__
means:

    **Regression testing** is any type of software testing that seeks to
    uncover software errors after changes to the program (e.g. bugfixes
    or new functionality) have been made, by retesting the program. The
    intent of regression testing is to assure that a change, such as a
    bugfix, did not introduce new bugs.

In other words, the tests are designed to be easy to run and to work out
fully automatically whether they have passed or failed, so that they can
be run usefully by people who didn't write them.

3. Running The Tests
--------------------

This section takes you through the process of running Cyrus' unit tests.

3.1. Setting Up The Machine
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Cyrus' unit tests are all located in a new directory,
``cyrus-imapd/cunit/``. They're written in C, like the remainder of
Cyrus, and use the `CUnit library from
SourceForge <http://cunit.sourceforge.net/>`__, with some home grown
wrappers and other improvements to make our lives easier.

Your first step is step is to ensure that the CUnit library (including
the headers) is installed. Some modern operating systems already have
CUnit, for example on Ubuntu you can just do:

::

    me@ubuntu> sudo apt-get install libcunit1-dev

Alternately, you can download the CUnit source, build it and install it.
It's not a complicated or difficult library, this shouldn't take long.
When you've done, install it in ``/usr/include`` and ``/usr/lib``.

3.2 Configure Script
~~~~~~~~~~~~~~~~~~~~

Because of the dependency on the CUnit library, the tests are disabled
by default; this means you need enable them with an option to the
``configure`` script:

::

    me@mybox> ./configure --enable-unit-tests
    ...
    checking for CU\_initialize\_registry in -lcunit... yes
    checking CUnit/CUnit.h usability... yes
    checking CUnit/CUnit.h presence... yes
    checking for CUnit/CUnit.h... yes
    ...

3.3 Make
~~~~~~~~

First you need to build Cyrus itself, using the traditional ``all:``
target.

::

    me@mybox> make all
    ...

Then, use the new ``check:`` target to build and run the unit tests.

::

    me@mybox> make check
     cd . && /bin/bash /home/me/cyrus-imapd/missing --run automake-1.11 --foreign Makefile
     cd . && /bin/bash ./config.status Makefile depfiles (a)
    config.status: creating Makefile
    config.status: executing depfiles commands
    ...
    make[3]: Entering directory \`/home/me/cyrus-imapd'
    make[3]: \`sieve/test' is up to date.
    cunit/cunit.pl --project cunit/default.cunit --generate-wrapper cunit/mboxname.testc (b)
    gcc -DHAVE\_CONFIG\_H ... -c -o cunit/mboxname.o cunit/mboxname.testc-cunit.c
    rm -f cunit/mboxname.testc-cunit.c
    /bin/bash ./libtool --tag=CC --mode=link gcc -fPIC -g -O2 -o
    cunit/unit cunit/unit.o ... lib/libcyrus\_min.la ... (c)
    ...
    Running unit tests (d)

        CUnit - A Unit testing framework for C - Version 2.1-0
        http://cunit.sourceforge.net/

    ...
    Suite: mboxname (e)
      Test: dir\_hash\_c ... passed
      Test: to\_parts ... passed
      Test: to\_userid ... passed
      Test: to\_usermbox ... passed
    ...
    --Run Summary: Type      Total     Ran  Passed  Failed (f)
                   suites       34      34     n/a       0
                   tests       323     323     323       0
                   asserts 1079745 1079745 1079745       0
    make[1]: Leaving directory `/home/me/cyrus-imapd/cunit'

Let's take a closer look at what's happening here.

(a)
    The ``check:`` target causes automake to re-run itself. This is
    normal automake behaviour. Note that the older build system used to
    run make recursively in sub-directories, the newer automake-based
    system builds everything from the top directory.
(b)
    The ``cunit/`` directory contains a number of C source files
    (called, for reasons too complicated to explain here,
    *whatever*.testc) with test code in them. For each of those, a small
    wrapper C source file is generated and then compiled into an object
    file.
(c)
    Finally, all the compiled object files are linked into an
    executable, with a ``main()`` routine from ``unit.c``, and a number
    of libraries and object files from other parts of the Cyrus tree.
(d)
    The resulting executable is then run.
(e)
    The test executable runs all the built tests one by one, telling us
    which ones passed and which ones failed as it runs them. You can
    also run it manually with the name of a test as an argument, and it
    will run only the named test.
(f)
    At the end, the text executable prints a summary of how many tests
    it ran and how many passed and failed. The key thing to look at here
    is the rightmost column, it should be all zero.

3.4 Using Valgrind
~~~~~~~~~~~~~~~~~~

Some failure modes are subtle, and cannot be detected in the C code
itself; this is where `the Valgrind program <http://valgrind.org/>`__
comes in very handy. It detects buffer overruns and memory leaks and
various other kinds of subtle errors.

To run the unit tests with Valgrind, use the new ``valgrind:`` target.

::

    me@mybox> make valgrind
    ...
    valgrind --tool=memcheck --leak-check=full ./unit -v (a)
    ==2999== Memcheck, a memory error detector
    ==2999== Copyright (C) 2002-2010, and GNU GPL'd, by Julian Seward et al.
    ==2999== Using Valgrind-3.6.0.SVN-Debian and LibVEX; [...]
    ==2999== Command: ./unit -v
    ==2999==
    ...
    --Run Summary: Type      Total     Ran  Passed  Failed   (b)
                   suites        9       9     n/a       0
                   tests        51      51      50       1
                   asserts     474     474     473       1
    ...
    ==2999== HEAP SUMMARY:   (c)
    ==2999==     in use at exit: 4,489 bytes in 134 blocks
    ==2999==   total heap usage: 715 allocs, 581 frees, 352,763 bytes allocated
    ==2999==
    ==2999== 4 bytes in 1 blocks are definitely lost in loss record 3 of 50
    ==2999==    at 0x4C2815C: malloc (vg_replace_malloc.c:236)
    ==2999==    by 0x44A0CA: xmalloc (xmalloc.c:57)
    ==2999==    by 0x4399D8: strconcat (util.c:631)
    ==2999==    by 0x40C059: test_uncast_null (strconcat.c:51)
    ==2999==    by 0x61B32A9: ??? (in /usr/lib/libcunit.so.1.0.1)
    ==2999==    by 0x61B36ED: ??? (in /usr/lib/libcunit.so.1.0.1)
    ==2999==    by 0x61B3827: CU_run_all_tests (in /usr/lib/libcunit.so.1.0.1)
    ==2999==    by 0x4066CC: run_tests (unit.c:144)
    ==2999==    by 0x406806: main (unit.c:283)
    ==2999==
    ...

Here's an explanation of what's happening in the example.

(a)
    The test executable is run as before, but using the ``valgrind``
    program. The first thing we see is Valgrind's banner message.
(b)
    The test executable proceeds as normal and eventually emits it's run
    summary, then exits.
(c)
    After the test executable exits, Valgrind checks for memory leaks
    and prints both a summary of all leaks and a stack trace showing
    where each block of leaked memory was allocated.

I'd just like to say that I love Valgrind and I think it's immensely
useful. I would have made running the tests under Valgrind the only
option for the ``check:`` target, except that Valgrind is not available
on all of Cyrus' supported platforms.

3.5 The Tests Are Failing
~~~~~~~~~~~~~~~~~~~~~~~~~

So you've noticed that some of the tests are failing. Let me make the
guiding principle of unit testing as clear as possible: **THE UNIT TESTS
SHOULD NOT FAIL**. All of the tests are designed to pass all the time,
in everyone's environment. The unit tests are run automatically every
twelve hours on the Cyrus `Continuous Integration
server <http://ci.cyrusimap.org/>`__, and a failing test fails the whole
build and makes people unhappy.

There are a few rules which you should follow to help us all get the
most benefit out of unit testing

-  If you see a test failing, investigate it.
-  If you can't investigate, complain on the mailing list or raise a bug
   so that somebody else can investigate.
-  When writing tests, write them to work in all environments and all
   combinations of ``configure`` script options. It's ok to have a test
   which is empty in some circumstances; it's not ok to have a test that
   fails.
-  When adding code, write new tests for the new code.
-  When modifying code, write new tests for the new behaviour.
-  When looking at old code, also take a look at the `coverage
   report <http://ci.cyrusimap.org/job/cyrus-imapd-master/887/cobertura/>`__
   and consider writing tests for the existing code.

3.6 Debugging A Test
--------------------

With the new Cyrus build system, the file ``cunit/unit`` is no longer an
executable, it's a shell script which sets up some environment variables
before running the real executable which is hidden away. This makes
debugging a failing test somewhat challenging. The solution is:

::

    me@mybox> ( cd cunit ; libtool --mode=execute gdb --args unit -t crc32 )
    ...
    Reading symbols from /home/me/cyrus-imapd/cunit/.libs/lt-unit...done.
    (gdb) list crc32.testc:1
    1       /* Unit test for lib/crc32.c */
    2       #include "cunit/cyrunit.h"
    3       #include "crc32.h"
    ...
    (gdb) break test_map
    Breakpoint 1 at 0x44a2f8: file ./cunit/crc32.testc, line 11.
    (gdb) run
    Starting program: /home/me/cyrus-imapd/cunit/.libs/lt-unit -t -v crc32
    [Thread debugging using libthread_db enabled]

        CUnit - A Unit testing framework for C - Version 2.1-0
        http://cunit.sourceforge.net/

    Suite: crc32
      Test: map ...
    Breakpoint 1, test_map () at ./cunit/crc32.testc:11
    11          c = crc32_map(TEXT, sizeof(TEXT)-1);
    (gdb)


Note the **-t** option. This turns off test timeouts, which is very
useful for manual debugging.

4. Adding Your Own Tests
------------------------

Adding your own tests is quite simple. Here's how.

4.1 Where To Put Your Tests
---------------------------

The unit test code in Cyrus is contained in a set of C source files in
the ``cunit`` directory. For reasons too complex to go into here, these
are named *whatever*.testc instead of the more usual *whatever*.c. If
you look closely, you will see that each of those C source files maps to
a "Suite" in CUnit parlance. For example, ``cunit/glob.testc`` is listed
as the Suite "glob" in CUnit's runtime output.

Typically, each Suite tests a single module or a related set of
functions; for example, ``cunit/glob.testc`` contains tests for the glob
module in ``lib/glob.c``.

So, if you want to add a new test for a module which already has some
existing tests, the sensible thing to do is to `add a new test to the
existing suite <#adding-a-test-to-a-suite>`__. Otherwise, you'll need to
`add a new Suite <#adding-a-new-suite>`__.

4.1 Adding A New Suite
----------------------

Each Suite is a single C source file in the ``cunit/`` directory. Your
first step is to create a new C source file. For this example, you'll
create a new Suite to test the CRC32 routines which live in
``lib/crc32.c``.

::

    me@mybox> vi cunit/crc32.testc
    ...

The file should contain something like this.

::

    /* Unit test for lib/crc32.c */
    #include "cunit/cyrunit.h"  (a)
    #include "crc32.h"  (b)

    static void test_map(void)  (c)
    {
        static const char TEXT[] = "lorem ipsum";  (d)
        static uint32_t CRC32 = 0x0;
        uint32_t c;  (e)

        c = crc32_map(TEXT, sizeof(TEXT)-1);  (f)
        CU_ASSERT_EQUAL(c, CRC32);  (g)
    }

Here's an explanation of what all these bits are for.

(a)
    You need to include the header ``"cunit/cyrunit.h"``, which is a thin
    Cyrus wrapper around the CUnit's library's header,
    ``<CUnit/CUnit.h>`` with some extra conveniences.
(b)
    You should also include any headers you need for declarations of the
    functions which you'll be testing. Note that the Cyrus ``lib/`` and
    ``imap/`` directories are already in the include path, so any header
    in there can be included without the directory prefix, e.g.
    ``"crc32.h"`` for ``lib/crc32.h``.
(c)
    You need to have at least one function which looks like this: it
    takes no arguments, returns void, and is named ``test_whatever``. It
    may be ``static`` or ``extern``, but I recommend ``static``.
    Functions with this signature are automatically discovered in the
    source code by the Cyrus unit test infrastructure, so all you have
    to do is write the function. Later, a CUnit test named "whatever"
    will be created automatically for your ``test_whatever`` function.
(d)
    Here's a good place to define the test inputs and expected outputs.
    Note that for this example you have no idea of the actual correct
    output. The right thing to do there is to manually calculate the
    expected result from first principles, or to use a different piece
    of software which you believe to be working. For this example, let's
    just use a known incorrect value and see what happens.
(e)
    Here's a good place for local variables you need during the test.
(f)
    Call the function under test (``crc32_map()`` in this example) with
    known inputs, and capture the results in a local variable ``c``.
(g)
    Compare the actual result in ``c`` with the expected result in
    ``CRC32``. The ``CU_ASSERT_EQUAL()`` macro checks that it's two
    arguments are equal (using an integer comparison), and if they're
    different it prints a message and records a failure. Note that
    unlike the libc ``assert()`` macro, control will continue even if
    the assert fails. The CUnit library provides a whole family of
    similar macros, see `the online CUnit
    documentation <http://cunit.sourceforge.net/doc/writing_tests.html#assertions>`__
    for more details.

Now you need to tell the Cyrus build system about your new Suite.

::

    me@mybox> vi Makefile.am
    ...

You need to add the filename of your new test to the definition of the
``cunit_TESTS`` variable.

::

    cunit_TESTS = \
        cunit/aaa-db.testc \
        cunit/annotate.testc \
        cunit/backend.testc \
        cunit/binhex.testc \
        cunit/bitvector.testc \
        cunit/buf.testc \
        cunit/byteorder64.testc \
        cunit/charset.testc \
        cunit/crc32.testc \
        cunit/dlist.testc \
        cunit/duplicate.testc \

At this point you should be able to just rebuild and rerun using **make
check**. You can also just rebuild without rerunning by using the
command **make cunit/unit**.

Note that sometimes this doesn't quite work right, and you may be able
to work around this problem using the command **rm
cunit/default.cunit**.

::

    me@mybox> make check
    ...
    ../cunit/cunit.pl [...] --add-sources [...] crc32.testc
    ...
    ../cunit/cunit.pl [...] --generate-wrapper crc32.testc
    gcc -c [...] -g -O2 .cunit-crc32.c
    gcc [...] -o unit [...] .cunit-crc32.o ...
    Running unit tests

        CUnit - A Unit testing framework for C - Version 2.1-0
        http://cunit.sourceforge.net/

    ...
    Suite: crc32
      Test: map ... FAILED
        1. crc32.testc:12  - CU_ASSERT_EQUAL(c=1926722702,CRC32=0)

Note how the test failure told us which in source file and at what line
number the failure occurred, and what the actual and expected values
were. Let's go and fix that up now.

::

    static const char TEXT[] = "lorem ipsum";
    static uint32\_t CRC32 = 0x72d7748e;

Re-run ``make check`` and you'll see your test being rebuilt and rerun,
and this time passing.

::

    me@mybox> make check
    ...
    ../cunit/cunit.pl [...] --generate-wrapper crc32.testc
    gcc -c [...] -g -O2 .cunit-crc32.c
    gcc [...] -o unit [...] .cunit-crc32.o
    ...
    Running unit tests

        CUnit - A Unit testing framework for C - Version 2.1-0
        http://cunit.sourceforge.net/

    ...
    Suite: crc32
      Test: map ... passed

4.2 Adding A Test To A Suite
----------------------------

Adding a new test to an existing test is easy: all you have to do is add
a new function to an existing C source file in the ``cunit/`` directory.
As an example, let's add a test for the ``crc_iovec()`` function.

::

    me@mybox> vi cunit/crc32.testc
    ...

    static void test_iovec(void)  (a)
    {
        static const char TEXT1[] = "lorem";  (b)
        static const char TEXT2[] = " ipsum";
        static uint32_t CRC32 = 0x72d7748e;
        uint32_t c;  (c)
        struct iovec iov[2];

        memset(iov, 0, sizeof(iov));  (d)
        iov[0].iov_base = TEXT1;
        iov[0].iov_len = sizeof(TEXT1)-1;
        iov[1].iov_base = TEXT2;
        iov[1].iov_len = sizeof(TEXT2)-1;

        c = crc32_iovec(iov, 2);  (e)
        CU_ASSERT_EQUAL(c, CRC32);  (f)
    }

Here's an explanation of what all these bits are for.

(a)
    Your new test function should look like this: it takes no arguments,
    returns void, and is named ``test_whatever``. It may be ``static``
    or ``extern``, but I recommend ``static``. Functions with this
    signature are automatically discovered in the source code by the
    Cyrus unit test infrastructure, so all you have to do is write the
    function. Later, a CUnit test named "whatever" will be created
    automatically for your ``test_whatever`` function. Note that the
    opening curly brace must be on the next line or the unit test
    infrastructure will not find the function.
(b)
    Here's a good place to define the test inputs and expected outputs.
(c)
    Here's a good place for local variables you need during the test.
(d)
    Here you set up the input conditions for the function under test.
(e)
    Call the function under test with your known inputs, and capture the
    results in a local variable, here ``c``.
(f)
    Compare the actual result in ``c`` with the expected result in
    ``CRC32``. The ``CU_ASSERT_EQUAL()`` macro checks that it's two
    arguments are equal (using an integer comparison), and if they're
    different it prints a message and records a failure. Note that
    unlike the libc ``assert()`` macro, control will continue even if
    the assert fails. The CUnit library provides a whole family of
    similar macros, see `the online CUnit
    documentation <http://cunit.sourceforge.net/doc/writing_tests.html#assertions>`__
    for more details.

Now run ``make check`` and you'll see your test being built and run.

::

    me@mybox> make check
    ...
    ../cunit/cunit.pl [...] --generate-wrapper crc32.testc
    gcc -c [...] -g -O2 .cunit-crc32.c
    gcc [...] -o unit [...] .cunit-crc32.o
    ...
    Running unit tests


         CUnit - A Unit testing framework for C - Version 2.1-0
         http://cunit.sourceforge.net/

    ...
    Suite: crc32
      Test: map ... passed
      Test: iovec ... passed

4.3 Suite Setup And Teardown
----------------------------

Sometimes the behaviour of the functions under test depend on external
influences such as environment variables, global variables, or the
presence of certain files.

These kinds of functions need special treatment to ensure that their
behaviour is locked down during the running of your tests. Otherwise,
all sorts of strange behaviour may confuse the results of the tests. For
example, a test might succeed the first time it's run in a given
directory and fail the next time. Or a test might succeed when run by
the author of the test but fail when run by another user.

CUnit provides a special arrangement which helps you in such cases: the
suite initialisation and cleanup functions. These are two functions that
you write and which live in the suite source. They are called from CUnit
respectively before any of the tests in the suite is run, and after all
tests from that suite are run.

Here's how to use them. The suite setup function should set up any
global state that the functions under test rely on, in such a way that
their state is predictable and always the same no matter who runs the
test or when or how many times. Similarly the suite teardown function
should clean up any state which might possibly interfere with other test
suites. Note that some suites will need an setup function but not
necessarily a teardown function.

Adding these functions is very easy: you just write functions of the
appropriate signature (names, arguments and return type) and the Cyrus
unit test infrastructure will automatically discover them and arrange
for them to be called. The functions should look like (actual example
taken from ``cunit/mboxname.testc``) this:

::

    static enum enum_value old_config_virtdomains;

    static int set_up(void)
    {
        old_config_virtdomains = config_virtdomains;
        config_virtdomains = IMAP_ENUM_VIRTDOMAINS_ON;
        return 0;
    }

    static int tear_down(void)
    {
        config_virtdomains = old_config_virtdomains;
        return 0;
    }


The functions should return 0 on success, and non-zero on error. They
must not call and ``CU_*`` functions or macros.

Good luck and good testing!
