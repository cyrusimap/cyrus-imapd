.. _coverage:

=============
Test Coverage
=============

This assumes you have a single user development environment where you can
already build and install Cyrus, and run the CUnit and Cassandane tests.  It
also assumes your Cyrus install and Cassandane setup do not use "destdir",
and that your compiler is GCC.

We'll be tinkering with group membership and file permissions, so proceed
with caution on multi-user systems.

When a coverage-enabled binary runs, it writes coverage data into ``foo.gcda``
files alongside the source files.  CUnit runs as you, but Cassandane runs as
cyrus, so we need to arrange for both these users to be able to write to the
source directory.  We'll do that using group memberships and the
group-writeable file mode bit.

One-time setup
==============

Group membership
----------------

1. Add the "cyrus" user account to your own user group
2. Perhaps: also add your user account to the "cyrus" user's group.  This might
   be "cyrus" or "mail" depending on how you set your system up.  I can't
   remember if this is actually necessary for coverage, or if I have it for
   something else, so skip it unless it becomes necessary (and update this
   doc!)

File permissions
----------------

1. Change into your cyrus-imapd directory: ``cd ~/path/to/cyrus-imapd``
2. Start from a clean state: ``git clean -xfd``
3. Set the group-writeable bit on everything: ``chmod -R g+w .``
4. Allow the group-writeable bit on new files you create: ``umask 0002``
5. Add that ``umask 0002`` line to your .bashrc or equivalent too, otherwise
   you'll have to remember to fix up file permissions every time you want to
   make a coverage report

Dependencies
------------

You'll need the ``lcov`` and ``genhtml`` tools for producing human-readable
reports.  On Debian, these are both found in the ``lcov`` package.

Preparing a coverage report
===========================

Compile Cyrus and run CUnit tests
---------------------------------

The collection of coverage data slows things down, and it might also log a lot
of complaints about overwriting old coverage data, or being unable to.  So I
do not recommend routinely compiling with coverage enabled -- only do this when
you're preparing a coverage report.

1. Change into your cyrus-imapd directory: ``cd ~/path/to/cyrus-imapd``
2. Start from a clean state: ``git clean -xfd``
3. Configure Cyrus, using your usual configure options, plus
   ``--enable-coverage``
4. Compile Cyrus: ``make -j4``
5. Run the CUnit tests: ``make -j4 check``
6. Install Cyrus (might need sudo): ``make install``

Run Cassandane
--------------

1. Run Cassandane on the installed Cyrus as you usually would

Generate report
---------------

I'd suggest making a script to automate this part.  I use one like `this
<https://github.com/elliefm/cyrus-build-tools/blob/master/cyrus-coverage>`_

1. Change into your cyrus-imapd directory: ``cd ~/path/to/cyrus-imapd``
2. Some of the ``foo.gcda`` files will be owned by your user (from the CUnit
   run), some will be owned by the cyrus user (from the Cassandane run).
   You can use something like this to reclaim the ownership (if your user:group
   is ellie:ellie)::

      find . -name \*.gcda -not -user ellie -execdir sudo chown ellie:ellie "{}" +

3. If you want to keep accumulating results, you'll need to ensure the Cyrus
   user can still write to those files.  I don't know if this is useful, but
   something like this will do it:
   ``find . -name \*.gcda -execdir chmod g+rw "{}" +``
4. Process all those ``foo.gcda`` files into an intermediate form:
   ``lcov --directory . -c -o coverage.info``
5. Strip out unit test and external library clutter:
   ``lcov --remove coverage.info "cunit/*" "/usr/*" -o coverage.info``
6. Generate HTML:
   ``genhtml -o coverage coverage.info``
7. You can now open that report in your browser.  Something like this will
   give you a link to copy and paste:
   ``echo file://$PWD/coverage/index.html``
