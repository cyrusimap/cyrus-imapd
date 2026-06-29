.. _developer-quickstart:

====================
How to hack on Cyrus
====================

This is the quick and dirty guide on how to hack on Cyrus.  It explains the
basics of using the developer tools to compile and test Cyrus, and it explains
how to write new tests and edit the docs.  The details of how all this works
are documented elsewhere.

Prerequisites
=============

You're going to need a clone of `the Cyrus git repository
<https://github.com/cyrusimap/cyrus-imapd/>`_.

You're going to need a way to run a container.  In other words, Docker or
another system like that.  The container you need is `cyrus-docker
<https://github.com/cyrusimap/cyrus-docker/pkgs/container/cyrus-docker>`_,
hosted on GitHub.  You generally won't need to pull that container yourself,
because you'll be using ``dar``, which will fetch the image and manage
containers for you.  You'll need perl installed, and you can fetch an
`all-in-one copy of dar
<https://github.com/cyrusimap/cyrus-docker/blob/master/fatpacked/dar>`_ to put
in your path.

That's it!  You don't need any other prerequisites, because they're all in the
container image.  If you want to develop *without* using the container image,
you can see all the things you'll need by reading the Dockerfile in the
cyrus-docker repository.

Building and testing
====================

Once you've got a checkout of cyrus-imapd.git and dar, you can build Cyrus in a
running container like this:

.. code-block:: bash

    cd cyrus-imap
    dar pull      # fetch the latest cyrus-docker image for your arch
    dar start     # start an idling container for the clone you're in
    dar build     # configure, build, check, and install Cyrus in the container
    dar test      # run the Cassandane test suite

That's it!  You've built and tested Cyrus.

To recompile (build without reconfiguring), you can run ``dar build -r``.  To
build and install without running the cunit tests, you can run ``dar build
-n``.  You can combine those with ``dar build -nr``.

To make clean in the container, you can run ``dar clean``.

To get a shell in the container, you can run ``dar sh``.  You can use ``dar run
some command with args`` to run arbitrary commands inside the container.

When you're done with the container, ``dar prune`` will destroy it.

``dar test`` is for running Cassandane tests.  Roughly speaking, each test is a
file in ``./cassandane/tiny-test/{SuiteName}`` and contains one Perl
subroutine.  Each suite has common code in a perl module file in
``./cassandane/Cassandane/Cyrus``.

If you want to run specific Cassandane tests only, you can run ``dar test
SuiteName`` or ``dar test SuiteName.prefix_*`` or ``dar test
SuiteName.exact_test_name``.

Writing tests
=============

The short version is:  tests are very easy to write, especially if you start by
copying a similar test and editing from there.  Most tests are `Cassandane
tests <developer-cassandane>`_, written in Perl, and designed to test a
complete (temporary) Cyrus install.  Some tests are tighter, focused, `cunit
tests <developer-cunit>`_ written in C.

.. TODO - flesh this out with the basics, linking to deeper docs
