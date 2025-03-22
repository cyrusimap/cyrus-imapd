.. _cyd-and-dar:

=========================================
Overview of Cyrus development environment
=========================================

This page details the tools we use to make Cyrus development easy.  Check out
our :ref:`development process <devprocess>` for a guide on how to contribute
your changes to the community.

cyrus-docker, cyd, and dar
==========================

The simplest way to hack on Cyrus IMAP is to use the Cyrus IMAP Docker image
and the related development tools.  It's possible to develop and test without
Docker, of course, but it's a more tedious process.  If you want to do that,
you should probably read this document, then go read the source code for all
the tools described.  For now, here's the easy way!

The Cyrus team maintains
`cyrus-docker <https://github.com/cyrusimap/cyrus-docker>`_, a Docker image
meant to make Cyrus development easy.  It's what we use for automated test runs
and it's also useful for local development.  In general, you won't need to
build your own image.  We produce a new image nightly, and the ``dar`` tool
will pull it down for you.  The Docker image contains everything you should
need for building and testing Cyrus.  It's based on Debian, but has
pre-installed versions of libraries that Debian doesn't provide, or that aren't
recent enough in Debian.

The image is published to the GitHub Container Repository, *not* Docker Hub.
You can find it at
`<https://github.com/cyrusimap/cyrus-docker/pkgs/container/cyrus-docker>`_.

The Docker image also includes ``cyd``, the inside-the-container development
tool.  ``cyd`` provides commands to run *inside* the container.  In day to day
development, you'll probably want to work *outside* the container, and that's
what ``dar`` is for.  For the sake of clarity, we're going to explain ``cyd``
first, then ``dar``.

cyd
---

``cyd`` is short for "Cyrus Development".  It's a program inside the Cyrus
docker image, and you can run it with ``docker run``.  It's got a number of
subcommand, like ``git``, and you'll always want to specify which one you want
to run.  For example, this command line will start a container using the Cyrus
docker image and running an interactive shell::

    docker run -ti cyd sh

The shell command runs a shell, but also prints a menu of (some) available
commands, something like this::

              /////  |||| Cyrus IMAP docker image
            /////    |||| Run cyrus-docker (or "cyd") as:
          /////      ||||
        /////        ||||  • cyd clone  - clone cyrus-imapd.git from GitHub
      /////          ||||  • cyd build  - build your checked out cyrus-imapd
      \\\\\          ||||  • cyd test   - run the cyrus-imapd test suite
        \\\\\        ||||  • cyd smoke  - check out, build and test
          \\\\\      ||||
            \\\\\    ||||  • cyd shell  - run a shell in the container
              \\\\\  ||||

Once you're in the shell, those next three commands are probably what you want
to run.

1.  ``cyd clone`` will clone the current development branch of cyrus-imap.git to
    ``/srv/cyrus-imapd``.  If that directory already exists, clone does
    nothing.

2.  ``cyd build`` will configure, build, and install Cyrus.

3.  ``cyd test`` will run the Cassandane test suite against the just-built
    Cyrus.

Most ``cyd`` commands take optional switches and arguments.  For help on a
command, you can run ``cyd help COMMAND``.

The fourth command listed above, ``cyd smoke``, is a shortcut to clone, build,
and test.  The other command you might want to run is ``cyd makedocs``, which
will build the Cyrus documentation website, putting the built files at
``/srv/cyrus-imapd/docsrc/build/html``.

dar
---

Developing with just Docker and ``cyd`` is possible, but can be a pain.  You
won't have your ssh credentials, so you can't push changes back up.  You'll be
logged in a root, and you won't have your editor configuration.  To make
development with Docker and ``cyd`` more streamlined, we've written ``dar``.

``dar`` runs ``cyd`` commands inside of a container, which it manages for you.
It expects that you'll run it from inside a git clone of the Cyrus repository.
To get started with ``dar`` you'll want to:

1.  clone the `Cyrus repository
    <https://github.com/cyrusimap/cyrus-imapd.git>`_ and chdir into it

2.  run ``dar smoke`` to build the Cyrus you've got checked out and then run
    the tests

If you try this, though, it won't work.  First, you'll be told to run ``dar
pull``, which will pull the Docker image for your platform.  You *need* to run
this at least once, unless you've already fetched the image by hand.  You *can*
run it more often, to check that you're up to date.  In general, there's a new
build of the Cyrus Docker image daily.

After pulling the image, the smoke command will still fail, this time because
you don't have a running container.  The error will tell you to run ``dar
start``, which will start a container for this checkout.  The container will be
running ``cyd idle``, a stub program that just keeps the container running.
From there on, you'll use ``dar`` like you would've used ``cyd``, but from
outside the container.  If you've been working on changes to the JMAP
SieveScripts feature, for example, you might reach a stopping point and run::

    dar build && dar test JMAPSieve

Cyrus will be built using your local source (even if uncommitted) and then the
JMAPSieve test suite will be run.  When they've finished, you'll be back at
your local shell.  If you need to go debug a stack trace or Cassandane output,
you can use ``dar sh`` to get a shell inside the container.

When you're all done, or when you've accidentally done something to ruin or
compromise the container, you can run ``dar prune`` to stop the container and
remove it.  Stopping and removing the container can take a little while, if
you've built up a lot of test output.

``dar`` works by mounting your git checkout into the container where the source
is expected.  When you build, you'll be building into that directory, meaning a
directory on your local machine.  This means you'll send up with `foo.o` files
in your working tree, and they'll be owned by the root user.  ``dar clean``
will clean all this up, but if you've already pruned your container, you'll
need to clean up by hand.  If you're confident you've committed everything you
need to commit, ``sudo git clean -dfx`` should do the trick.

