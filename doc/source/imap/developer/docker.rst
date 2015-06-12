.. _imap-developer-docker-images:

=============
Docker Images
=============

The Cyrus IMAP uses Docker images for testing builds and performing unit
tests for, at the time of this writing, 13 (releases of) Linux
distributions.

The images are configured to start running tests automatically (i.e.
they have an *entrypoint*). To get an interactive shell, see
:ref:`imap-developer-docker-images-interactive-shell`.

The results of the tests are posted to our `Phabricator`_ instance as
comments to commits, or raise a concern (which in turn becomes an
`Audit`_ request).

When `Dr. Jenkins`_ raises a concern with a commit, she intends to raise
awareness over builds failing.

The current state of the tree is compared to the last state of the tree
using the *parent* of the *current* commit.

*   If a step in *current* fails, but the *parent* also fails,
    `Dr. Jenkins`_ will only leave a comment -- with one exception;

    If :ref:`imap-developer-docker-images-make-relaxed` fails, checking
    the parent is irrelevant, and a concern is raised -- triggering an
    audit.

*   If a step in *current* fails, but it does not fail in the *parent*,
    it is likely the commit broke the build (or that the `Dr. Jenkins`
    script does not work). This raises a concern too.

Quick Notes
===========

*   If the environment variables ``PHAB_CERT`` and ``PHAB_USER`` are
    specified, Arcanist is installed and configured.

    This enables you to run through a debugging session on a specific
    platform, interacting with, for example, `Differential`_ or
    `Diffusion`_ at https://git.cyrus.foundation.

    You can obtain your certificate, which is a very long string, from
    Phabricator's `Conduit`_.

*   To apply a Differential revision regardless, specify the
    ``DIFFERENTIAL`` environment variable.

    .. NOTE::

        Do not specify the ``D`` in the variable, just the number.

*   The images come with **vim** pre-installed and pre-configured to:

    #.  Remember the last position in a file you've opened,

    #.  Employ syntax highlighting,

    #.  Apply the current latest indentation policy for Cyrus IMAP.

*   In an interactive shell, ``PROMPT_COMMAND`` is set to have the
    terminal window you have open reflect the name of the image you are
    running and running multiple of them is not just a bunch of windows
    titled with container IDs.

Environment Variables
=====================

``COMMIT``

    More commonly referred to as a *git ref*, the ``COMMIT`` environment
    variable is used to issue a ``git checkout ${COMMIT}`` with.

    **Examples:**

    Run against ``HEAD`` of the ``cyrus-imapd-2.5`` branch:

    .. parsed-literal::

        $ :command:`docker run -it -e "COMMIT=cyrus-imapd-2.5" \\
            cyrusimapd/maipo`

    .. IMPORTANT::

        The images and scripts do not currently support Cyrus IMAP
        versions prior to 2.5.0.

``CONFIGURE_OPTS``

    Use the options specified to run ``./configure``, rather then the
    default configure options.

    **Examples:**

    #.  Test with a yet unknown configure option added by a
        `Differential`_ revision (don't forget to also set the
        ``DIFFERENTIAL`` environment variable):

        .. parsed-literal::

            $ :command:`docker run -it -e "CONFIGURE_OPTS=--enable-ceph" \\
                cyrusimapd/maipo`

    #.  Test an option that is otherwise known to fail:

        .. parsed-literal::

            $ :command:`docker run -it -e "CONFIGURE_OPTS=--with-openssl=no" \\
                cyrusimapd/wheezy`

``DIFFERENTIAL``

    Before running anything, apply the `Differential`_ revision
    specified.

    .. NOTE::

        Only specify the number, not the ``D`` prefix.

    **Examples:**

    Test a `Differential`_ revision:

    .. parsed-literal::

        $ :command:`docker run -it -e "DIFFERENTIAL=9" \\
            cyrusimapd/santiago`

``PHAB_CERT``

``PHAB_USER``

Future Environment Variables
----------------------------

``BUILD_ID``

    We intend to run the Docker containers as part of the
    `Harbormaster`_ and `DryDock`_ applications in `Phabricator`_, for
    the purposes of continuous integration -- rather than comment on
    commits individually.

``TICKET``

    Report to a `Maniphest`_ ticket rather than the `Diffusion`_ commit.

Running the Tests Yourself
==========================

.. parsed-literal::

    $ :command:`docker run -ti cyrusimapd/heisenbug`

.. NOTE::

    Aside from specifying a ``PHAB_CERT`` environment variable, this is
    how tests are run when they result in a comment or concern on a
    commit.

.. _imap-developer-docker-images-interactive-shell:

Getting an Interactive Shell
============================

.. parsed-literal::

    $ :command:`docker run -ti --entrypoint="/bin/bash" cyrusimapd/heisenbug -s`

This will give you an interactive shell.

The images are configured with an entry point of :file:`/entrypoint.sh`,
so maybe you want to execute that.

Functions for Your Convenience
==============================

Functions are pulled from :file:`/entrypoint.sh` so you can
:command:`source /functions.sh` which gives you the following commands:

``_make_relaxed``

    This command configures the build with relaxed ``CFLAGS``, as
    opposed to ``-g -Wall -Wextra -Werror``.

``_make_strict``

    This command configures the build with strict ``CFLAGS``, turning
    all warnings to errors: ``-g -Wall -Wextra -Werror``.

Build Process Steps
===================

``./configure`` (maintainer mode)
---------------------------------

If the ``CONFIGURE_OPTS`` environment variable has been specified, the
following commands are run automatically:

.. parsed-literal::

    $ :command:`./configure --enable-maintainer-mode`
    $ :command:`make \\
        imap/rfc822_header.c \\
        imap/rfc822_header.h`

These *should* not fail, but if they do, it's probably your fault. See
:ref:`imap-developer-pre-configure-fails`.

.. NOTE::

    If ``CONFIGURE_OPTS`` is not specified, then
    :ref:`imap-developer-docker-images-configure-for-real` takes care of
    specifying the required ``--enable-maintainer-mode`` option.

.. _imap-developer-docker-images-configure-for-real:

``./configure`` (for real)
--------------------------

Configure is run for real, using either the defined ``CONFIGURE_OPTS``
or a default of (at the time of this writing):

.. parsed-literal::

    ./configure \\
        --enable-autocreate \\
        --enable-coverage \\
        --enable-gssapi \\
        --enable-http \\
        --enable-idled \\
        --enable-maintainer-mode \\
        --enable-murder \\
        --enable-nntp \\
        --enable-replication \\
        --enable-unit-tests \\
        --with-ldap=/usr

If the second run of ``./configure`` fails for whatever reason, the
script checks out the *parent* of the *current* commit and tries again.

.. _imap-developer-docker-images-make-relaxed:

``make`` (relaxed)
------------------

The first run of ``make`` is *relaxed*, meaning that ``CFLAGS`` are
default.

``make`` (strict)
-----------------

The second run of ``make`` is *strict*, meaning that ``CFLAGS`` are
default.

``make check``
--------------

Execute the CUnit tests in ``cunit.``.

.. _Audit: https://git.cyrus.foundation/audit/
.. _Conduit: https://git.cyrus.foundation/settings/panel/conduit/
.. _Differential: https://git.cyrus.foundation/differential/
.. _Diffusion: https://git.cyrus.foundation/diffusion/
.. _Dr. Jenkins: https://git.cyrus.foundation/p/jenkins/
.. _DryDock: https://git.cyrus.foundation/drydock/
.. _Harbormaster: https://git.cyrus.foundation/harbormaster/
.. _Maniphest: https://git.cyrus.foundation/maniphest/
.. _Phabricator: https://git.cyrus.foundation/
