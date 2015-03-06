.. _imap-developer-docker-images:

=============
Docker Images
=============

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

Running the Tests Yourself
==========================

.. parsed-literal::

    $ :command:`docker run -ti cyrusimapd/heisenbug`

.. NOTE::

    Aside from specifying a ``PHAB_CERT`` environment variable, this is
    how tests are run when they result in a comment or concern on a
    commit.

Getting an Interactive Shell
============================

.. parsed-literal::

    $ :command:`docker run -ti --entrypoint="/bin/bash" cyrusimapd/heisenbug -s`

This will give you an interactive shell.

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
:ref:`imap-developer-make-pre-configure-fails`.

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

.. _Conduit: https://git.cyrus.foundation/settings/panel/conduit/
.. _Differential: https://git.cyrus.foundation/differential/
.. _Diffusion: https://git.cyrus.foundation/diffusion/
.. _Dr. Jenkins: https://git.cyrus.foundation/p/jenkins/
