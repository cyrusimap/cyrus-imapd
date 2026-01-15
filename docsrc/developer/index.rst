.. _imap-developer:

===================
Developer Resources
===================

We want it to be easy to contribute to Cyrus, whether it's documentation
improvements, bug fixes, new features, or optimizations.

The contribution guidelines below outline the process that you'll need to
follow to get a code patch merged. By making expectations and process explicit,
we hope to make it easier for you to contribute.

Getting Started
===============

.. toctree::
    :maxdepth: 1

    process
    overview
    compiling
    /installing
    developer-testing
    coverage
    jmap

.. toctree::
    :hidden:

    install-xapian

Contributing
============

.. toctree::
    :maxdepth: 1

    Contributing to the documentation <documentation>
    Documentation style guide </styles>
    The CUnit (C) test suite <cunit>
    The Cassandane (Perl) test suite <cassandane>

Cyrus Internals
===============

These documents are intended for persons interested in contributing to
the Cyrus IMAP development effort, or for those interested in lower-level
details about how Cyrus is implemented.

.. toctree::
    :maxdepth: 1

    namespaces
    libraries
    Cyrus APIs <API>
    Thoughts & Notes <thoughts>
    Guidance for Developers <guidance>

This :download:`diagram <images/master-state-machine.svg>` shows
the Master State Machine.

Releasing
=========

.. toctree::
    :maxdepth: 1

    releasing
    major-releasing
    snapshot-releasing
