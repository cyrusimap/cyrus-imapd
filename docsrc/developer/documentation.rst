.. _contribute-docs:

=============
Documentation
=============

Overview
========

The best way to test changes to our documentation is to use the :ref:`dar
makedocs <cyd-and-dar>` command from your local git clone.  That build is
nitpicky and treats warnings as errors, exactly as CI does, so a
cross-reference to a target that doesn't exist fails the build instead of being
quietly rendered as plain text.  If ``dar makedocs`` is clean, CI will be too.

The best way to submit changes to our documentation is via a GitHub pull
request.

Source formats
--------------

Our documentation is built with `Sphinx <https://sphinx-doc.org>`_.  Pages may
be written either in `reStructuredText
<https://docutils.sourceforge.net/rst.html>`_ or in Markdown, which is parsed
by `MyST <https://myst-parser.readthedocs.io/>`_.  Most existing pages are
reST, for historical reasons; for a *new* page, prefer Markdown.

Of the MyST extensions, only ``substitution`` is enabled, so a Markdown page
can use the replacement tags described below but not all the rest of MyST
syntax.  The Cyrus-specific roles are reST roles: in Markdown you write them
with MyST's role syntax rather than the reST backtick form.

Generated pages
---------------

Some pages in ``docsrc`` don't exist until you build.  They're gitignored build
artifacts.  When you're editing the docs, make sure you're editing a tracked
file, or you might later realize that your work was pointless.

Most notably:

``developer/cassandane-api/``
    One page per Cassandane module with embedded Pod, plus the listing that
    :ref:`the Cassandane page <developer-cassandane>` includes.  The module
    list is discovered at build time -- every module with an ``=head`` line is
    published -- so adding Pod to a Cassandane module is all it takes to get
    it onto the site.

Special Tags
============

Our Sphinx setup has a few additional tags that are of note.

rfc
---

In HTML output, this generates a link to the referenced document.

Usage: ``:rfc:`<number>```

Example: ``:rfc:`3501``` produces :rfc:`3501`.

cyrusman
--------

In HTML output, this generates an internal link to the referenced man page.

Currently we support sections 1, 5 and 8. These look for their man pages in the *commands* (1,8) and *config* (5) directories within the source.

Usage: ``:cyrusman:`<command>(<section>)``` or ``:cyrusman:`<configfile>.conf(5)```

Example: ``:cyrusman:`imapd.conf(5)``` produces :cyrusman:`imapd.conf(5)`.

imap_current_stable_version
---------------------------

This is a replacement tag and will output the current stable version number defined in conf.py.

Usage: ``|imap_current_stable_version|``

Produces |imap_current_stable_version|.

Conventions: Man Pages
======================

For Unix manual, or "man" pages, we follow the conventions laid out in the man page for man(1) itself:

.. note::

    Conventional section names include NAME, SYNOPSIS, CONFIGURATION,
    DESCRIPTION, OPTIONS, EXIT STATUS, RETURN VALUE, ERRORS, ENVIRONMENT,
    FILES, VERSIONS, CONFORMING TO, NOTES, BUGS, EXAMPLE, AUTHORS, and SEE
    ALSO. The following conventions apply to the SYNOPSIS section and can be
    used as a guide in other sections.

**bold text**
    type exactly as shown.

*italic text*
    replace with appropriate argument.

[-abc]
    any or all arguments within [ ] are optional.

-a|-b
    options delimited by | cannot be used together.

argument ...
    argument is repeatable.

[expression] ...
    entire expression within [ ] is repeatable.

Synopsis
--------

In reStructured Text, this means a SYNOPSIS section might look like this::

    Synopsis
    ========

        **ipurge** [ **-f** ] [ **-C** *config-file* ] [ **-x** ] [ **-X** ] [ **-i** ] [ **-s** ] [ **-o** ]
                [ **-d** *days* | **-b** *bytes* | **-k** *Kbytes* | **-m** *Mbytes* ]
                [ *mailbox-pattern*... ]

Rendering output like this:

SYNOPSIS

**ipurge** [ **-f** ] [ **-C** *config-file* ] [ **-x** ] [ **-X** ] [ **-i** ] [ **-s** ] [ **-o** ] [ **-d** *days* | **-b** *bytes* | **-k** *Kbytes* | **-m** *Mbytes* ] [ *mailbox-pattern*... ]

Examples
--------

In order to preserve space in traditional man page output, we use the ``..
only:: html`` directive in the reStructured Text (.rst) files for the verbose
output of the Examples for commands.

For example, this is good, and follows the style of the man(8) manpage::

    Examples
    ========

    **arbitron -o**

    ..

    Old format (no subscribers) short list.

    .. only:: html

        tech.Commits 0
        tech.Commits.archive 0

    **arbitron -d** *14*

    ..

    Normal short list format for the past *14* days.

    .. only:: html

        tech.Commits 0 2
        tech.Commits.archive 0 4

The output would render like so in a manpage:

EXAMPLES

| **arbitron -o**
| Old format (no subscribers) short list.

.. only:: html

::

    tech.Commits 0
    tech.Commits.archive 0

| **arbitron -d** *14*
| Normal short list format for the past *14* days.

.. only:: html

::

    tech.Commits 0 2
    tech.Commits.archive 0 4
