.. _contribute-docs:

=============
Documentation
=============

Overview
========

Our documentation for the website is held under git source control, the same as the source. We'd love to have your contributions, which can be sent to the :ref:`mailing list <feedback-mailing-lists>` or you can submit a patch directly against the source.

Our helpfile source uses Sphinx_ and `Restructured Text`_.

While editing the documentation can take place in any text editor, you'll need tools to fetch the source, generate man pages and html for testing.

Documentation Tools
===================

For basic reStructured Text operations, we are using Sphinx version 1.3.6:

* python-sphinx
* python-sphinxcontrib-programoutput
* python-sphinxcontrib.actdiag
* python-sphinxcontrib.blockdiag
* python-sphinxcontrib.nwdiag
* python-sphinxcontrib.phpdomain
* python-sphinxcontrib.seqdiag
* python-sphinxcontrib.spelling

You will need the `gitpython <https://gitpython.readthedocs.io/en/stable/>`_
python package for performing datestamp operations:

* gitpython

You will also need the perl package, which is used to build some docs from their Perl source:

* Pod::POM::View::Restructured

For editing and preview

* `geany <http://www.geany.org>`_
    * Has a full feature set
    * Minimal syntax highlighting for .rst files.

* `retext <http://sourceforge.net/projects/retext>`_ (`Windows install instructions <http://sourceforge.net/p/retext/wiki/Windows%20Install%20of%20ReText/>`_)
    * Built-in preview mode.
    * Struggles with templates

* or any text editor
    * No preview capability
    * Some editors have syntax highlighting support for .rst files.

For interaction with the repositories

* git
* git-stuff

Building the files
==================

The best way to build the documentation is to use the toplevel Makefile (generated as part of
:ref:`building the source <compiling>`)::

    make doc

This runs ``make doc-html doc-text man`` and places the relevant output in ``doc/html/``, ``doc/text/`` and ``man/`` directories.

If you don't have a full source build environment and just want to manage the documentation
on its own, from the `docsrc/`` directory run::

    make clean init man html

This generates the manpages and the html files. The results are in ``build``.

Run ``make`` with no arguments for a list of available output targets.

Submitting updates
==================

Using GitHub pull requests
--------------------------

We operate on the GitHub fork/pull model. We'd love to have your pull request come through!

If you're new to GitHub or the fork/pull model, we have a :ref:`Quick GitHub guide <github-guide>` to get you going.

Patches through the mailing list
--------------------------------
If you're not planning on regularly submitting changes, you can just send your patch through to the :ref:`mailing list <feedback-mailing-lists>` and one of the regular maintainers will incorporate it.

.. _Sphinx: http://sphinx-doc.org
.. _Restructured Text: http://docutils.sourceforge.net/rst.html

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

    Conventional section names include NAME, SYNOPSIS, CONFIGURATION, DESCRIPTION, OPTIONS, EXIT STATUS, RETURN VALUE, ERRORS, ENVIRONMENT, FILES, VERSIONS, CONFORMING TO, NOTES, BUGS, EXAMPLE, AUTHORS, and SEE ALSO. The following conventions apply to the SYNOPSIS section and can be used as a guide in other sections.

| **bold text** - type exactly as shown.
| *italic text*	- replace with appropriate argument.
| [-abc]	- any or all arguments within [ ] are optional.
| -a|-b	- options delimited by | cannot be used together.
| argument ... - argument is repeatable.
| [expression] ... - entire expression within [ ] is repeatable.

.. note::

    Exact rendering may vary depending on the output device. For instance, man will usually not be able to render italics when running in a terminal, and will typically use underlined or coloured text instead. The command or function illustration is a pattern that should match all possible invocations. In some cases it is advisable to illustrate several exclusive invocations as is shown in the SYNOPSIS section of this manual page.

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

In order to preserve space in traditional man page output, we're using the ``.. only:: html`` directive in the reStructured Text (.rst) files for the verbose output of the Examples for commands.

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
