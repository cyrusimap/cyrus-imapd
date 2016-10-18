.. _contribute-docs:

=============
Documentation
=============

Overview
========

Our documentation for the website is held under git source control, the same as the source. We'd love to have your contributions, which can be sent to the :ref:`mailing list <feedback>` or you can submit a patch directly against the source.

Our helpfile source uses Sphinx_ and `Restructured Text`_.

While editing the documentation can take place in any text editor, you'll need tools to fetch the source, generate man pages and html for testing and tools to submit your updates via Arcanist.

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

To support Arcanist 

* php5-cli
* php5-curl

Checking the files
==================
    
For a full-fledged test generating Sphinx output, run::

    make clean init man html
    
from the checkout directory and look at the results. This generates the manpages and the html files.

Run make with no arguments for a list of available output targets.

Submitting updates
==================

Using Phabricator/Arcanist
--------------------------

This assumes you aren't a member of the `Documentation Committers`_ group on Phabricator_ and thus are subject to a mandatory review step by the `Documentation Reviewers`_ group.

1. Take ownership of a Maniphest_ task (or create a new task). You'll need a Phabricator_ account to do this.
2. Clone the source
3. Make a new branch (either via ``git checkout -b`` or using ``arc feature``)
4. Code code test test test code code test test test.
5. Use git to commit your changes.
6. When you are ready to submit your changes to a Differential

    * use: ``arc diff`` to commit to origin/master, or ``arc diff <branch>`` to commit to an alternate branch.
    * Various checks take place, after which you are requested to provide some details about your proposed changes. Please fill out in detail as this will help speedy review and acceptance of your change.
    * For changes to Documentation, the reviewers section should be set to #Documentation_Reviewers.
    * It is important to note that arc does not allow you to specify, as part of the commit message, whether or not your diff depends on any other existing diffs.

7. Wait for review (a quick note to the mailing list can speed this along)
8. Once approved, it'll be merged into the master.

Reviewing Code
##############

Reviewing Differential revisions is a job for volunteer members of the `Documentation Reviewers`_ projects. Only those people that have direct commit access are eligible to become a reviewer (because otherwise the process doesn't work).

When a reviewer initially starts review, they execute ``arc patch D5``. This gets Arcanist to checkout a branch arcpatch-D5 (or a variant of that name, such as arcpatch-D5_1 if arcpatch-D5 already existed) and the changeset for the revision is applied.

The reviewer examines and comments on the related Differential revision. If the change is to be accepted, the reviewer must set the Differential to 'Accepted'. This allows the diff to be landed.

| For changes to be applied to master: ``arc land arcpatch-D5``
| For changes to apply on another branch: ``arc land arcpatch-D5 --onto cyrus-imapd-2.4``

Patches through the mailing list
--------------------------------
If you're not planning on regularly submitting changes, you can just send your patch through to the mailing list and one of the regular maintainers will see about incorporating it.

.. _Documentation Committers: https://git.cyrus.foundation/tag/documentation_committers/
.. _IMAP Reviewers: https://git.cyrus.foundation/tag/imap_reviewers/
.. _SASL Reviewers: https://git.cyrus.foundation/tag/sasl_reviewers/
.. _Documentation Reviewers: https://git.cyrus.foundation/tag/documentation_reviewers/
.. _Maniphest: https://git.cyrus.foundation/maniphest/
.. _Phabricator: https://git.cyrus.foundation/
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
    
