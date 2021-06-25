.. _devprocess:

===================
Development Process
===================

We need to develop not just for ourselves, but for those who follow us. This means following good development process to provide transparency, maintainability and readability to what we're doing.

Coding Style
============

* Unix style: CRLF line endings.
* No trailing spaces.
* No tabs: use 4 spaces instead.
* Bracketing style: use the style that's already there.
* You are not a compiler: code for readability, not compactness.
* We are open source: coding security-by-obscurity is not necessary. Use semantically sensible function and variable names.
* Comments. More comments. Still more comments. Nobody will know what your brilliant idea was when you wrote that gnarly piece of code unless you tell them.
* Commit messages. Commit discrete changes, don't munge six different fixes into a single commit. And provide a clear message (preferably tied into a GitHub issue) of what problem these changes address.


Making changes
==============

Before you begin
----------------

Found a bug? Got an enhancement? Great!

New Feature considerations: this is an open source project. If your change isn't a basic part of what is already planned, will you be around to support it? Can you justify why it's in the best interests of the project to have your change included? We'd love to talk it through with you: contact us via the :ref:`mailing lists <feedback-mailing-lists>`.

Using GitHub
------------

First, check out our :ref:`Guide to GitHub <github-guide>`, which covers:

1. Create a GitHub account.
2. Fork the repository.
3. Clone the fork.
4. Branch the clone.

From there, you:

1. Take ownership of a GitHub issue (or create a new one to cover what you're planning to do).
2. Code code :ref:`test test test <developer-testing>` code code test test test.
3. Use git to commit your changes.
4. Issue a :ref:`pull request <github-guide-pull>` on GitHub.
5. Wait for review (a quick note to the mailing list can speed this along).
6. Once approved, it'll be merged into the master.

Patches through the mailing list
--------------------------------
If you're not planning on regularly submitting changes, you can just send your patch through to the mailing list and one of the regular maintainers will see about incorporating it.

Useful Developer Information
============================

Some combined :ref:`tips on developing with Cyrus <imap-developer-guidance>` have been collected.

Community Participation
=======================

Join us! The project is only as good as the sum of its people. We all work together, despite the tyranny of distance and timezones.

Meetings are currently :ref:`held online via Zoom <feedback-meetings>`.

There's also :ref:`mailing lists <support>`.
