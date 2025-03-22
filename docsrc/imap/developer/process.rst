.. _devprocess:

===================
Development Process
===================

We need to develop not just for ourselves, but for those who follow us. This means following good development process to provide transparency, maintainability and readability to what we're doing.

Coding Style
============

* Unix style: LF line endings.
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

New Feature considerations: this is an open source project. If your change
isn't a basic part of what is already planned, will you be around to support
it? Can you justify why it's in the best interests of the project to have your
change included? We'd love to talk it through with you: contact us via the
:ref:`mailing lists <feedback-mailing-lists>`.

When you want to submit your change for the core team's consideration, you'll
need to make a GitHub pull request.  Explaining GitHub is out of scope for this
document, but the short version is: Cyrus isn't doing anything weird with its
use of GitHub, and you can file a pull request as usual.  Be sure to note, in
it, the issue number of any issue the pull request will close.

The Cyrus core team reviews new pull requests regularly, but sometimes there's
a bit of a backlog, or things slip through the cracks.  If you haven't heard
back in two weeks, consider contacting us on the ``cyrus-devel`` mailing list.

Useful Developer Information
============================

Some combined :ref:`tips on developing with Cyrus <imap-developer-guidance>` have been collected.

Community Participation
=======================

Join us! The project is only as good as the sum of its people. We all work
together, despite the tyranny of distance and timezones.

Meetings are currently :ref:`held online via Zoom <feedback-meetings>`.

…and don't forget about the :ref:`mailing lists <support>`.
