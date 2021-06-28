.. _devprocess:

===================
Development Process
===================

We need to develop not just for ourselves, but for the legions who follow us. This means following good development process to provide transparency, maintainability and readability to what we're doing.

Coding Style
============

* Unix style: CRLF line endings
* No trailing spaces.
* No tabs: use 4 spaces instead.
* Bracketing style: use the style that's already there.
* You are not a compiler: code for readability, not compactness.
* We are open source: coding security-by-obscurity is not necessary. Use semantically sensible function and variable names.
* Comments. More comments. Still more comments. Nobody will know what your brilliant idea was when you wrote that gnarly piece of code unless you tell them.
* Commit messages. Commit discrete changes, don't munge six different fixes into a single commit. And provide a clear message (preferably tied into a Maniphest task/Differential diff) of what problem these changes address.


Making changes
==============

Before you begin
----------------

Found a bug? Got an enhancement? Great!

Something to consider before you leap in with a new feature: this is an open source project. If your change isn't a basic part of what is already planned, will you be around to support it? Can you justify why it's in the best interests of the project to have your change included? We'd love to talk it through with you: contact us via the :ref:`mailing lists <feedback>`.

Using Phabricator/Arcanist
--------------------------

This assumes you aren't a member of the `IMAP Committers`_ group on Phabricator_ and thus are subject to a mandatory review step by the `IMAP Reviewers`_ group.

1. Take ownership of a Maniphest_ task (or create a new task). You'll need a Phabricator_ account to do this.
2. Clone the source
3. Make a new branch (either via ``git checkout -b`` or using ``arc feature``)
4. Code code test test test code code test test test.
5. Use git to commit your changes.
6. When you are ready to submit your changes to a Differential
    * use: ``arc diff`` to commit to origin/master, or ``arc diff <branch>`` to commit to an alternate branch.
    * Various checks take place, after which you are requested to provide some details about your proposed changes. Please fill out in detail as this will help speedy review and acceptance of your change.
    * For changes to IMAP, the reviewers section should be set to #IMAP_Reviewers,
    * For changes to SASL, the reviewers section should be set to #SASL_Reviewers, and
    * For changes to Documentation, the reviewers section should be set to... you guessed it... #Documentation_Reviewers.
    * It is important to note that arc does not allow you to specify, as part of the commit message, whether or not your diff depends on any other existing diffs.

7. Wait for review (a quick note to the mailing list can speed this along)
8. Once approved, it'll be merged into the master.

Reviewing Code
##############

Reviewing Differential revisions is a job for volunteer members of the `IMAP Reviewers`_, `SASL Reviewers`_ and/or `Documentation Reviewers`_ projects. Only those people that have direct commit access are eligible to become a reviewer (because otherwise the process doesn't work).

When a reviewer initially starts review, they execute ``arc patch D5``. This gets Arcanist to checkout a branch arcpatch-D5 (or a variant of that name, such as arcpatch-D5_1 if arcpatch-D5 already existed) and the changeset for the revision is applied.

The reviewer examines and comments on the related Differential revision. If the change is to be accepted, the reviewer must set the Differential to 'Accepted'. This allows the diff to be landed.

| For changes to be applied to master: ``arc land arcpatch-D5``
| For changes to apply on another branch: ``arc land arcpatch-D5 --onto cyrus-imapd-2.4``

Patches through the mailing list
--------------------------------
If you're not planning on regularly submitting changes, you can just send your patch through to the mailing list and one of the regular maintainers will see about incorporating it.

.. _IMAP Committers: https://git.cyrus.foundation/tag/imap_committers/
.. _IMAP Reviewers: https://git.cyrus.foundation/tag/imap_reviewers/
.. _SASL Reviewers: https://git.cyrus.foundation/tag/sasl_reviewers/
.. _Documentation Reviewers: https://git.cyrus.foundation/tag/documentation_reviewers/
.. _Maniphest: https://git.cyrus.foundation/maniphest/
.. _Phabricator: https://git.cyrus.foundation/

Useful Developer Information
============================

Some combined :ref:`tips on developing with Cyrus <cyrus-hacking>` have been collected.

Community Participation
=======================

Join us! The project is only as good as the sum of its people. We all work together, despite the tyranny of distance and timezones.

Meetings are currently :ref:`held online via Zoom <feedback-meetings>`.

There's also :ref:`mailing lists <feedback>`.
