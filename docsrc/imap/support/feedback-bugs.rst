.. _feedback-bugs:

Reporting Bugs
==============

Bug reports can be sent to us through our :ref:`mailing list <feedback-mailing-lists>` or logged in our `GitHub issue tracker <https://github.com/cyrusimap/cyrus-imapd/issues/>`__. (Registration is required)
When reporting a bug, please provide the following information;

* Your platform, and if applicable, your distribution and the distribution version.
* The exact version of Cyrus IMAP or SASL you are using.
* If a packaged version is used, the source of the packaged version.
* If a custom version is used, any options that may have specified during the build process.
* If relevant, are you using altnamespace, unixhierarchysep, or virtdomains?
* If relevant, are you in a murder configuration? (In which case please provide information for all hosts)
* What did you do?
* What did you expect to happen, and what actually happened?
* If Cyrus crashed, please provide a backtrace of the :ref:`core dump <faqs-o-coredump>`.

If you know how to fix the bug, we also are delighted to receive pull
requests or patch snippets sent via email on the mailing lists.

.. note::
    **Cyrus IMAP Version**

    The Cyrus IMAP team would appreciate if you try your best to supply us with the exact version of Cyrus IMAP that you run. The Cyrus IMAP version from upstream, usually in the format x.y.z does not include important information on the *build* or *release*, nor the source for the package you may have used.

    Most Linux distributions allow you do get the full version with ``rpm -qv cyrus-imapd`` or ``dpkg -l cyrus-imapd``.
    If package management, for whatever reason, cannot tell you what version of Cyrus IMAP you have, connecting to your Cyrus IMAP server (typically via telnet to port 110 or 143) could.

.. note::
    **Cyrus SASL Version**

    The Cyrus team would appreciate if you try your best to supply us with the exact version of Cyrus SASL that you run. The Cyrus SASL version from upstream, usually in the format x.y.z does not include important information on the *build* or *release*, nor the source for the package you may have used.

    Most Linux distributions allow you do get the full version with ``rpm -qv cyrus-sasl`` or ``dpkg -l cyrus-sasl``.
    If package management, for whatever reason, cannot tell you what version of Cyrus SASL you have, **what could?**

If you run a development version of Cyrus IMAP or SASL (i.e. your own compile from GIT's master or any of the stable branches), please remember to note that in the report.

.. todo::
    provide some text on logging a new ticket, information to provide, etc. Possibly mention the life cycle of a product version series.
