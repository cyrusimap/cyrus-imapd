Reporting Bugs
==============

Bug reports can be logged in our `GitHub issue tracker
<https://github.com/cyrusimap/cyrus-imapd/issues>`__.
Please bear in mind registration is required.
When reporting a bug, please prepare to provide the following information;

* Your platform, and if applicable, your distribution and the distribution version.
* The exact version of Cyrus IMAP or SASL you are using.
* If a packaged version is used, the source of the packaged version.
* If a custom version is used, any options that may have specified during the build process.
* If relevant, are you using altnamespace, unixhierarchysep, or virtdomains?
* If relevant, are you in a murder configuration? (In which case please provide information for all hosts) 

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

If you run a development version of Cyrus IMAP or SASL (i.e. your own compile from GIT's master or any of the stable branches), please remember to use the -next version for the Bugzilla report.

.. todo::
    provide some text on logging a new ticket in our bugzilla, information to provide, etc. Possibly mention the life cycle of a product version series. 
