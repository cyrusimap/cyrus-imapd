=======================
Cyrus SASL Installation
=======================

.. todo:
    This is all available at http://www.cyrusimap.org/docs/cyrus-sasl/2.1.25/install.php
    
You can install Cyrus SASL via packages or via tarball.

Contributors will want to `compile from source`_.

.. _compile from source: developer/installation.html

Unix package Installation
=========================

Are you `upgrading from Cyrus SASLv1`_?

Please see the file install.php for instructions on how to install this package.

Note that the library can use the environment variable SASL_PATH to locate the directory where the mechanisms are; this should be a colon-separated list of directories containing plugins. Otherwise it will default to the value of `--with-plugindir` as supplied to `configure` (which itself defaults to `/usr/local/lib`).

Mac OSX Installation
====================

Please read macosx.php

Windows Installation
====================

Please read windows.php. This configuration has not been extensively tested.

Configuration
=============

There are two main ways to configure the SASL library for a given application. The first (and typically easiest) is to make use of the application's configuration files. Provided the application supports it (via the `SASL_CB_GETOPT` callback), please refer to that documetation for how to supply SASL options.

Alternatively, Cyrus SASL looks for configuration files in `/usr/lib/sasl/Appname.conf` where Appname is settable by the application (for example, Sendmail 8.10 and later set this to "Sendmail").

Configuration using the application's configuration files (via the getopt callback) will override those supplied by the SASL configuration files.

For a detailed guide on configuring libsasl, please look at sysadmin.php and options.php

.. _upgrading from Cyrus SASLv1: 

.. toctree::
    :hidden:
    
    developer/installation

