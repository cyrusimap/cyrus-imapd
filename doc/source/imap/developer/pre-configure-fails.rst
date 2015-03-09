.. _imap-developer-pre-configure-fails:

====================================================
Error Message: Step ``pre-configure`` fails on (...)
====================================================

When `Dr. Jenkins`_ raises a concern with a commit, (...)

To reproduce the issue, see :ref:`imap-developer-docker-images` to fire
up a Docker container of your own, with an interactive shell.

Normally, the script ``/entrypoint.sh`` is executed, so you can
reproduce this as follows:

.. parsed-literal::

    $ :command:`COMMIT=<id> /entrypoint.sh`

It *should* output the commands it issues.

.. _Dr. Jenkins: https://git.cyrus.foundation/p/jenkins/
