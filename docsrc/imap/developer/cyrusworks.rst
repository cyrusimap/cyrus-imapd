===========
Cyrus Works
===========

.. rubric:: About Cyrus Works

Whenever the Cyrus team push changes to
`the project repository <https://github.com/cyrusimap/>`_, a notification is
sent to `Jenkins <https://jenkins.io/>`_ (open source automation server).
Our Jenkins server is called Cyrus Works and can be found at
https://www.cyrus.works.

.. rubric:: Testing

Once a week Cyrus.Works builds a complete image, fetching all upstream packages.

Interim builds during the week use the cached weekly image and apply the latest
Cyrus IMAP code changes from Git.

Email notifications of build results are sent to the development team.

.. rubric:: How it works

`Cassandane <https://github.com/cyrusimap/cassandane>`_, the Cyrus IMAP test
framework gets pulled in to the
`Docker Container <https://github.com/cyrusimap/cyrus-docker>`_, confirms
existing functionality still works and no regression bugs have been introduced.

You can find out more about Cyrus.Works in the `FastMail 2016 advent series blog post <https://blog.fastmail.com/2016/12/14/cyrus-works/>`_.

The code used to build Cyrus.works is available https://github.com/cyrusimap/cyrusworks.
