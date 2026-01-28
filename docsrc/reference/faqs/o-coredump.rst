.. _faqs-o-coredump:

How to enable core dumps
------------------------

In case of abnormal program termination, Cyrus automatically writes core dumps in the subdirectory cores in the configdirectory. However, for security reasons most Linux systems disable core dumps for processes that changed ownership, and Cyrus will silently abort the save attempt.

To make sure that core dumps are enabled for debugging, please:

Make sure that cores contain the PID of the process.

.. code-block:: bash

    # echo 1 >/proc/sys/kernel/core_uses_pid

As a security feature, Linux won't generate cores for processes which have changed ownership. This prevents any of the Cyrus processes in your test ever dumping core, so you want to turn that feature off.

.. code-block:: bash

    # echo 1 >/proc/sys/fs/suid_dumpable

Finally, some Linux systems might require to unlimit the size of core dumps.

.. code-block:: bash

    # ulimit -c unlimited

Then you can fire up gdb:

.. code-block:: bash

    gdb /usr/local/cyrus/lmtpd /tmp/core.XXX  (use proper locations)

At the (gdb) prompt run the backtrace command (``bt``).

.. warning::

    These parameters are disabled for a reason and should only be used for debugging. We do not recommend to regularly enable setuid cores and unlimited core sizes on production systems.
