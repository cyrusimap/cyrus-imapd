.. _linker-warnings:

.. _openssl-versions:

OpenSSL Version Mismatches
--------------------------

Your system may have multiple versions of OpenSSL on it. it is possible that
some libraries which Cyrus can use might be linked against different versions of
the OpenSSL libraries, or that those may be different from the version which
Cyrus itself will use.

Major updates of OpenSSL are not always compatible with each other at the API
level. OpenSSL is used by many libraries and system components and not all of
those become compatible with the new version at the same time. Because of this
some Linux distributions choose to ship multiple OpenSSL versions and allow
components to use whichever version is appropriate.

If two different versions of the OpenSSL libraries linked into one program, it
results in program instability. To check if this is happening, look for warnings
from the linker like the following:

.. code-block:: bash

    /usr/bin/ld: warning: libssl.so.10, needed by /usr/lib/gcc/x86_64-redhat-linux/7/../../../../lib64/libclamav.so, may conflict with libssl.so.1.1
    /usr/bin/ld: warning: libcrypto.so.10, needed by /usr/lib/gcc/x86_64-redhat-linux/7/../../../../lib64/libclamav.so, may conflict with libcrypto.so.1.1

In this case, ClamAV is still linked against OpenSSL 1.0, while Cyrus is
building with OpenSSL 1.1.
