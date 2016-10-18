Problems detecting Berkley DB on Red Hat Linux
----------------------------------------------

Modern Redhat Linux ships with a Berkeley DB compiled 
``--with-pthreads``, which Cyrus is unable to directly link against. 

You can either recompile Berkeley DB without pthread support, or you can 
add ``-lpthread`` to your LDFLAGS environment variable before you 
configure/build. 

