"unable to join environment" error
----------------------------------

This error is caused if you build Berkley DB 4 with threading support, 
but do not then link the pthreads library to Cyrus. This is commonly 
caused by a Linux distribution which supplies the pre-threaded library 
version. 

One workaround is to rebuild the db4 library without thread support. 
Another is provided by Scott Adkins (adkinss@ohio.edu):: 

    I talked to SleepyCat about it and they suggested making sure that the 
    threads library was being linked into the IMAP server. It used to be 
    that when compiling db3 that the IMAP server would automatically link in 
    the threads library, probably because of an rpath listed in the db3 
    shared library. They must have changed something with db4, since the 
    threads library is no longer linked into applications if they link 
    against the db4 library. 

    As it turns out, linking with threads (I believe I simply included the 
    ``-pthread CC`` command line option to have that happen) caused the join 
    errors to go away. I was still having some flakiness with db4 though... 

Starting with Cyrus 2.2.1, it is possible to build without linking 
Berkeley DB at all, which may be a viable option for some sites. 

  