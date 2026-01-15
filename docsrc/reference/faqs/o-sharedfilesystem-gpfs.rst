Shared File Systems GPFS for high availability
----------------------------------------------

Stephen L. Ulmer (ulmer@ufl.edu) actually has used Cyrus with GPFS, and 
writes: 

FOR THE LOVE OF GOD, RUN AWAY! 

We had our Cyrus message store on GPFS for just about a year. I've been 
a Unix systems administrator for almost 15 years; It was the worst 
single judgement of my professional career. Period. 

During the 18 months when we had GPFS deployed, my unit had TWO crit 
sits and uncovered over 30 bugs in the GPFS software alone (not counting 
stuff we found in VSD, AIX, et cetera). The situation ended with the 
GPFS architect suggesting that we do something else. He's a great guy, 
and he helped us many times, but the product just doesn't do what we 
wanted. 

GPFS is the successor to the Multi-Media Filesystem, which was used in 
IBM's Videocharger product. It's excellent at streaming small numbers of 
large files (like, say, movies). It's horrible when you get above a few 
hundred-thousand files, as the systems can't possibly have enough memory 
to keep track of the filesystem meta-data. 

Our Cyrus installation has about 80K users, close to 1TB of disk, and 
many millions of files. Just the number of files alone would be enough 
to kill the idea of using GPFS. 

Cyrus makes pretty extensive use of mmap().
While GPFS implements mmap(), the GPFS architect had some words about 
the way certain operations are accomplished in Cyrus. I think there are 
(or used to be) places where an mmap'd file is opened for write with 
another file handle (or from another process). GPFS doesn't handle this 
well. This technique works accidentally on non-clustered filesystems 
because AIX (also) mmap's things for you behind your back (in addition 
to whatever you do) and then serializes all of the access to regions of 
those files. That's really the only reason why Cyrus works on JFS. 

Also note that the other groups/developers within IBM (especially the 
group that does the automounter) have their collective heads up their 
ass with respect to supporting "after market" filesystems on AIX. After 
two freakin' years of PMRs they still couldn't figure out how to make 
autofs interact predictably with locally-mounted GPFSs. I constantly had 
to employ work-arounds in my automounter maps. 

If you just want failover, then use the HACMP product to deal with the 
failover scenario. If you need to scale beyond one system image, try out 
a Cyrus Murder. That's what we're using now, it works great. 

Note that in the Murder scenario, you can still use HACMP to have one of 
your back-ends take over for another if it fails. You just have to 
carefully craft your cyrus.conf files to only bind to a single IP 
address, so that you can run two separate instances of Cyrus on the same 
machine during the failover. 

I will be happy to discuss our particular situation, implementation 
choices and details with you if you'd like to contact me out-of-band. 



We're currently running our Murder on::

    2 x p630 [backends]
        4 x 1.4GHz Power4+ CPU
        8GB Real Memory
     
    4 x p615 [frontends]
        2 x 1.2GHz Pwer4+ CPU
        4GB Real Memory
     
The frontends are also the web servers for our Virtual Hosting cluster. We're running version 2.1.x of Cyrus. Now that 2.2.x is stable we'll upgrade, but you can imagine that it'll take some planning.

In short, we don't recommend it. If you want to do it, it may possibly work but you may also lose your email or have corrupted cyrus.* files. You can look at the mailing list archives for more information.

There are several critical things that must be supported for this to work: 

    * file locking 
    * mmap() 
    * writing to an mmap()'d file with the write() syscall 
    
In general, this is bad news. Don't do it. Really. About the closest you can currently get is having a "warm spare" that takes over the IP of the affected backend, and have a SAN between the two systems.

:ref:`Cyrus Murder <murder>` may be a "good enough" solution in some environments, as a way to partition failures and spread load across many machines. Combined with a warm-spare approach this can be a good way to achieve highly available systems (though not ones which are fully redundant)