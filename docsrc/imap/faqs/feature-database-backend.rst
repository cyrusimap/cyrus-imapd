Which database backend should I use for which databases?
--------------------------------------------------------

Here's a brief summary of the major database types:

* **Berkeley DB**: Slow enumeration, fast random access, fast write, binary support. However, it has proved to be somewhat unstable and prone to locking problems.

* **Berkeley DB (no sync)**: Slow enumeration, fast random access, very fast write, binary support, but no guarantee of database durability; recent writes can be lost on crashes.

* **Skiplist**: Proprietary Cyrus Format, fast enumeration, moderately fast write, moderately fast random access, binary support

* **Flat**: Easy to maintain format, fast enumeration, very slow write, moderate random access, no binary support

The default database backend for each database is the type currently 
recommended by the Cyrus developers. Please reference the 
:cyrusman:`imapd.conf(5)` manpage for your version of Cyrus imapd to see 
what the defaults are. 

