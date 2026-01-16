.. _imap-developer-thoughts-notes:

..  Note: This document was converted from the original by Nic Bernstein
    (Onlight).  Any formatting mistakes are my fault and not the
    original author's.  Converted via the pandoc tool from HTML.

Cyrus IMAP Server: Notes
========================

-  appending: it's important that the index records for individual
   messages make it to disk before the index header indicating that
   they're there. so something like:

   #. sync messages to disk (or depend on ``link()`` being atomic)
   #. create new index records, flush to disk
   #. create new header if necessary (adding new user flag), flush to
      disk
   #. flush cache file
   #. update index header, flush to disk
