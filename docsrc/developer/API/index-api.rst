.. _imap-developer-api-index:

..  Note: This document was converted from the original by Nic Bernstein
    (Onlight).  Any formatting mistakes are my fault and not the
    original author's.  Converted via the pandoc tool from HTML.

Index API
=========

Intro
-----

The Index API is implemented in ``imap/index.h`` and ``imap/index.c``.
It provides a snapshot view into the underlying mailbox (see `the
Mailbox API documentation <mailbox-api.html>`) which obeys IMAP
semantics, as well as all the searching and sorting logic.

Opening and closing
-------------------

::

    struct index_state *state = NULL;
    struct index_init init;
    int r;
    const char *mboxname = "user.brong";

    memset(&init, 0, sizeof(struct index_init));
    init.userid = imapd_userid;
    init.authstate = imapd_authstate;
    init.out = imapd_out;

    r = index_open(mboxname, &init, &state);
    if (r) return r;

    do_stuff(state);

    index_close(&state);

The ``index_init`` interface sucks. So does passing lots of parameters.
For now, this will do! Just pass NULL if you're only reading, or use the
code already in imapd and you'll be fine.

The Index Model
---------------

Ok - I think a few words about the index model and how it differs from
direct mailbox access are needed! In the past, index.c used pointers
directly into the mmaped ``cyrus.index`` file and maintained the old
mmaped copy if an expunge took place. Under the namelock regime, this is
no longer required because namelocks will avoid the file being
re-written.

Also, memory is now cheap. Rather than using locks to ensure
consistency, we just keep a copy of the ``struct index_record`` for even
message in the index, stored in memory. Since these are about 100 bytes
each, a 1 million email mailbox will take rougly 100Mb of memory. That's
not too bad on a modern server, and that's a **huge** mailbox.

So - the model works like this:

-  Create the index state or re-lock (``index_lock``) the mailbox on an
   existing index.
-  call ``index_refresh``
-  if any changes are to be made (i.e. flag updates for a store,
   non-peek body fetch, expunge) then cycle through the refreshed state
   map and update the records which are affected.
-  call ``index_unlock`` (unlock the underlying mailbox and commit the
   statuscache changes)

   At this point the index lock is **released** and we have not yet
   generated any network traffic. Now start generating the response.

-  if expunges are allowed, call ``index_tellexpunge``
-  call ``index_tellchanges`` to tell about all other changes
-  return any response that the command itself required
