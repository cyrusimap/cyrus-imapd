.. _imap-developer-thoughts-prot-events:

..  Note: This document was converted from the original by Nic Bernstein
    (Onlight).  Any formatting mistakes are my fault and not the
    original author's.  Converted via the pandoc tool from HTML.

Cyrus IMAP Server: Prot Events
==============================

From an email exchange between Ken Murchison and Lawrence Greenfield,
dated 03 Feb 2002 (slightly redacted and formatted for your viewing
pleasure):

|    From: Ken Murchison
|    To: Lawrence Greenfield
|    Subject: Re: prot events
|

    Lawrence Greenfield wrote:

        Can you give me some details on how the event API in the prot
        layer works?  I'm a little unclear about the memory management,
        what should be returned from the event callback,

    Either the event pointer (if the event is still active), or NULL
    (if the event has been removed by the callback).

        and how to reschedule an event.

    Simply set the 'mark' time in the event to the wall time you want
    it to run again.

        (I'd like to make an event called every X seconds of idle time;
        I know the API can't do exactly that but I suspect I can fake
        it well enough.)

    Look at backend_timeout() in proxyd.c and/or drac_ping() in
    contrib/drac_auth.patch, they do exactly this.

    The API is pretty simple:

    *   use prot_addwaitevent() to add an event (linked list) callback
        onto a stream.  takes the stream, the 'mark' time at which to
        run the event (NOT an interval, but the future clock value),
        the function pointer, and a rock to pass to the callback as
        args, and returns a pointer to the event (to use for future
        removal).

    *   use prot_removewaitevent() to remove an event.  takes the
        stream and a pointer to the event as args.

    *   the event callback gets the stream, a pointer to the event
        and the rock as args.  To reschedule an event, simply set the
        'mark' time and return the event pointer.  If the callback
        removes the event, then return NULL.

    If you see and flaws in this API, feel free to go ahead and change it.

    Ken
