.. _admin-protlayer:

================
Cyrus Prot Layer
================

.. note::

    This is woefully incomplete, it only covers waitevents. Minimally we should also discuss prot_select and the bigbuffer stuff from 2.2, perhaps with an overview on configuring a prot layer (sasl, tls, telemetry, etc).

The prot layer, defined in prot.h, is a stdio replacement for network i/o. It does the standard buffering of input and output and allows certain operations especially suited for request/response protocols like IMAP.

Events
======

The prot layer allows "events" to be associated with each prot stream. These events are trigger at the given time or after when the protstream is attempted to be read from.

An event is currently represented by the **prot_waitevent** datastructure::

    struct prot_waitevent;
     
    typedef struct prot_waitevent *prot_waiteventcallback_t(struct protstream *s,
                               struct prot_waitevent *ev,
                               void *rock);
     
    struct prot_waitevent {
       time_t mark;
       prot_waiteventcallback_t *proc;
       void *rock;
       struct prot_waitevent *next;
    };

The application is currently allowed to modify **mark**, **proc**, and **rock** as desired when there are no active calls to a prot function on the stream which this event is associated.

The API
-------

Use **prot_addwaitevent()** to add an event callback onto the stream::

    extern struct prot_waitevent *prot_addwaitevent(struct protstream *s,
                       time_t mark,
                       prot_waiteventcallback_t *proc,
                       void *rock);

where:
    * **s** is the stream to add the event to, 
    * **mark** is the time to trigger the event, 
    * **proc** is the callback to make, and 
    * **rock** is an opaque data item handed to the callback. It returns a pointer to the event structure; this is the pointer that must be used to remove the event or modify it in some way.

Use **prot_removewaitevent()** to remove an event::

    extern void prot_removewaitevent(struct protstream *s,
                struct prot_waitevent *event);

It requires event to have been returned from prot_addwaitevent() previously. No further references are allowed to event or its fields. ``event->rock`` is not free'd nor examined in any way. This function may be called while inside the callback ``event->proc()``. If an event is removed inside of its callback, that callback must return NULL.

Some common things to do with events:

* To reschedule an event ev, simply set ``ev->mark`` to the next time it should trigger. If currently in ``ev->proc()``, it should return ev.
