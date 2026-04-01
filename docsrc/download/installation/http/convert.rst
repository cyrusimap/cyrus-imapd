.. _convert:

=================
Media Conversion
=================

About the convert module
========================

.. warning::

    The ``convert`` module is **experimental** and is not meant for
    production use. It is not enabled by default.

The ``convert`` module converts between media types for selected content
types. It accepts an HTTP ``POST`` request at the ``/convert`` URL and
returns the converted data in the response body.

Currently it only converts between iCalendar and JSCalendar, according to
the definition of the IETF draft
`draft-ietf-calext-jscalendar-icalendar
<https://datatracker.ietf.org/doc/draft-ietf-calext-jscalendar-icalendar/>`_:

* A request with a ``text/calendar`` body is converted to JSCalendar and
  returned as ``application/jscalendar+json``.
* A request with an ``application/jscalendar+json`` body is converted to
  iCalendar and returned as ``text/calendar``.

Configuration
=============

The module is enabled by adding ``convert`` to the
:imapdconf:`httpmodules` option. It requires JMAP support to be compiled in.
