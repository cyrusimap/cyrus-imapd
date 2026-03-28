Files in this directory define entries in the imapoptions database.  The
imapoptions database is the canonical source of the imapd.conf options
recognised by Cyrus.

This database is used by tools/imapoptions.pl, which uses it to produce outputs
in the various formats needed by parts of the build.

FORMAT
======

Each file is approximately an RFC822 email file, consisting of:

1) A block of headers, defining properties of the option
2) An empty line
3) A block of documentation in RST format

HEADERS
=======

Long headers may be wrapped across multiple lines in the usual way for RFC822.

Name
----
The name of the option.  Must match the filename!

This header is required.

Type
----
The libconfig data type of the option.

* BITFIELD: a subset from a set of bits
* BYTESIZE: a size
* DURATION: a duration
* ENUM: one of a set of opaque values
* INT: an integer
* STRING: a string
* STRINGLIST: one of a set of strings
* SWITCH: a boolean value

This header is required.

Allowed-Values
--------------
The set of possible values for this option, separated by spaces.  The order of
values is significant and preserved.

For BITFIELD, ENUM, and STRINGLIST, this header is required.

For other types, this header is forbidden.

Default-Value
-------------
The default value for this option.

For BITFIELD, this may be multiple values separated by spaces.  All must have
been defined by Allowed-Values.

For BYTESIZE, this may be a string parseable by `config_parsebytesize`, or the
special value NULL.

For DURATION, this may be a string parseable by `config_parseduration`, or the
special value NULL.

For ENUM, this must be a single value from the set defined by Allowed-Values.

For INT, this may be any `long` integer.

For STRINGLIST, this must be a single value from the set defined by
Allowed-Values, or the special value NULL.

For STRING, this may be the special value NULL, any arbitrary string, or left
empty.

For SWITCH, this must be either 1 (enabled) or 0 (not enabled).

This header is required.

Last-Modified
-------------

Set this to UNRELEASED if you add a new option, or change the behaviour of
an existing one.

The release manager will replace it with a real version number during the
release process.

This header is required.

Deprecated-Since
----------------

Set this to UNRELEASED to mark the option as deprecated.

The release manager will replace it with a real version number during the
release process.

This header is optional.

Replaced-By
-----------

The name of another option that replaces this one.  The option so named must
exist and not itself be deprecated.

When Deprecated-Since is set, this header is optional.

When Deprecated-Since is not set, this header is forbidden.

For-Documentation-Only
----------------------

There are some options that we need to document but which do not get an
entry in the imapopts struct.  Set this flag to 1 for that behaviour.

This header is optional.

DOCUMENTATION
=============

The documentation block should be formatted as [reStructuredText][1].

[1]: https://www.sphinx-doc.org/en/master/usage/restructuredtext/

Deprecated options do not need a documentation block.  Documentation will be
generated automatically based on the Deprecated-Since and Replaced-By headers.

You do not need to repeat the Allowed-Values header content here, it will be
included automatically.  You may want to list and document the individual
values though.

The RST extensions used for Cyrus documentation are all available here.
Consider using :cyrusman:, :rfc:, etc as needed.

Keep in mind that the documentation you write here will be embedded into a
larger document.  Avoid using RST sequences that would break the enclosing
structure.
