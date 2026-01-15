.. _imap-developer-guidance-internationalization:

..  Note: This document was converted from the original by Nic Bernstein
    (Onlight).  Any formatting mistakes are my fault and not the
    original author's.

Cyrus IMAP Server: Internationalization
=======================================

introduction
------------

Cyrus currently transcodes characters to a canonical UTF-8 form for
searching. The base spec of IMAP4 only requires understanding multiple
character sets to properly implement SEARCH. Since the base spec came
out, several extensions have been proposed that require further charset
support: SORT, THREAD, and the Sieve subsystem. As of this writing,
Cyrus doesn't correctly support these other commands.

Cyrus currently only believes in 16-bit characters. Technically, Unicode
has up to 21-bit characters (expressible in UTF-16 and 3-byte UTF-8) and
ISO 10646 allows up to 31-bit characters (though ISO's current policy is
to not allocate any characters outside of the 21-bit Unicode range). The
lower 16-bit characters make up the basic multilingual plane (BMP) where
the majority of languages live. This restriction is apparent in
``charset.c:writeutf8()``, the UTF-8 decoders, and the Unicode
canonicalization table used by Cyrus. Since Cyrus's known character sets
(except for UTF-8) don't contain any characters off of the BMP this
isn't seen to be a major problem.

Throughout this text, Unicode and ISO 10646 will be used interchangeable
to refer to the 16-bit character set of the BMP, regardless of encoding.
"Character", unless otherwise specified, refers to a single Unicode
character ``ffff`` or under.

cyrus canonical form
--------------------

Since when users search e-mail messages it's much easier for them to
eliminate false positives than realize there are hits that aren't
displayed, the Cyrus searching algorithm errs on the side of more
matches. Before comparing any two strings, Cyrus puts them in a
canonical form. Logically, the process works as follows:

-  the input string is translated into a sequence of Unicode characters.
-  each character is transformed into lowercase. (For some characters, a
   single uppercase character may transform into multiple lowercase
   characters.)
-  each character is fully decomposed.
-  all whitespace (Unicode general categories starting with ``Z``) is
   removed.
-  combining diacritical marks, such as the accent on é, are removed.
   (These are Unicode characters ``0300``-``03ff``.)
-  certain characters are expanded to alternative spellings using ASCII
   characters, such as "æ" to "ae".
-  the output characters are then encoded in UTF-8.

The actual transcoding does all of these steps at once with the aid of
tables, carefully built at compile-time.

The central part of Cyrus's internationalization support is it's
transcoding routines in ``lib/charset.[ch]``, and
``lib/chartable.[ch]``. Cyrus's transcoding routines are very elegant
and very compact, thus somewhat intimidating. During compilation, Cyrus
builds up a large number of tables (see `mkchartable <#mkchartable>`__)
and uses them so that it never has to consider more than a single octet
at a time while outputting the Cyrus canonical form for an input string.

external interface
------------------

``lib/charset.h`` is the public interface for Cyrus lib clients to get
character canonicalization and searching support. In contains the
following functions:

``char *charset_convert(const char *s, int charset, char *buf, int bufsz)``
    Given a string *s* in charset *charset*, decode it into canonical
    form in *buf*. *buf* must be reallocable and currently at least size
    *bufsz*.
``char *charset_decode_mimeheader(const char *s, char *buf, int bufsz)``
    Given a string *s* containing possible MIME encoded substrings (per
    RFC 2047), decode into canonical form in *buf*. *buf* must be
    reallocable and currently at least size *bufsz*.
``charset_index charset_lookupname(const char *name)``
    Given *name* return the Cyrus charset index. 0 always represents
    US-ASCII. The returned charset\_index may be saved in a file; it is
    stable and is an integer. If this version of Cyrus does not support
    the charset, ``CHARSET_UNKNOWN_CHARSET`` is returned.
``comp_pat *charset_compilepat(const char *s)``
    Compiles a NUL-terminated canonicalized string *s* into a
    Boyer-Moore table for fast searching. I'll describe these `compiled
    patterns <#comp_pat>`__ later.
``void charset_freepat(comp_pat *pat)``
    Frees a pattern previously return by ``charset_compilepat()``.
``int charset_searchstring(const char *substr, comp_pat *pat,     const char *s, int len)``
    Searches for a canonicalized string *substr* in the canonicalized
    string *s*. *s* is of length *len*. *substr* must have been
    previously compiled into *pat*. Returns non-zero for a hit, zero for
    no match.
``int charset_searchfile(const char *substr, comp_pat *pat,                               const char *msg_base, int mapnl, int len,                               charset_index charset, int encoding)``
    Searches for the canonicalized string *substr* with compiled pattern
    *pat* in a large buffer starting at *msg\_base* of length *len*. The
    large buffer is of charset *charset* with the encoding *encoding*.
    ``charset_searchfile()`` will dynamically unencode and canonicalize
    the search text looking for *substr*. (If *mapnl* is set, the buffer
    has only ``\n`` instead of ``\r\n``, but the length assumes that
    each ``\n`` is dynamically converted to ``\r\n``. This feature is
    deprecated.)
``char *charset_decode_mimebody(const char *msg_base, int len,                                      int encoding, char **buf, int *bufsz,                                      int *outlen)``
    Decode the MIME body part (per RFC 2045) located in the large buffer
    starting at *msg\_base* of length *len*. The large buffer is of
    encoding *encoding*. ``charset_decode_mimebody()`` will decode into
    *buf*. *buf* must be reallocable and currently at least size
    *bufsz*. The number of decoded bytes is returned in *outlen*.
``charset_extractfile()``
    Used by ``squatter`` and possibly other text indexing engines, but
    not described here.

the TRANSLATE macro: using the transcoding tables
-------------------------------------------------

The external interface is implemented with the help of the ``START`` and
``TRANSLATE`` macros:

``void START(struct decode_state *state, const unsigned char (*table)[256][4])``
    ``START`` initializes *state* to be ready for transcoding of the
    charset translation table given with *table*. The starting active
    table is always the first one in the list passed in.
``void TRANSLATE(struct decode_state *state, unsigned char input, unsigned char *outbuf, unsigned outindex)``
    ``TRANSLATE`` takes four parameters: *state* is the current state of
    the translation; it must have been initialized with ``START`` and is
    modified by ``TRANSLATE``; *input* is one octet of input from the
    stream to be transcoded; *outbuf* is a pointer to the start of the
    buffer to write output characters; *outindex* is the index where
    this translation should be written. The size of *outbuf* must be at
    least *outindex + charset\_max\_translation*.

Each charset consists of a set of one or more tables; the *table*
parameter passed into ``START`` is the first of these tables and the
others are adjacent in memory. Characters are transcoded by indexing
into the active table with *input* and examining the 4 octet
translation. The 4 octet translation may consist of 0–3 character
translations followed by a control code or a series of control codes. In
effect, the translation for a given octet is a mini-program that
consists either of UTF-8 octets or control codes. One of the control
codes RET, END, JSR, or JMP must occur in the 4 octet translation.

control codes
~~~~~~~~~~~~~

Control codes are represented by uppercase US-ASCII characters since no
uppercase characters can appear in the output translation (recall that
Cyrus canonical form downcases). Any uppercase US-ASCII character
(``[A .. Z]``) is thus interpreted specially by the ``TRANSLATE``
virtual machine. Any other octet encountered as an output translation is
presumed to be part of the UTF-8 output sequence and copied to the
output.

The names of control codes are actually C pre-processor defines to
uppercase US-ASCII characters. As the mnenomics are easier to
understand, I use them in discussing their semantics.

control code reference
~~~~~~~~~~~~~~~~~~~~~~

``TRANSLATE`` recognizes the following "normal" control codes:

XLT
    This is the first octet of the four octet sequence, indicating that
    the desired translation is larger than 3 UTF-8 octets. The next two
    octets represent an offset to look up in the special
    chartables\_long\_translations[] table. After that translation is
    copied to the outbuf, the final octet is interpreted (it must be
    either a RET or an END).
JSR
    The ``TRANSLATE`` virtual machine has a stack, fixed at size 1. A
    JSR copies address of the current active table to the stack and
    transitions to the active table given by the next two octets. (For
    instance, table 1 would be the next table after the table given as a
    parameter to ``START``.) Translation of the current octet stops
    after encountering a JSR.

    JSRs are useful for converting a two octet input character: the
    first octet in the character will make a JSR to some table; the
    second octet will produce a translation and RET to the current
    table.

    Since the virtual machine has a fixed size stack, it would be highly
    unusual for the virtual machine to encounter two different JSRs
    without an intervening RET.

JMP
    Similar to JSR, but does not change the stack. It is the equivalent
    of a goto. JMPs are useful to deal with modal input character sets
    (such as an escape in ISO-2022-JP, see `how the tables are
    generated <#mkchartable>`__).
RET
    Indicates that we are done translating this input octet and we
    should return to the previous active table. It might appear as the
    first of the 4 translation octets, in which case this input
    character translates into nothing (it might be whitespace, for
    instance).
END
    Indicates we are done translating this input octet. When
    ``TRANSLATE`` is next called, that input octet will be interpreted
    against the current active table; the stack does not change.

In addition, it recognizes the following "special" control codes for
charsets that aren't easily represented by a set of tables, UTF-8 and
UTF-7:

U7F
    UTF-7 consists of US-ASCII characters and a special escape character
    that indicates a transition to base-64 encoded UTF-16 characters.
    The virtual machine has built in code to handle the base64 decoding.
    In UTF-7's base64, 8 input octets result in 3 characters, so the
    tables would be rather large.
U7N
    This indicates that the current octet is the continuation of the
    base-64 section.
U83
    One and two character UTF-8 sequences are handled normally in the
    charset code. To keep the table size down, 3 octet sequences are
    handled specially. U83 indicates that the current input octet is the
    start of a three character sequence. It is also an implicit jump to
    the 2nd table in the UTF-8 sequence, ending this translation.
U83\_2
    This input octet 2nd of 3-octet UTF-8 input, with an implicit jump
    to the 3rd table.
U83\_3
    3rd octet of a 3-octet UTF-8 input. This produces the output
    characters and has an implicit jump to the 1st table of UTF-8.

Finally, it's useful to mention the special character ``EMPTY`` which is
guaranteed not to match any character. It is also represented by an
uppercase US-ASCII character.

searching and compiled patterns
-------------------------------

boyer-moore
~~~~~~~~~~~

brief description of boyer-moore xxx

cyrus implementation
~~~~~~~~~~~~~~~~~~~~

why two arrays? us-ascii optimization, really kinda useless now xxx

meta-data stored at the end xxx

generating the tables: ``mkchartable``
--------------------------------------

The program ``mkchartable`` is used to generate the charset transcoding
tables used by TRANSLATE. These tables are carefully constructed so no
more than a single octet need be examined at a time; this octet results
in either an output stream of UTF-8 characters being generated or some
sort of state change.

``mkchartable`` uses three different sorts of input files to generate
these tables. These files are located in the ``lib/charset`` directory.

charset tables
~~~~~~~~~~~~~~

Each charset file maps a single charset to the corresponding Unicode
characters. For the US-ASCII and ISO-8859-x character sets this is
trivial: each input byte corresponds to a single Unicode character.
(Actually, some ISO-8859-x octets do not map to any Unicode character.
In that case, the file either does not contain that octet or map it to
"``????``".)

Other character sets are trickier. For instance, GB-2312 has both single
and double byte characters, but is still a simple map from input
character to output character. More complicated are modal character
encodings. For instance, ISO-2022-JP starts in US-ASCII mode and uses
``1B`` as an escape character followed by another two characters to
select a new mode.

The input charset labels modes with "``:``" followed by the mode name.
The starting mode "``US-ASCII``" in ISO-2022-JP is preceded by
"``:US-ASCII``". Mode transitions are denoted by a Unicode conversion of
"``>newmode``" or "``:newmode``". To denote that the octet ``42``
transitions into the "``US-ASCII``" mode, the charset file has
"``42 >US-ASCII``". The mode names themselves are arbitrary labels and
have no effect on the output.

The input charset labels modes with ":" followed by the mode name. The
mode name is optionally followed by a space and the "``<``" character.
If the "``<``" character is present, then all translations will be
followed by a RET instruction instead of an END instruction.

The transition "``>newmode``" results in a JSR instruction being
generated. A JMP instruction is generated by a transition of
"``:newmode``".

The input byte can be specified as "``*``". This is used to define the
"default action" which is used for input bytes that are not otherwise
defined for the mode. If the default action is not explicitly stated, it
is a translation to EMPTY.

unicode data table
~~~~~~~~~~~~~~~~~~

The ``unidata2.txt`` file is verbatim from the Unicode standard. More
recent versions should be available `from their
website <http://www.unicode.org/xxx>`__. Each entry in the file
describers a Unicode character by the following properties, separated by
semicolons:

-  code point (16-bit character value) in hex
-  character name (unused by Cyrus)
-  general category, such as whitespace or punctuation
-  the canonical combining class (unused)
-  bidirection category (unused)
-  character decomposition
-  decimal digit value (unused)
-  digit value (unused, and, no, I don't know the difference)
-  numeric value including fractions (unused)
-  mirrored character (unused)
-  Unicode 1.0 name (unused)
-  comment (unused)
-  upper case equivalent (unused)
-  lower case equivalent

In general, Cyrus uses the lower case equivalent if there is one, and
the decomposed value otherwise.

unicode fixup table
~~~~~~~~~~~~~~~~~~~

The ``unifix.txt`` file contains Cyrus-specific mappings for characters.
It overrides the ``unidata2.txt`` table. Each rule in the file is
explained with a comment. It's helpful to remember that the Unicode
general categories starting with ``Z`` represent whitespace, and
whitespace is always removed.

generating ``chartable.c``
~~~~~~~~~~~~~~~~~~~~~~~~~~

how ``mkchartable`` works: collapses the encoding modes, the unicode
translations, and other normalizations into the output tables described
above xxx

for the future
--------------

Sieve/ACAP comparators
~~~~~~~~~~~~~~~~~~~~~~

adjustable normalization?
~~~~~~~~~~~~~~~~~~~~~~~~~

The use of uppercase US-ASCII characters is one of the annoyances in
trying to generalize the charset transcoding. If we continue to restrict
the characters under consideration to the BMP, switching to UTF-8
control codes that start 4 or 5 byte sequences is possible.

Another possibility is to use a NUL character as an escape sequence,
though this increases the size of each control code by 1 octet.

handle >2 octet input characters
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

make UTF-8 more regular
~~~~~~~~~~~~~~~~~~~~~~~

consider whether we really need U83, U83\_2, U83\_3. also consider
changing ``{ U83, 0, 0, 0 }`` translations to ``{ U83, JMP, 0, 1 }``
sequences to at least eliminate the implicit jump.

require minimal UTF-8 characters
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

references
----------

xxx

-  [UNICODE] Unicode / ISO 10646
-  [UTF-8] utf-8 RFC
-  [UTF-7] utf-7 RFC
-  [BM] boyer-moore
-  [ACAP] the comparators reference. see section XXX of RFC 2244.
