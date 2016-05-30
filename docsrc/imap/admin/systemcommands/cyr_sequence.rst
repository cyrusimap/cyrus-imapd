.. cyrusman:: cyr_sequence(8)

.. _imap-admin-systemcommands-cyr_sequence:

================
**cyr_sequence**
================

Debug tool for seqset. Also useful for resolving sequences.

Synopsis
========

.. parsed-literal::

    **cyr_sequence** [ **-C** *altconfig* ] [ **-m** *maxval* ] \<command\> *sequence* 
    
    The *command* is one of:
    
        * parsed
        * compress
        * members
        * ismember
        * create
    
    The *sequence* is a list of sequences. Discrete numbers are separated with commas, ranges are separated by colons.
    
Description
===========

**cyr_sequence** shows what happens when various operations are performed over a sequence.


Options
=======

.. program:: cyr_sequence

.. option:: parsed *sequence*

   Dumps a parsed view of the list structure, broken into contiguous sections.

.. option:: compress *sequence*

    Given a list, compress ranges with colons.

.. option:: members *sequence*

    Displays the full list of members within the sequence, in order, expanding out the ranges.
    
.. option:: ismember *[num...]*

    For each number in the list, check if it's in the sequence.

.. option:: create *[-s] [-o origlist] [items]*

    Generate a new list from the items, prefix numbers with ``~`` to remove them from the list. 
    If an original list is given, this is joined into this new list.
    
    The *-s* flag generates a sparse list.

.. option:: join *sequence1* *sequence2*

    Join two sequences together and return the output in compressed format.
    
.. option:: -C *altconfig*

    Specify an alternate config file.

.. option:: -m *maxval*

    Limit the maximum value to accept.

Examples
========

.. parsed-literal::

    **cyr_sequence parsed 1,3,4,5**

.. only:: html
   
    ::
   
        Sections: 2
        [1, 1]
        [3, 5]

.. parsed-literal::

    **cyr_sequence compress 1,3,4,5**

.. only:: html

    ::

        1,3:5

.. parsed-literal::

    **cyr_sequence members 1,23:25,28,30:32**

.. only:: html

    ::

        1
        23
        24
        25
        28
        30
        31
        32

