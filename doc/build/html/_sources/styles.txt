Document Conventions
====================

This manual uses several conventions to highlight certain words and phrases and draw attention to specific pieces of information.


.. todo::
   Check if all of these styles are relevant (and possible) using reStructuredText formatting. Most of this copied from the XML used with Publican.

Typographic Conventions
-----------------------

Mono-spaced with non-white background
"""""""""""""""""""""""""""""""""""""

Used to highlight system input, including shell commands, file names and paths. Also used to highlight keycaps and key combinations. For example:

    To see the contents of the file ``my_next_bestselling_novel`` in your current working directory, enter the ``cat my_next_bestselling_novel`` command at the shell prompt and press ``Enter`` to execute the command.

The above includes a filename, a shell command and a keycap, all present in mono-spaced type and all distinguishable thanks to context.

Key combinations can be distinguished from keycaps by the hyphen connecting each part of a key combinations. For example:

    Press ``Enter`` to execute the command.

    Press ``Ctrl-Alt-F2`` to switch to the first virtual terminal. Press ``Ctrl-Alt-F1`` to return to your X-Windows session.

The first paragraph highlights the particular keycap to press. The second highlights two key combinations (each a set of three keycaps with each set pressed simultaneously).

If source code is discussed, class names, methods, functions, variable names and returned values mentioned within a paragraph will be presented as above, in ``mono-spaced type``. For example:

    File-related classes include ``filesystem`` for file systems, ``file`` for files, and ``dir`` for directories. Each class has its own associated set of permissions.

Proportional Bold
"""""""""""""""""

This denotes words or phrases encountered on a system, including application names; dialog box text; labelled buttons; check-box and radio button labels; menu titles and sub-menu titles. For example:

    Choose **System** -> **Preferences** -> **Mouse** from the main menu bar to launch **Mouse Preferences**. In the **Buttons** tab, click the **Left-handed mouse** check box and click **Close** to switch the primary mouse button from the left to the right (making the mouse suitable for use in the left hand).

Italic
""""""

The addition of italics indicates replaceable or variable text. Italics denotes text you do not input literally or displayed text that changes depending on circumstance. For example:

    To connect to a remote machine using ssh, type ``ssh *username@domain.name*`` at a shell prompt. If the remote machine is **example.com** and your username on that machine is **john**, type ``ssh john@example.com``

    The ``mount -o remount *file-system*`` command remountes the named file system. For example, to remount the ``/home`` file system, the command is ``mount -o remount /home``.

    To see the version of a currently installed package, use the ``rpm -q *package*`` command. It will return a result as follows: *package-version-release*. 

Note the words in bold italics above — username, domain.name, file-system, package, version and release. Each word is a placeholder, either for text you enter when issuing a command or for text displayed by the system.

Aside from standard usage for presenting the title of a work, italics denotes the first use of a new and important term. For example: 

    Publican is a *DocBook* publishing system.

Pull-quote Conventions
----------------------

Terminal output and source code listings are set off visually from the surrounding text.

Output sent to a terminal is presented thus::

    books        Desktop   documentation  drafts  mss    photos   stuff  svn
    books_tests  Desktop1  downloads      images  notes  scripts  svgs

Source-code listings are also presented this way but may add syntax highlighting.


Notes and Warnings
------------------

Finally, we use three visual styles to draw attention to information that might otherwise be overlooked.

.. note::
   Notes are tips, shortcuts, or alternative approaches to the task at hand. Ignoring a note should have no negative consequences, but you might miss out on a trick that makes your life easier.

.. important::
   Important boxes detail things that are easily missed: configuration changes that only apply to the current session, or services that need restarting before an update will apply. Ignoring a box labelled 'Important' will not cause data loss but may cause irritation and frustration.

.. warning::
   Warnings should not be ignored. Ignoring warnings will most likely cause data loss.

.. todo::
   To-do sections mean that someone hasn't yet written this section, or maybe there is some information missing or potentially inaccurate. It will probably be worth reading the to-do note.

