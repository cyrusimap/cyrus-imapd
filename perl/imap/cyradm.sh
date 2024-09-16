#! /bin/sh
exec perl -x -S $0 ${1+"$@"} # -*-perl-*-
#!perl
#
# Copyright (c) 1994-2008 Carnegie Mellon University.  All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in
#    the documentation and/or other materials provided with the
#    distribution.
#
# 3. The name "Carnegie Mellon University" must not be used to
#    endorse or promote products derived from this software without
#    prior written permission. For permission or any legal
#    details, please contact
#      Carnegie Mellon University
#      Center for Technology Transfer and Enterprise Creation
#      4615 Forbes Avenue
#      Suite 302
#      Pittsburgh, PA  15213
#      (412) 268-7393, fax: (412) 268-7395
#      innovation@andrew.cmu.edu
#
# 4. Redistributions of any form whatsoever must retain the following
#    acknowledgment:
#    "This product includes software developed by Computing Services
#     at Carnegie Mellon University (http://www.cmu.edu/computing/)."
#
# CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
# THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
# FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
# AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
# OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#

use Cyrus::IMAP::Shell;
shell;

=head1 NAME

cyradm - Cyrus administration shell, alter ego of Cyrus::IMAP::Shell

=head1 SYNOPSIS

  $ cyradm [--user user] [--[no]rc] [--systemrc file] [--userrc file] \
  > [--port n] [--auth mechanism] [--tlskey keyfile] [--notls] \
  > [--cafile cacertfile] [--cadir cacertdir] \
  > [--server] server

but possibly

  $ perl -MCyrus::IMAP::Shell -e 'run("myscript")'

or even (not recommended)

  use Cyrus::IMAP::Admin::Shell;

  run('myscriptname');

=head1 DESCRIPTION

This module implements B<cyradm> in Perl.  It is a shell around
L<Cyrus::IMAP::Admin>.  Commands are provided in both Tcl-compatible
forms and GNU-style long option forms.

=head1 COMMANDS

=over 4

=item C<authenticate> [C<--minssf> I<N>] [C<--maxssf> I<N>] [C<--mechanisms> I<list>] [C<--service> I<name>] [C<--tlskey> I<keyfile>] [C<--notls>] [C<--cafile> I<cacertfile>] [C<--capath> I<cacertdir>] [I<user>]

=item C<auth> [C<--minssf> I<N>] [C<--maxssf> I<N>] [C<--mechanisms> I<list>] [C<--service> I<name>] [C<--tlskey> I<keyfile>] [C<--notls>] [C<--cafile> I<cacertfile>] [C<--capath> I<cacertdir>] [I<user>]

=item C<login> [C<--minssf> I<N>] [C<--maxssf> I<N>] [C<--mechanisms> I<list>] [C<--service> I<name>] [C<--tlskey> I<keyfile>] [C<--notls>] [C<--cafile> I<cacertfile>] [C<--capath> I<cacertdir>] [I<user>]

Authenticate to server.  You must already be connected to a server and
Cyrus imapd will refuse to allow you to re-authenticate once you have
authenticated once.

=item C<chdir> I<directory>

=item C<cd> I<directory>

Change directory.  A C<pwd> builtin is not provided, but the default command
action will run C<pwd> from a shell if invoked.

=item C<createmailbox> [C<--partition> I<partition>] [C<--specialuse> I<specialuse>] I<mailbox>

=item C<create> [C<--partition> I<partition>] [C<--specialuse> I<specialuse>] I<mailbox>

=item C<create> [C<--specialuse> I<specialuse>] I<mailbox> I<partition>

=item C<cm> [C<--partition> I<partition>] [C<--specialuse> I<specialuse>] I<mailbox>

=item C<cm> [C<--specialuse> I<specialuse>] I<mailbox> I<partition>

Create a mailbox on the default or a specified partition.  Both old-style
and getopt-style usages are accepted (combining them will produce an error).
Optionally assign a special use to the mailbox.

=item C<deleteaclmailbox> I<mailbox> I<id> [...]

=item C<deleteacl> I<mailbox> I<id> [...]

=item C<dam> I<mailbox> I<id> [...]

Remove ACLs from the specified mailbox.

=item C<deletemailbox> I<mailbox>

=item C<delete> I<mailbox>

=item C<dm> I<mailbox>

Delete the specified mailbox.

Administrators do not have implicit delete rights on mailboxes.  Use the
B<setaclmailbox> command to grant the C<x> permission to your
principal if you need to delete a mailbox you do not own.

=item C<disconnect>

=item C<disc>

Disconnect from the current server.  The prompt will revert to C<cyradmE<gt>>.

=item C<exit> [I<number>]

=item C<quit> [I<number>]

Exit B<cyradm>, optionally with a specific exit status; the exit status of the
last command will be used if one is not specified.

=item help [command]

=item ? [command]

Show help for C<command> or all commands.

=item C<getmetadata> [I<mailbox>]

=item C<getmd> [I<mailbox>]

Display mailbox/server metadata

=item C<info> [I<mailbox>]

Display the mailbox/server annotations.

=item C<listaclmailbox> I<mailbox>

=item C<listacl> I<mailbox>

=item C<lam> I<mailbox>

List ACLs on the specified mailbox.

=item C<listmailbox> [C<--subscribed>] [C<--specialuse>] [I<pattern> [I<reference>]]

=item C<list> [C<--subscribed>] [C<--specialuse>] [I<pattern> [I<reference>]]

=item C<lm> [C<--subscribed>] [C<--specialuse>] [I<pattern> [I<reference>]]

List all, or all subscribed or special-use, mailboxes matching the specified
pattern.  The pattern may have embedded wildcards C<'*'> or C<'%'>, which
match anything or anything except the separator character, respectively.

Mailboxes returned will be relative to the specified reference if one
is specified.  This allows a mailbox list to be limited to a particular
hierarchy.

In some cases when the C<'%'> wildcard is used to end a pattern, it may
match an entry which is not a mailbox but which contains other mailboxes.
In this case, the entry will be parenthesized to indicate that it is a
root for other mailboxes, as opposed to a mailbox itself.

=item C<listquota> I<root>

=item C<lq> I<root>

List quotas on specified root.  If the specified mailbox path does not have
a quota assigned, an error will be raised; see I<listquotaroot> for a way to
find the quota root for a mailbox.

=item C<listquotaroot> I<mailbox>

=item C<lqm> I<mailbox>

=item C<lqr> I<mailbox?>

show quota roots and quotas for mailbox

=item C<mboxconfig> [C<--private>] I<mailbox> I<attribute> I<value>

=item C<mboxcfg> [C<--private>] I<mailbox> I<attribute> I<value>

Set mailbox metadata, optionally set the private instead of the shared
version of the metadata. A value of "none" will remove the attribute.

The currently supported attributes are:

=over 4

=item C<comment>

Sets a comment or description associated with the mailbox.

=item C<expire>

Sets the number of days after which messages will be expired from the mailbox.

=item C<news2mail>

Sets an email address to which messages injected into the server via NNTP
will be sent.

=item C<pop3showafter>

Sets a time (in RFC3501 format, for example "6-Jan-2011 11:45:32 +1100")
which specifies a cutoff date such that POP3 fetching of the folder does
not see messages whose internaldate is before or equal to the date.

=item C<sharedseen>

Enables the use of a shared \Seen flag on messages rather than a
per-user \Seen flag.  The 's' right in the mailbox ACL still controls
whether a user can set the shared \Seen flag.

=item C<sieve>

Indicates the name of the global sieve script that should be run when
a message is delivered to the shared mailbox (not used for personal
mailboxes).

=item C<squat>

Indicates that the mailbox should have a squat index created for it.

=item C</explicit/annotation>

Sets the annotation I</explicit/annotation> on I<mailbox> to I<value>.

=back

=item C<renamemailbox> [C<--partition> I<partition>] I<oldname> I<newname>

=item C<rename> [C<--partition> I<partition>] I<oldname> I<newname>

=item C<renm> [C<--partition> I<partition>] I<oldname> I<newname>

=item C<renamemailbox> I<oldname> I<newname> [I<partition>]

=item C<rename> I<oldname> I<newname> [I<partition>]

=item C<renm> I<oldname> I<newname> [I<partition>]

Rename the specified mailbox, optionally moving it to a different partition.
Both old-style and getopt-style usages are accepted; combining them will
produce an error.

=item server [--noauthenticate] [server]

=item connect [--noauthenticate] [server]

=item servername [--noauthenticate] [server]

With no arguments, show the current server.  With an argument, connect to that
server.  It will prompt for automatic login unless the C<--noauthenticate>
option is specified.  (This may change; in particular, either automatic
authentication will be removed or all C<authenticate> options will be added.)

When connected to a server, the B<cyradm> prompt changes from C<cyradmE<gt>> to
C<servernameE<gt>>, where I<servername> is the fully qualified domain name
of the connected server.

=item C<setaclmailbox> I<mailbox> I<id> I<rights> [I<id> I<rights> ...]

=item C<setacl> I<mailbox> I<id> I<rights> [I<id> I<rights> ...]

=item C<sam> I<mailbox> I<id> I<rights> [I<id> I<rights> ...]

Set ACLs on a mailbox.  The ACL may be one of the special strings C<none>,
C<read> (C<lrs>), C<post> (C<lrsp>), C<append> (C<lrsip>), C<write>
(C<lrswipkxten>), C<delete> (C<lrxten>), or C<all> (C<lrswipkxten>), or
any combinations of the ACL codes:

=over 4

=item l

Lookup (mailbox is visible to LIST/LSUB, SUBSCRIBE mailbox)

=item r

Read (SELECT/EXAMINE the mailbox, perform STATUS)

=item s

Seen (set/clear \SEEN flag via STORE, also set \SEEN flag during
    APPEND/COPY/FETCH BODY[...])

=item w

Write flags other than \SEEN and \DELETED

=item i

Insert (APPEND, COPY destination)

=item p

Post (send mail to mailbox)

=item k

Create mailbox (CREATE new sub-mailboxes, parent for new mailbox in RENAME)

=item x

Delete mailbox (DELETE mailbox, old mailbox name in RENAME)

=item t

Delete messages (set/clear \DELETED flag via STORE, also set \DELETED
    flag during APPEND/COPY)

=item e

Perform EXPUNGE and expunge as part of CLOSE

=item a

Administer (SETACL/DELETEACL/GETACL/LISTRIGHTS)

=item n

Add, delete or modify annotations

=back

=item C<setinfo> I<attribute> I<value>

Set server metadata.  A value of "none" will remove the attribute.
The currently supported attributes are:

=over 4

=item C<motd>

Sets a "message of the day".  The message gets displayed as an ALERT after
authentication.

=item C<comment>

Sets a comment or description associated with the server.

=item C<admin>

Sets the administrator email address for the server.

=item C<shutdown>

Sets a shutdown message.  The message gets displayed as an ALERT and
all users are disconnected from the server (subsequent logins are disallowed).

=item C<expire>

Sets the number of days after which messages will be expired from the
server (unless overridden by a mailbox annotation).

=item C<squat>

Indicates that all mailboxes should have a squat indexes created for
them (unless overridden by a mailbox annotation).

=back

=item C<setmetadata> [--private] mailbox [I<annotation>] I<value>

=item C<setmd> [--private] mailbox [I<annotation>] I<value>

Set metadata on mailbox, where <annotation> is one of
[comment|expire|news2mail|pop3showafter|sharedseen|sieve|specialuse|
squat|/<explicit annotation>].

Note that flags with a leading backslash must be escaped with an
additional backslash.  For example:

=over 4

  setmetadata --private Spam specialuse "\\Junk"

=back

Note, too, that "private" annotations are private to the user currently
authenticated as, not necessarily the owner of the mailbox.  To set
annotations for another user you must authorize as that user.

In addition to the use of optional flag B<--private>, one may use a more
explicit syntax, prefixing the annotation with '/shared/' or '/private/'
as in this example:

=over 4

  setmetadata Spam /private/specialuse "\\Junk"

=back

=item C<setquota> I<root> I<resource> I<value> [I<resource> I<value> ...]

=item C<sq> I<root> I<resource> I<value> [I<resource> I<value> ...]

Set a quota on the specified root, which may or may not be an actual mailbox.
The only I<resource> understood by B<Cyrus> is C<STORAGE>.  The I<value> may
be the special string C<none> which will remove the quota.

=item C<version>

=item C<ver>

Display the version info of the current server.

=item C<xfermailbox> [C<--partition> I<partition>] I<mailbox> I<server>

=item C<xfer> [C<--partition> I<partition>] I<mailbox> I<server>

=item C<xfermailbox> I<mailbox> I<server> [I<partition>]

=item C<xfer> I<mailbox> I<server> [I<partition>]

Transfer (relocate) the specified mailbox to a different server.
Both old-style and getopt-style usages are accepted; combining them will
produce an error.

=back

=head1 NOTES

GNU-style long options must be given in their entirety; Tcl-style options
may be abbreviated.

Tcl-style options are provided as a compatibility feature.  They will
probably go away in the future.

Multiple commands can be given on a line, separated by C<';'> characters.

All commands set an exit status, which at present is not useful.

Unknown commands are passed to a subshell for execution.

The Tcl version of B<cyradm> is used for scripting as well as interactively.
While this is possible to a limited extent by use of the C<run> method,
scripting would normally be done with C<Cyrus::IMAP::Admin>, which is far
more flexible than either interactive C<cyradm> or the Tcl scripting
mechanism for Cyrus.

B<cyradm> understands B</bin/sh>-style redirection:  any command can have
its standard or error output redirected, with all B<sh>-style redirections
(except C<E<lt>E<gt>>) supported.  It does not currently understand pipes
or backgrounding.

If the C<Term::Readline::Perl> or C<Term::Readline::GNU> modules are
available, B<cyradm> will use it.

An alias facility is implemented internally, but no access is currently
provided to it.  This will change, if only to allow some of the predefined
aliases to be removed if they conflict with useful shell commands.

=head1 AUTHOR

Brandon S. Allbery, allbery@ece.cmu.edu

=head1 SEE ALSO

Cyrus::IMAP::Admin
Term::ReadLine
sh(1), perl(1), imapd(8).

=cut
