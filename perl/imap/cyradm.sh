#! /bin/sh
# 
# Copyright (c) 2000 Carnegie Mellon University.  All rights reserved.
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
#    prior written permission. For permission or any other legal
#    details, please contact  
#      Office of Technology Transfer
#      Carnegie Mellon University
#      5000 Forbes Avenue
#      Pittsburgh, PA  15213-3890
#      (412) 268-4387, fax: (412) 268-7395
#      tech-transfer@andrew.cmu.edu
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
#
# $Id: cyradm.sh,v 1.10 2002/05/25 19:57:49 leg Exp $
case "x$BASH_VERSION" in
x) exec perl -MCyrus::IMAP::Shell -e shell -- ${1+"$@"} ;;
*) exec perl -MCyrus::IMAP::Shell -e shell -- "$@" ;;
esac
echo "$0: how did I get here?" >&2
exit 1

=head1 NAME

cyradm - Cyrus administration shell, alter ego of Cyrus::IMAP::Shell

=head1 SYNOPSIS

  $ cyradm [--user user] [--[no]rc] [--systemrc file] [--userrc file] \
  > [--port n] [--auth mechanism] [--server] server

but possibly

  $ perl -MCyrus::IMAP::Shell -e 'run("myscript")'

or even (not recommended)

  use IMAP::Admin::Shell;

  run('myscriptname');

=head1 DESCRIPTION

This module implements B<cyradm> in Perl.  It is a shell around
L<Cyrus::IMAP::Admin>.  Commands are provided in both Tcl-compatible
forms and GNU-style long option forms.

=head1 COMMANDS

=over 4

=item C<authenticate> [C<--minssf> I<N>] [C<--maxssf> I<N>] [C<--mechanisms> I<list>] [I<user>]

=item C<auth> [C<--minssf> I<N>] [C<--maxssf> I<N>] [C<--mechanisms> I<list>] [I<user>]

=item C<login> [C<--minssf> I<N>] [C<--maxssf> I<N>] [C<--mechanisms> I<list>] [I<user>]

Authenticate to server.  You must already be connected to a server and
Cyrus imapd will refuse to allow you to re-authenticate once you have
authenticated once.

=item C<chdir> I<directory>

=item C<cd> I<directory>

Change directory.  A C<pwd> builtin is not provided, but the default command
action will run C<pwd> from a shell if invoked.

=item C<createmailbox> [C<--partition> I<partition>] I<mailbox>

=item C<createmailbox> I<mailbox> I<partition>

=item C<create> [C<--partition> I<partition>] I<mailbox>

=item C<create> I<mailbox> I<partition>

=item C<cm> [C<--partition> I<partition>] I<mailbox>

=item C<cm> I<mailbox> I<partition>

Create a mailbox on the default or a specified partition.  Both old-style
and getopt-style usages are accepted (combining them will produce an error).

=item C<deleteaclmailbox> I<mailbox> I<id> [...]

=item C<deleteacl> I<mailbox> I<id> [...]

=item C<dam> I<mailbox> I<id> [...]

Remove ACLs from the specified mailbox.

=item C<deletemailbox> I<mailbox>

=item C<delete> I<mailbox>

=item C<dm> I<mailbox>

Delete the specified mailbox.

Administrators do not have implicit delete rights on mailboxes.  Use the
B<setaclmailbox> command to grant the C<d> permission to your principal
if you need to delete a mailbox you do not own.

Note that the online help admits to an optional host argument.  This argument
is not currently used, and will be rejected with an error if specified; it
is reserved for IMSP.

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

=item C<info> [I<mailbox>]

Display the mailbox/server metadata.

=item C<listaclmailbox> I<mailbox>

=item C<listacl> I<mailbox>

=item C<lam> I<mailbox>

List ACLs on the specified mailbox.

=item C<listmailbox> [C<--subscribed>] [I<pattern> [I<reference>]]

=item C<list> [C<--subscribed>] [I<pattern> [I<reference>]]

=item C<lm> [C<--subscribed>] [I<pattern> [I<reference>]]

List all, or all subscribed, mailboxes matching the specified pattern.
The pattern may have embedded wildcards C<'*'> or C<'%'>, which match
anything or anything except the separator character, respectively.

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

When connected to a server, B<cyradm>'s prompt changes from C<cyradmE<gt>> to
C<servernameE<gt>>, where I<servername> is the fully qualified domain name
of the connected server.

=item C<setaclmailbox> I<mailbox> I<id> I<rights> [I<id> I<rights> ...]

=item C<setacl> I<mailbox> I<id> I<rights> [I<id> I<rights> ...]

=item C<sam> I<mailbox> I<id> I<rights> [I<id> I<rights> ...]

Set ACLs on a mailbox.  The ACL may be one of the special strings C<none>,
C<read> (C<lrs>), C<post> (C<lrsp>), C<append> (C<lrsip>), C<write>
(C<lrswipcd>), or C<all> (C<lrswipcda>), or any combinations of the ACL codes:

=over 4

=item l

Lookup (visible to LIST/LSUB/UNSEEN)

=item r

Read (SELECT, CHECK, FETCH, PARTIAL, SEARCH, COPY source)

=item s

Seen (STORE \SEEN)

=item w

Write flags other than \SEEN and \DELETED

=item i

Insert (APPEND, COPY destination)

=item p

Post (send mail to mailbox)

=item c

Create and Delete mailbox (CREATE new sub-mailboxes, RENAME or DELETE mailbox)

=item d

Delete (STORE \DELETED, EXPUNGE)

=item a

Administer (SETACL)

=back

=item C<setquota> I<root> I<resource> I<value> [I<resource> I<value> ...]

=item C<sq> I<root> I<resource> I<value> [I<resource> I<value> ...]

Set a quota on the specified root, which may or may not be an actual mailbox.
The only I<resource> understood by B<Cyrus> is C<STORAGE>.  The I<value> may
be the special string C<none> which will remove the quota.

=item C<version>

=item C<ver>

Display the version info of the current server.

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
