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
# A shell framework for Cyrus::IMAP::Admin
#
# run(*FH|'FH')
#       read commands from the filehandle and pass to exec(); defaults to
#       __DATA__
# shell
#       = run(*STDIN)
#
# This isn't derived from CPAN.pm, first because I need to support the stuff
# that makes it act at least somewhat like the old cyradm and second because
# I'm pretty sure this will have to be released under the crappy TTO license
# instead of the GPL/Artistic License.
#

package Cyrus::IMAP::Shell;
use strict;

use IO::File;
use Cyrus::IMAP::Admin;
use Getopt::Long qw(:config no_ignore_case);
use Exporter;
use POSIX ();
use Carp qw(confess);

use vars qw(@ISA @EXPORT $VERSION *cyradm);
$VERSION = "1.00";
@ISA = qw(Exporter);
@EXPORT = qw(cyradm shell run);

# note aliases
my %builtins = (exit =>
                  [\&_sc_exit, '[number]', 'exit cyradm'],
                quit => 'exit',
                help =>
                  [\&_sc_help, '[command]', 'show commands'],
                '?' => 'help',
                lam => 'listacl',
                listacl =>
                  [\&_sc_listacl, 'mailbox', 'list ACLs on mailbox'],
                listaclmailbox => 'listacl',
                lm => 'listmailbox',
                listmailbox =>
                  [\&_sc_list, '[-subscribed] [-specialuse] [pattern [base]]',
                   'list mailboxes'],
                server =>
                  [\&_sc_server, '[-noauthenticate] [server]',
                   'show current server or connect to server'],
                servername => 'server',
                connect => 'server',
                authenticate =>
                  [\&_sc_auth,
                   '[-minssf N] [-maxssf N] [-mechanisms list] [-service name] [-tlskey keyfile] [-notls] [-cafile cacertfile] [-capath cacertdir] [user]',
                   'authenticate to server'],
                auth => 'authenticate',
                login => 'authenticate',
                listquota =>
                  [\&_sc_quota, 'root', 'list quotas on specified root'],
                lq => 'listquota',
                listquotaroot =>
                  [\&_sc_quotaroot, 'mailbox',
                   'show quota roots and quotas for mailbox'],
                lqr => 'listquotaroot',
                lqm => 'listquotaroot',
                disconnect =>
                  [\&_sc_disconn, '', 'disconnect from current server'],
                disc => 'disconnect',
                chdir =>
                  [\&_sc_chdir, 'directory', 'change current directory'],
                cd => 'chdir',
                createmailbox =>
                  [\&_sc_create, '[--partition partition] [--specialuse specialuse] mailbox [partition]',
                   'create mailbox'],
                create => 'createmailbox',
                cm => 'createmailbox',
                deleteaclmailbox =>
                  [\&_sc_deleteacl, 'mailbox id [id ...]',
                   'remove ACLs from mailbox'],
                deleteacl => 'deleteaclmailbox',
                dam => 'deleteaclmailbox',
                deletemailbox =>
                  [\&_sc_delete, 'mailbox [host]', 'delete mailbox'],
                delete => 'deletemailbox',
                dm => 'deletemailbox',
                getmetadata =>
                  [\&_sc_getmetadata, '[mailbox]',
                   'display mailbox/server metadata'],
                getmd => 'getmetadata',
                info =>
                  [\&_sc_info, '[mailbox]',
                   'display mailbox/server annotations'],
                mboxcfg =>
                  [\&_sc_mboxcfg, '[--private] mailbox [comment|expire|news2mail|sieve|squat|/<explicit annotation>] value',
                   'configure mailbox'],
                mboxconfig => 'mboxcfg',
                reconstruct =>
                  [\&_sc_reconstruct, 'mailbox', 'reconstruct mailbox (if supported)'],
                renamemailbox =>
                  [\&_sc_rename,
                   '[--partition partition] oldname newname [partition]',
                   'rename (and optionally relocate) mailbox'],
                rename => 'renamemailbox',
                renm => 'renamemailbox',
                setaclmailbox =>
                  [\&_sc_setacl, 'mailbox id rights [id rights ...]',
                   'set ACLs on mailbox'],
                setacl => 'setaclmailbox',
                sam => 'setaclmailbox',
                setinfo =>
                  [\&_sc_setinfo, '[motd|comment|admin|shutdown|expire|squat] text',
                   'set server metadata'],
                setmetadata =>
                  [\&_sc_setmetadata, '[--private] mailbox [comment|expire|news2mail|pop3showafter|sharedseen|sieve|specialuse|squat|/<explicit annotation>] value',
                   'set metadata to mailbox'],
                setmd => 'setmetadata',
                setquota =>
                  [\&_sc_setquota,
                   'mailbox resource value [resource value ...]',
                   'set quota on mailbox or resource'],
                sq => 'setquota',
                version =>
                  [\&_sc_version, '',
                   'display version info of current server'],
                ver => 'version',
                xfermailbox =>
                  [\&_sc_xfer,
                   '[--partition partition] mailbox server [partition]',
                   'transfer (relocate) a mailbox to a different server'],
                xfer => 'xfermailbox',
                subscribe =>
                  [\&_sc_subscribe, '[mailbox]',
                    'subscribe to a mailbox'],
                sub => 'subscribe',
                unsubscribe =>
                  [\&_sc_unsubscribe, '[mailbox]',
                     'unsubscribe from a mailbox'],
                unsub => 'unsubscribe',
                #? alias
                #? unalias
                #? load
                #? unload
               );

# ugh.  ugh.  suck.  aieee.
my $use_rl = 'Cyrus::IMAP::DummyReadline';
{
  if (eval { require Term::ReadLine; }) {
    $use_rl = 'Term::ReadLine';
  }
}

# callback when stream closes
sub _cb_eof {
  my %cb = @_;
  # indicate that the connection went away
  print STDERR "\nConnection to server lost.\n";
  ${$cb{-rock}} = undef;
}

# okay, this sucks.  the alternatives are worse.
my $coll_command = '';

# originally I used Text::ParseWords::shellwords; unfortunately, that is a
# bit inaccurate because it doesn't word-break at shell metacharacters.  which
# I need.  (also need to know when a metachar is a metachar on return.
sub _nexttoken {
  my $lr = shift;
  $$lr =~ s/^(\s+)// and $coll_command .= $1;
  my $quoted = 0;
  my $q = '';

  my @tok = ('', undef);
  # this is cute.  (shells are funny that way)
  # we parse "words" which are delimited by whitespace.  except that if a
  # quote appears, we have to gobble to the closing quote and then continue
  # with what we were doing.  and outside quotes, we need to look for special
  # characters (in this case, /&<>;/) and break "words" there.
  while ($$lr ne '' && ($quoted || $$lr !~ /^\s/)) {
    $tok[1] ||= 0;
    if ($q eq '' && $$lr =~ /^([&<>;])/) {
      last if $tok[0] ne '';
      $tok[0] = $1;
      $coll_command .= $1;
      $$lr =~ s///;
      $tok[1] = 1;
      last;
    }
    if ($$lr =~ /^([^&<>;\'\"\$\\\s]+)/) {
      $tok[0] .= $1;
      $coll_command .= $1;
      $$lr =~ s///;
      next;
    }
    if ($$lr =~ /^\\(.)/) {
      # gack.  "consistency?  wazzat?"
      $coll_command .= "\\" . $1;
      $tok[0] .= "'" if $q eq "'" && $1 ne "'";
      $tok[0] .= $1;
      $$lr =~ s///;
      next;
    }
    if ($$lr =~ /^\$(\{(\w+)\}|(\w+))/) {
      $coll_command .= "\$" . $1;
      # if someone asks for shell var qualifiers I will kill them
      $$lr =~ s//$ENV{$+}/;
      $$lr =~ s/^(\s+)// and $coll_command .= $1 if $q;
      redo;
    }
    if ($$lr =~ /^([\'\"])/ && $q eq 'x') {
      $q = '';
      $coll_command .= $1;
      $$lr =~ s///;
      $quoted = !$quoted;
      next;
    }
    if ($$lr =~ /^([\'\"])/ && $q eq '') {
      $q = 'x';
      $coll_command .= $1;
      $$lr =~ s///;
      $quoted = !$quoted;
      next;
    }
    $$lr =~ s/^(.)//;
    $tok[0] .= $1;
    $coll_command .= $1;
  }
  @tok;
}

# relatively trivial... except for the shell fallback.
sub _execvv {
  my ($cyrref, $cmd, $av0, $fa, $lfa, @argv) = @_;
  while (defined($builtins{$av0}) && !ref($builtins{$av0})) {
    $av0 = $builtins{$av0};
  }
  if (defined($builtins{$av0})) {
    &{$builtins{$av0}[0]}($cyrref, $av0, $fa, $lfa, @argv);
  }
  else {
    my $pid = fork;
    if (!defined($pid)) {
      die "fork: $!\n";
    }
    elsif ($pid) {
      waitpid($pid, 0);
    }
    else {
      $argv[0] =~ s!^.*/!!;
      my $fd = 0;
      # process redirections in $fa
      # sorted so lower $lfa->[$fh]->fileno consumed before $fh!
      foreach my $fh (sort {$a->fileno <=> $b->fileno} @$lfa) {
        if (!defined($fh)) {
          POSIX::close($fd);
        } else {
          POSIX::dup2($fh->fileno, $fd);
        }
        $fd++;
      }
      foreach my $fh (@$lfa) {
        POSIX::close($fd) if defined($fh) && $fh->fileno > $fd;
      }
      # anything else left open is just lost.  sorry.
      exec $cmd;
      die "$av0: $!\n";
    }
  }
}

# wrapper to trap errors and report them.
# (there are two such, one for "program" errors and one for "shell" errors...)
sub _execv {
  my ($cyrref, $cmd, $av0, $fa, $lfa, @argv) = @_;
  my $rc;
  local($@);
  if (!defined(eval { $rc = &_execvv; })) {
    $lfa->[2]->print($@);
    $lfa->[2]->print("\n") unless substr($@, -1, 1) eq "\n";
    $rc = -1;
  }
}

# ick
sub _redir {
  my ($fha, $op, $dst, $src) = @_;
  my ($rop, $amp);
  if ($op =~ s/\&$//) {
    $amp = '&';
  } else {
    $amp = '';
  }
  if ($op eq '>') {
    $rop = O_WRONLY|O_CREAT|O_TRUNC;
    $src = 1 if !defined($src) || $src eq '';
  }
  elsif ($op eq '>>') {
    $rop = O_WRONLY|O_CREAT|O_APPEND;
    $src = 1 if !defined($src) || $src eq '';
  }
  elsif ($op eq '<') {
    $rop = O_RDONLY;
    $src = 0 if !defined($src) || $src eq '';
  }
  else {
    die "can't handle \`$op' redirection\n";
  }
  if ($amp) {
    die "invalid file descriptor \`$dst'\n" if $dst ne '-' && $dst != /^\d+$/;
    if ($dst eq '-') {
      $fha->[$src] = undef;
    }
    elsif (!defined($fha->[$dst])) {
      die "file descriptor \`$dst' not open\n";
    }
    else {
      $fha->[$src] = IO::File->new("$op&" . $fha->[$dst]->fileno);
    }
  } else {
    $fha->[$src] = IO::File->new($dst, $rop) or die "$dst: $!\n";
  }
}

# this was once trivial, then I added parsing for redirection...
sub _exec {
  my ($cyrref, $fa, $cmd) = @_;
  $fa ||= [*STDIN, *STDOUT, *STDERR];
  # clone it:  only "exec" has permanent effects on the fh stack
  my $lfa = [@$fa];
  my @argv = ();
  my $state = '';
  my ($tok, $type);
  while (($tok, $type) = _nexttoken(\$cmd) and defined($type)) {
    if (!$type) {
      if ($state eq '') {
        # @@ here is where we should do aliasing, if we do it at all
        push(@argv, $tok);
      }
      else {
        # at this point, $state is the redirection (/^([<>])\1?\&?$/) and
        # $arg->[0] is the destination.  if $argv[$#argv] matches /^\d+$/,
        # it is the affected file handle.
        my $target;
        $target = pop(@argv) if $argv[-1] =~ /^\d+$/;
        _redir($lfa, $state, $tok, $target);
        $state = '';
      }
    }
    elsif ($tok eq ';') {
      _execv($cyrref, $coll_command, $argv[0], $fa, $lfa, @argv);
      $coll_command = '';
      @argv = ();
    }
    elsif ($tok eq '&') {
      if ($state ne '<' && $state ne '>') {
        die "syntax error: cannot deal with \`&' here\n";
      }
      $state .= '&';
    }
    elsif ($tok eq '<' || $tok eq '>') {
      if ($state ne '' && ($state ne $tok || $state eq '<')) {
        die "syntax error: cannot deal with \`$tok' here\n";
      }
      $state .= $tok;
    }
    else {
      die "syntax error: don't understand \`$tok'\n";
    }
  }
  if (@argv) {
    _execv($cyrref, $coll_command, $argv[0], $fa, $lfa, @argv);
    $coll_command = '';
  }
}

# not too horrible
sub _run {
  my $cyradm = shift;
  my $fstk = shift || [*STDIN, *STDOUT, *STDERR];
  my $fin = shift || $fstk->[0] || *STDIN;
  my ($hfh, $line);
  $hfh = $use_rl->new('cyradm shell', $fin, $fstk->[1]);
  $hfh->ornaments(0);
  my $rc;
  while (defined ($line = $hfh->readline((defined $$cyradm ?
                                          $$cyradm->servername :
                                          'cyradm') . '> '))) {
    local($@);
    if (!defined(eval { $rc = _exec($cyradm, $fstk, $line); })) {
      $fstk->[2]->print($@);
      $fstk->[2]->print("\n") unless substr($@, -1, 1) eq "\n";
      $rc = -1;
    }
  }
  $rc;
}

# trivial; wrapper for _run with correct setup
sub run {
  my $cyradm;
  _run(\$cyradm, [*STDIN, *STDOUT, *STDERR], *__DATA__);
}

# All the real work is done by _run(); this is a convenience wrapper.
# (It's not as trivial as run() because it does things expected of standalone
# programs, as opposed to things expected from within a program.)
sub shell {
  my ($server, $port, $authz, $auth, $systemrc, $userrc, $dorc, $mech, $pw,
      $tlskey, $notls, $cacert, $capath) =
    ('', 143, undef, $ENV{USER} || $ENV{LOGNAME}, '/usr/local/etc/cyradmrc.pl',
     "$ENV{HOME}/.cyradmrc.pl", 1, undef, undef, undef, undef, undef, undef);
  GetOptions('user|u=s' => \$auth,
             'authz|z=s' => \$authz,
             'rc|r!' => \$dorc,
             'systemrc|S=s' => \$systemrc,
             'userrc=s' => \$userrc,
             'server|s=s' => \$server,
             'port|p=i' => \$port,
             'auth|a=s' => \$mech,
             'password|w=s' => \$pw,
             'tlskey|t:s' => \$tlskey,
             'notls' => \$notls,
             'cafile=s' => \$cacert,
             'cadir=s' => \$capath,
             'capath=s' => \$capath,
             'help|h' => sub { cyradm_usage(); exit(0); },
             'version|v' => sub { cyradm_version(); exit(0); }
            );
  if ($server ne '' && @ARGV) {
    die "cyradm: may not specify server both with --server and bare arg\n";
  }
  if (@ARGV) {
    $server = shift(@ARGV);
    $port = shift(@ARGV) if @ARGV;
    cyradm_usage() if @ARGV;
  }
  my $cyradm;
  if ($server ne '') {
    $cyradm = Cyrus::IMAP::Admin->new($server, $port)
      or die "cyradm: cannot connect to server\n";
    $cyradm->addcallback({-trigger => 'EOF',
                          -callback => \&_cb_eof,
                          -rock => \$cyradm});
    $cyradm->authenticate(-authz => $authz, -user => $auth,
                          -mechanism => $mech, -password => $pw,
                          -tlskey => $tlskey, -notls => $notls,
                          -cafile => $cacert, -capath => $capath)
      or die "cyradm: cannot authenticate to server" . (defined($mech)?" with $mech":"") . " as $auth\n";
  }
  my $fstk = [*STDIN, *STDOUT, *STDERR];
  if ($dorc && $systemrc ne '' && -f $systemrc) {
    my $fh = IO::File->new($systemrc, O_RDONLY);
    _run(\$cyradm, $fstk, *$fh) if $fh;
  }
  if ($dorc && $userrc ne '' && -f $userrc) {
    my $fh = IO::File->new($userrc, O_RDONLY);
    _run(\$cyradm, $fstk, *$fh) if $fh;
  }
  _run(\$cyradm, $fstk, *STDIN);
}
*cyradm = \&shell;

###############################################################################

# show cyradm command line arguments
sub cyradm_usage {
  print <<'END_OF_HELP';
Usage: cyradm [args] server
  --user <user>         Connect as <user> (authentication name)
  --authz <user>        Authorize as <user>
  --[no]rc              (Do not) load the configuration files
  --systemrc <file>     Use system-wide configuration <file>
  --userrc <file>       Use user configuration <file>
  --port <port>         Connect to server on <port>
  --auth <mechanism>    Authenticate with <mechanism>
  --tlskey <keyfile>    Use certificate with keyfile to authenticate with server
  --notls               Disable StartTLS negotiation
  --cafile <cacertfile> Use CA certificate file to validate server certificate
  --cadir <cacertdirectory> Use CA certificate directory to validate
                            server certificate
  --help                This help message
  --version             The version of Cyrus IMAP this utility is a part of

Defaults to interactive mode. Please see man cyradm(1) and the 'help' command
in the cyradm-shell for details.
END_OF_HELP
}

# show cyradm version
sub cyradm_version {
  print "version: Cyrus IMAP $VERSION\n";
}

# help display
sub do_help {
  my ($fd, $cmd, @list) = @_;
  if (!@list || grep($_ eq $cmd, @list)) {
    unless (defined($builtins{$cmd})) {
      $fd->print("unknown command: $cmd\n");
      return 0;
    }
    if (!ref($builtins{$cmd})) {
      $fd->print("$cmd, alias for ");
      do_help($fd, $builtins{$cmd}, $builtins{$cmd}, @list);
    } else {
      $fd->print("$cmd $builtins{$cmd}[1]\n\t$builtins{$cmd}[2]\n");
    }
  }
  1;
}

sub _sc_help {
  my ($cyrref, $name, $fh, $lfh, @argv) = @_;
  my (@nargv, $opt, $rc);
  shift(@argv);
  while (defined ($opt = shift(@argv))) {
    last if $opt eq '--';
    if ($opt =~ /^-/) {
      die "usage: help [command]\n";
    }
    else {
      push(@nargv, $opt);
      last;
    }
  }
  push(@nargv, @argv);
  $rc = 0;
  if (@nargv) {
    foreach my $cmd (sort {$a cmp $b} @nargv) {
      $rc = 1 if !do_help($lfh->[1], $cmd, @nargv);
    }
  } else {
    # compress commands and their aliases, plus one line of help
    my %cmds;
    my $cmd;
    foreach $cmd (keys %builtins) {
      if (ref($builtins{$cmd})) {
        $cmds{$cmd} ||= [[], ''];
        $cmds{$cmd}[1] = $builtins{$cmd}[2];
      } else {
        $cmds{$builtins{$cmd}} ||= [[], ''];
        push(@{$cmds{$builtins{$cmd}}[0]}, $cmd);
      }
    }
    my $nwid = 0;
    foreach $cmd (keys %cmds) {
      $cmds{$cmd}[0] = join(', ', $cmd, @{$cmds{$cmd}[0]});
      $nwid = length($cmds{$cmd}[0]) if $nwid < length($cmds{$cmd}[0]);
    }
    foreach $cmd (sort {$a cmp $b} keys %cmds) {
      $lfh->[1]->printf("%-*s  %s\n", $nwid, $cmds{$cmd}[0], $cmds{$cmd}[1]);
    }
  }
  $rc;
}

sub _sc_exit {
  my ($cyrref, $name, $fh, $lfh, @argv) = @_;
  my (@nargv, $opt);
  shift(@argv);
  while (defined ($opt = shift(@argv))) {
    last if $opt eq '--';
    if ($opt =~ /^-/) {
      die "usage: exit [number]\n";
    }
    else {
      push(@nargv, $opt);
      last;
    }
  }
  push(@nargv, @argv);
  if (@nargv > 1) {
    die "usage: exit [number]\n";
  }
  push(@nargv, 0) if !@nargv;
  exit $nargv[0];
}

sub _sc_list {
  my ($cyrref, $name, $fh, $lfh, @argv) = @_;
  my $cmd = 'listmailbox';
  my (@nargv, $opt, %opts, $subscribed);
  shift(@argv);
  while (defined ($opt = shift(@argv))) {
    # gack.  bloody tcl.
    last if $opt eq '--';
    if ($opt ne '' && '-subscribed' =~ /^\Q$opt/ || $opt eq '--subscribed') {
      $subscribed = 1;
    } elsif ($opt ne '' && '-specialuse' =~ /^\Q$opt/ || $opt eq '--specialuse') {
      $opts{'-sel-special-use'} = 1;
    } elsif ($opt ne '' && '-recursivematch' =~ /^\Q$opt/ || $opt eq '--recursivematch') {
      $opts{'-sel-recursivematch'} = 1;
    }
    elsif ($opt =~ /^-/) {
      die "usage: listmailbox [-subscribed] [-specialuse] [pattern [base]]\n";
    }
    else {
      push(@nargv, $opt);
      last;
    }
  }

  if ($subscribed) {
    if (scalar (keys %opts) > 0 ) {
      # LIST + LIST-EXTENDED
      $opts{'-sel-subscribed'} = 1;
    } else {
      # LSUB
      $cmd = 'listsubscribed';
      # undef %opts;
    }
  }

  push(@nargv, @argv);
  if (@nargv > 2) {
    die "usage: listmailbox [-subscribed] [-specialuse] [pattern [base]]\n";
  }
  push(@nargv, '*') if !@nargv;
  push(@nargv, undef) if scalar (@nargv) < 2; # no ref
  push(@nargv, \%opts);
  if (!$cyrref || !$$cyrref) {
    die "listmailbox: no connection to server\n";
  }
  my ($l, $w, @l);
  my @res = $$cyrref->$cmd(@nargv);
  if (defined $$cyrref->error) {
    $lfh->[2]->print($$cyrref->error, "\n");
    return 1;
  }
  foreach my $mbx (@res) {
    $l = $mbx->[0];
    if ($mbx->[1] ne '') {
      $l .= ' (' . $mbx->[1] . ')';
    }
    if (defined ($mbx->[3])) {
      $l .= ' (' . $mbx->[3] . ')';
    }
    if (length($l) + 1 > $w) {
      $w = length($l) + 1;
    }
    push(@l, $l);
  }
  return 1 if !@l;
  @l = sort {$a cmp $b} @l;
  my $ll = $ENV{COLUMNS} || 79;
  $w = $ll if $w > $ll;
  my $n = int($ll / $w);
  my $c;
  for ($l = 0; $l < int((@l + $n - 1) / $n); $l++) {
    for ($c = 0; $c < @l; $c += int((@l + $n - 1) / $n)) {
      if ($l + $c < @l) {
        $lfh->[1]->print($l[$l + $c], ' ' x ($w + 1 - length($l[$l + $c])));
      }
    }
    $lfh->[1]->print("\n");
  }
  0;
}

sub _sc_listacl {
  my ($cyrref, $name, $fh, $lfh, @argv) = @_;
  my (@nargv, $opt);
  shift(@argv);
  while (defined ($opt = shift(@argv))) {
    # gack.  bloody tcl.
    last if $opt eq '--';
    if ($opt =~ /^-/) {
      die "usage: listaclmailbox mailbox\n";
    }
    else {
      push(@nargv, $opt);
      last;
    }
  }
  push(@nargv, @argv);
  if (@nargv != 1) {
    die "usage: listaclmailbox mailbox\n";
  }
  if (!$cyrref || !$$cyrref) {
    die "listaclmailbox: no connection to server\n";
  }

  if($nargv[0] =~ /(\*|%)/) {
    # list operation
    my @res = $$cyrref->listmailbox(($nargv[0]));
    foreach my $mbx (@res) {
      my $name = $mbx->[0];
      my $flags = $mbx->[1];
      next if($flags =~ /(\\noselect|\\nonexistent|\\placeholder)/i);
      $lfh->[1]->print($name,":\n");
      my %acl = $$cyrref->listaclmailbox($name);
      if (defined $$cyrref->error) {
         $lfh->[2]->print($$cyrref->error, "\n");
         next;
      }
      foreach my $acl (keys %acl) {
        $lfh->[1]->print("  ", $acl, " ", $acl{$acl}, "\n");
      }
    }
  } else {
    my %acl = $$cyrref->listaclmailbox(@nargv);
    if (defined $$cyrref->error) {
       $lfh->[2]->print($$cyrref->error, "\n");
       return 1;
    }

    foreach my $acl (keys %acl) {
      $lfh->[1]->print($acl, " ", $acl{$acl}, "\n");
    }
  }
  return 0;
}

sub _sc_server {
  my ($cyrref, $name, $fh, $lfh, @argv) = @_;
  my (@nargv, $opt, $auth);
  shift(@argv);
  $auth = 1;
  while (defined ($opt = shift(@argv))) {
    last if $opt eq '--';
    if ($opt ne '' && '-noauthenticate' =~ /^\Q$opt/ ||
        $opt eq '--noauthenticate') {
      $auth = 0;
      next;
    }
    if ($opt =~ /^-/) {
      die "usage: server [-noauthenticate] [server]\n";
    }
    else {
      push(@nargv, $opt);
      last;
    }
  }
  push(@nargv, @argv);
  if (!@nargv) {
    if (!$cyrref || !$$cyrref) {
      die "server: no connection to server\n";
    }
    $lfh->[1]->print($$cyrref->servername, "\n");
    0;
  }
  elsif (@nargv == 1) {
    $$cyrref = Cyrus::IMAP::Admin->new($nargv[0])
      or die "server: $nargv[0]: cannot connect to server\n";
    if ($auth) {
      $$cyrref->authenticate or die "server: $nargv[0]: cannot authenticate\n";
    }
    0;
  }
  else {
    die "usage: server [-noauthenticate] [server]\n";
  }
}

sub _sc_auth {
  my ($cyrref, $name, $fh, $lfh, @argv) = @_;
  my (@nargv, $opt, %opts, $want);
  shift(@argv);
  while (defined ($opt = shift(@argv))) {
    if (defined $want) {
      $opts{$want} = $opt;
      $want = undef;
      next;
    }
    last if $opt eq '--';
    if ($opt ne '' && '-mechanisms' =~ /^\Q$opt/ || $opt eq '--mechanisms') {
      $want = '-mechanism';
      next;
    }
    if ($opt ne '' && '-minssf' =~ /^\Q$opt/ || $opt eq '--minssf') {
      $want = '-minssf';
      next;
    }
    if ($opt ne '' && '-maxssf' =~ /^\Q$opt/ || $opt eq '--maxssf') {
      $want = '-maxssf';
      next;
    }
    if ($opt ne '' && '-service' =~ /^\Q$opt/ || $opt eq '--service') {
      $want = '-service';
      next;
    }
    if (Cyrus::IMAP::havetls()) {
      if ($opt ne '' && '-tlskey' =~ /^\Q$opt/ || $opt eq '--tlskey') {
        $want = '-tlskey';
        next;
      }
      if ($opt ne '' && '-notls' =~ /^\Q$opt/ || $opt eq '--notls') {
        $want = '-notls';
        next;
      }
      if ($opt ne '' && '-cafile' =~ /^\Q$opt/ || $opt eq '--cafile') {
        $want = '-cafile';
        next;
      }
      if ($opt ne '' && '-cadir' =~ /^\Q$opt/ || $opt eq '--cadir') {
        $want = '-capath';
        next;
      }
      if ($opt ne '' && '-capath' =~ /^\Q$opt/ || $opt eq '--capath') {
        $want = '-capath';
        next;
      }
      if ($opt =~ /^-/) {
        die "usage: authenticate [-minssf N] [-maxssf N] [-mechanisms STR]\n".
            "                    [-service name] [-tlskey keyfile] [-notls]\n".
            "                    [-cafile cacertfile] [-capath cacertdir]\n".
            "                    [user]\n";
      }
    }
    if ($opt =~ /^-/) {
      die "usage: authenticate [-minssf N] [-maxssf N] [-mechanisms STR]\n".
          "                    [-service name] [user]\n";
    }
    else {
      push(@nargv, $opt);
      last;
    }
  }
  push(@nargv, @argv);
  if (@nargv > 1) {
    if (Cyrus::IMAP::havetls()) {
      die "usage: authenticate [-minssf N] [-maxssf N] [-mechanisms STR]\n".
          "                    [-service name] [-tlskey keyfile] [-notls]\n".
          "                    [-cafile cacertfile] [-capath cacertdir]\n".
          "                    [user]\n";
    } else {
      die "usage: authenticate [-minssf N] [-maxssf N] [-mechanisms STR]\n".
          "                    [-service name] [user]\n";
    }
  }
  if (@nargv) {
    $opts{-user} = shift(@nargv);
  }
  if (!$cyrref || !$$cyrref) {
    die "authenticate: no connection to server\n";
  }
  unless ($$cyrref->authenticate(%opts)) {
    my $sn = $$cyrref->servername;
    die "authenticate: authentication to server $sn failed\n";
  }
  0;
}

sub _sc_quota {
  my ($cyrref, $name, $fh, $lfh, @argv) = @_;
  my (@nargv, $opt);
  shift(@argv);
  while (defined ($opt = shift(@argv))) {
    # gack.  bloody tcl.
    last if $opt eq '--';
    if ($opt =~ /^-/) {
      die "usage: listquota root\n";
    }
    else {
      push(@nargv, $opt);
      last;
    }
  }
  push(@nargv, @argv);
  if (@nargv != 1) {
    die "usage: listquota root\n";
  }
  if (!$cyrref || !$$cyrref) {
    die "listquota: no connection to server\n";
  }
  my %quota = $$cyrref->listquota(@nargv);
  foreach my $quota (keys %quota) {
    $lfh->[1]->print(" ", $quota, " ", $quota{$quota}[0], "/",
                     $quota{$quota}[1]);
    if ($quota{$quota}[1]) {
      $lfh->[1]->print(" (", $quota{$quota}[0] * 100 / $quota{$quota}[1], "%)");
    }
  }
  $lfh->[1]->print("\n");
  0;
}

sub _sc_quotaroot {
  my ($cyrref, $name, $fh, $lfh, @argv) = @_;
  my (@nargv, $opt);
  shift(@argv);
  while (defined ($opt = shift(@argv))) {
    # gack.  bloody tcl.
    last if $opt eq '--';
    if ($opt =~ /^-/) {
      die "usage: listquotaroot mailbox\n";
    }
    else {
      push(@nargv, $opt);
      last;
    }
  }
  push(@nargv, @argv);
  if (@nargv != 1) {
    die "usage: listquotaroot mailbox\n";
  }
  if (!$cyrref || !$$cyrref) {
    die "listquotaroot: no connection to server\n";
  }
  my ($root, %quota) = $$cyrref->listquotaroot(@nargv);
  $lfh->[1]->print($root);
  my ($used, $tot);
  foreach my $quota (keys %quota) {
    ($used, $tot) = split(/ /, $quota{$quota});
    $lfh->[1]->print(" ", $quota, " ", $quota{$quota}[0], "/",
                     $quota{$quota}[1]);
    if ($quota{$quota}[1]) {
      $lfh->[1]->print(" (", $quota{$quota}[0] * 100 / $quota{$quota}[1], "%)");
    }
  }
  $lfh->[1]->print("\n");
  0;
}

sub _sc_disconn {
  my ($cyrref, $name, $fh, $lfh, @argv) = @_;
  my (@nargv, $opt);
  shift(@argv);
  while (defined ($opt = shift(@argv))) {
    # gack.  bloody tcl.
    last if $opt eq '--';
    if ($opt =~ /^-/) {
      die "usage: disconnect\n";
    }
    else {
      push(@nargv, $opt);
      last;
    }
  }
  push(@nargv, @argv);
  if (@nargv != 0) {
    die "usage: disconnect\n";
  }
  if (!$cyrref || !$$cyrref) {
    die "disconnect: no connection to server\n";
  }
  $$cyrref = undef;
  0;
}

sub _sc_chdir {
  my ($cyrref, $name, $fh, $lfh, @argv) = @_;
  my (@nargv, $opt);
  shift(@argv);
  while (defined ($opt = shift(@argv))) {
    # gack.  bloody tcl.
    last if $opt eq '--';
    if ($opt =~ /^-/) {
      die "usage: chdir directory\n";
    }
    else {
      push(@nargv, $opt);
      last;
    }
  }
  push(@nargv, @argv);
  if (@nargv != 1) {
    die "usage: chdir directory\n";
  }
  chdir($nargv[0]) or die "chdir: $nargv[0]: $!\n";
  0;
}

sub _sc_create {
  my ($cyrref, $name, $fh, $lfh, @argv) = @_;
  my (@nargv, $opt, $part, $want, %opts);
  shift(@argv);
  while (defined ($opt = shift(@argv))) {
    if ($want) {
      if ($want eq '-partition') {
        $part = $opt;
      } else {
        $opts{$want} = $opt;
      }
      $want = undef;
      next;
    }
    if ($opt ne '' && '-partition' =~ /^\Q$opt/ || $opt eq '--partition') {
      $want = '-partition';
      next;
    }
    if ($opt ne '' && '-specialuse' =~ /^\Q$opt/ || $opt eq '--specialuse') {
      $want = '-specialuse';
      next;
    }
    last if $opt eq '--';
    if ($opt =~ /^-/) {
      die "usage: createmailbox [--partition partition] [--specialuse specialuse] mailbox [partition]\n";
    }
    else {
      push(@nargv, $opt);
      last;
    }
  }
  push(@nargv, @argv);
  if (!@nargv || @nargv > 2) {
    die "usage: createmailbox [--partition partition] mailbox [partition]\n";
  }
  push(@nargv, $part) if (defined ($part));
  push(@nargv, undef) if (@nargv < 2);
  push(@nargv, \%opts);
  if (!$cyrref || !$$cyrref) {
    die "createmailbox: no connection to server\n";
  }
  $$cyrref->create(@nargv) || die "createmailbox: " . $$cyrref->error . "\n";
  0;
}

sub _sc_delete {
  my ($cyrref, $name, $fh, $lfh, @argv) = @_;
  my (@nargv, $opt);
  shift(@argv);
  while (defined ($opt = shift(@argv))) {
    last if $opt eq '--';
    if ($opt =~ /^-/) {
      die "usage: deletemailbox mailbox [host]\n";
    }
    else {
      push(@nargv, $opt);
      last;
    }
  }
  push(@nargv, @argv);
  if (!@nargv || @nargv > 1) {
    die "usage: deletemailbox mailbox\n";
  }
  if (!$cyrref || !$$cyrref) {
    die "deletemailbox: no connection to server\n";
  }

  if($nargv[0] =~ /(\*|%)/) {
    # list operation
    my @res = $$cyrref->listmailbox(($nargv[0]));
    foreach my $mbx (@res) {
      my $name = $mbx->[0];
      my $flags = $mbx->[1];
      next if($flags =~ /(\\noselect|\\nonexistent|\\placeholder)/i);
      print "Deleting mailbox $name...";
      $nargv[0] = $name;
      my $rc = $$cyrref->delete(@nargv);
      if(!defined($rc)) {
        print $$cyrref->error . "\n";
        last;
      } else {
        print "OK.\n";
      }
    }
  } else {
    $$cyrref->delete(@nargv) || die "deletemailbox: " . $$cyrref->error . "\n";
  }
  0;
}

sub _sc_reconstruct {
  my ($cyrref, $name, $fh, $lfh, @argv) = @_;
  my (@nargv, $opt);
  my $recurse = 0;
  shift(@argv);
  while (defined ($opt = shift(@argv))) {
    last if $opt eq '--';
    if ($opt =~ /^-/) {
      if($opt eq "-r") {
        $recurse = 1;
      } else {
        die "usage: reconstruct [-r] mailbox\n";
      }
    }
    else {
      push(@nargv, $opt);
      last;
    }
  }
  push(@nargv, @argv);
  if (!@nargv || @nargv > 1) {
    die "usage: reconstruct [-r] mailbox\n";
  }
  if (!$cyrref || !$$cyrref) {
    die "reconstruct: no connection to server\n";
  }
  $$cyrref->reconstruct(@nargv) || die "reconstruct: " .$$cyrref->error. "\n";
  0;
}

sub _sc_rename {
  my ($cyrref, $name, $fh, $lfh, @argv) = @_;
  my (@nargv, $opt, $want, $part);
  shift(@argv);
  while (defined ($opt = shift(@argv))) {
    if ($want) {
      $part = $opt;
      $want = undef;
      next;
    }
    if ($opt ne '' && '-partition' =~ /^\Q$opt/ || $opt eq '--partition') {
      $want = 1;
      next;
    }
    last if $opt eq '--';
    if ($opt =~ /^-/) {
      die "usage: renamemailbox [--partition name] oldname " .
          "newname [partition]\n";
    }
    else {
      push(@nargv, $opt);
      last;
    }
  }
  push(@nargv, @argv);
  $part = pop(@nargv) if @nargv > 2 && !defined($part);
  if (@nargv != 2) {
    die "usage: renamemailbox [--partition name] oldname " .
        "newname [partition]\n";
  }
  if (!$cyrref || !$$cyrref) {
    die "renamemailbox: no connection to server\n";
  }
  $$cyrref->rename($nargv[0], $nargv[1], $part) ||
    die "renamemailbox: " . $$cyrref->error . "\n";
  0;
}

sub _sc_xfer {
  my ($cyrref, $name, $fh, $lfh, @argv) = @_;
  my (@nargv, $opt, $want, $part);
  shift(@argv);
  while (defined ($opt = shift(@argv))) {
    if ($want) {
      $part = $opt;
      $want = undef;
      next;
    }
    if ($opt ne '' && '-partition' =~ /^\Q$opt/ || $opt eq '--partition') {
      $want = 1;
      next;
    }
    last if $opt eq '--';
    if ($opt =~ /^-/) {
      die "usage: xfermailbox [--partition name] mailbox " .
          "server [partition]\n";
    }
    else {
      push(@nargv, $opt);
      last;
    }
  }
  push(@nargv, @argv);
  $part = pop(@nargv) if @nargv > 2 && !defined($part);
  if (@nargv != 2) {
    die "usage: xfermailbox [--partition name] mailbox " .
        "server [partition]\n";
  }
  if (!$cyrref || !$$cyrref) {
    die "xfermailbox: no connection to server\n";
  }
  $$cyrref->xfer($nargv[0], $nargv[1], $part) ||
    die "xfermailbox: " . $$cyrref->error . "\n";
  0;
}

sub _sc_deleteacl {
  my ($cyrref, $name, $fh, $lfh, @argv) = @_;
  my (@nargv, $opt);
  shift(@argv);
  while (defined ($opt = shift(@argv))) {
    last if $opt eq '--';
    if ($opt =~ /^-/) {
      die "usage: deleteaclmailbox mailbox id [id ...]\n";
    }
    else {
      push(@nargv, $opt);
      last;
    }
  }
  push(@nargv, @argv);
  if (@nargv < 2) {
    die "usage: deleteaclmailbox mailbox id [id ...]\n";
  }
  if (!$cyrref || !$$cyrref) {
    die "deleteaclmailbox: no connection to server\n";
  }

  if($nargv[0] =~ /(\*|%)/) {
    # list operation
    my @res = $$cyrref->listmailbox(($nargv[0]));
    foreach my $mbx (@res) {
      my $name = $mbx->[0];
      my $flags = $mbx->[1];
      next if($flags =~ /(\\noselect|\\nonexistent|\\placeholder)/i);
      # If id of '*' is passed then delete all existing acls
      if ($nargv[1] eq '*') {
        my %acl = $$cyrref->listaclmailbox($name);
        if (defined $$cyrref->error) {
          print($$cyrref->error, "\n");
          next;
        }
        pop(@nargv);
        foreach my $acl (keys %acl) {
          push(@nargv, $acl, $acl{$acl});
        }
      }
      print "Deleting acl on $name...";
      $nargv[0] = $name;
      my $rc = $$cyrref->deleteacl(@nargv);
      if(!defined($rc)) {
        print $$cyrref->error . "\n";
        last;
      } else {
        print "OK.\n";
      }
    }
  } else {
    # If id of '*' is passed then delete all existing acls
    if ($nargv[1] eq '*') {
      my %acl = $$cyrref->listaclmailbox($nargv[0]);
      if (defined $$cyrref->error) {
        print($$cyrref->error, "\n");
        next;
      }
      pop(@nargv);
      foreach my $acl (keys %acl) {
        push(@nargv, $acl, $acl{$acl});
      }
    }
    $$cyrref->deleteacl(@nargv) ||
      die "deleteaclmailbox: " . $$cyrref->error . "\n";
  }

  0;
}

sub _sc_setacl {
  my ($cyrref, $name, $fh, $lfh, @argv) = @_;
  my (@nargv, $opt);
  shift(@argv);
  while (defined ($opt = shift(@argv))) {
    last if $opt eq '--';
    if ($opt =~ /^-/) {
      die "usage: setaclmailbox mailbox id rights [id rights ...]\n";
    }
    else {
      push(@nargv, $opt);
      last;
    }
  }
  push(@nargv, @argv);
  if (@nargv < 3 || (@nargv - 1) % 2) {
    die "usage: setaclmailbox mailbox id rights [id rights ...]\n";
  }
  if (!$cyrref || !$$cyrref) {
    die "setaclmailbox: no connection to server\n";
  }

  if($nargv[0] =~ /(\*|%)/) {
    # list operation
    my @res = $$cyrref->listmailbox(($nargv[0]));
    foreach my $mbx (@res) {
      my $name = $mbx->[0];
      my $flags = $mbx->[1];
      next if($flags =~ /(\\noselect|\\nonexistent|\\placeholder)/i);
      print "Setting ACL on $name...";
      $nargv[0] = $name;
      my $rc = $$cyrref->setacl(@nargv);
      if(!defined($rc)) {
        print $$cyrref->error . "\n";
        last;
      } else {
        print "OK.\n";
      }
    }
  } else {
    $$cyrref->setacl(@nargv) || die "setaclmailbox: " . $$cyrref->error . "\n";
  }
  0;
}

sub _sc_setquota {
  my ($cyrref, $name, $fh, $lfh, @argv) = @_;
  my (@nargv, $opt);
  shift(@argv);
  while (defined ($opt = shift(@argv))) {
    last if $opt eq '--';
    if ($opt =~ /^-/) {
      die ("usage: setquota mailbox limit num [limit num ...]\n" .
           "       setquota mailbox num\n");
    }
    else {
      push(@nargv, $opt);
      last;
    }
  }
  push(@nargv, @argv);
  if (@nargv == 2) {
      my ($mbox, $limit) = @nargv;
      if ($limit eq 'none') {
          @nargv = ($mbox);
          print "remove quota\n";
      } else {
          @nargv = ($mbox, "STORAGE", $limit);
          print "quota:", $limit, "\n";
      }
  }
  if ((@nargv - 1) % 2) {
    die ("usage: setquota mailbox limit num [limit num ...]\n" .
         "       setquota mailbox num\n");
  }
  if (!$cyrref || !$$cyrref) {
    die "setquota: no connection to server\n";
  }
  $$cyrref->setquota(@nargv) || die "setquota: " . $$cyrref->error . "\n";
  0;
}

sub _sc_version {
  my ($cyrref, $name, $fh, $lfh, @argv) = @_;
  my (@nargv, $opt);
  shift(@argv);
  while (defined ($opt = shift(@argv))) {
    # gack.  bloody tcl.
    last if $opt eq '--';
    if ($opt =~ /^-/) {
      die "usage: version\n";
    }
    else {
      push(@nargv, $opt);
      last;
    }
  }
  push(@nargv, @argv);
  if (@nargv != 0) {
    die "usage: version\n";
  }
  if (!$cyrref || !$$cyrref) {
    die "version: no connection to server\n";
  }

  my $info;
  $$cyrref->addcallback({-trigger => 'ID',
                      -callback => sub {
                        my %d = @_;
                        $info = $d{-text};
                      }});
  my ($rc, $msg) = $$cyrref->send('', '', 'ID NIL');
  $$cyrref->addcallback({-trigger => 'ID'});
  if ($rc ne 'OK') {
    $lfh->[2]->print($msg, "\n");
    return 1;
  }

  if ($info eq 'NIL') {
    $lfh->[1]->print("no version info returned by server\n");
    return 0;
  }
  while ($info =~ s/\"([^\"]+)\"\s+(\"[^\"]+\"|NIL)\s*//) {
    my $field = $1;
    my $value = $2;
    $value =~ s/\"//g;                  # strip quotes
    # split environment into multiple lines
    $value =~ s/;/\n            /g if $field eq 'environment';
    $value = '' if $value eq 'NIL';     # convert NIL to empty string
    $lfh->[1]->printf("%-11s: %s\n", $field, $value);
  }
  0;
}

sub _sc_info {
  my ($cyrref, $name, $fh, $lfh, @argv) = @_;
  my (@nargv, $opt);
  shift(@argv);
  while (defined ($opt = shift(@argv))) {
    # gack.  bloody tcl.
    last if $opt eq '--';
    if ($opt =~ /^-/) {
      die "usage: info [mailbox]\n";
    }
    else {
      push(@nargv, $opt);
      last;
    }
  }
  push(@nargv, @argv);
  if (!$cyrref || !$$cyrref) {
    die "info: no connection to server\n";
  }
  my %info = $$cyrref->getinfo(@nargv);
  if (defined $$cyrref->error) {
    $lfh->[2]->print($$cyrref->error, "\n");
    return 1;
  }

  foreach my $mailbox (sort keys %info) {
      if($mailbox eq "") {
        print "{Server Wide}\n";
      } else {
        print "{$mailbox}:\n";
      }

    my %attribname = ();
    foreach my $attribname (sort keys %{$info{$mailbox}}) {
      foreach my $attrib (sort keys %{$info{$mailbox}->{$attribname}}) {
        if(!exists $attribname{$attribname}) {
          $attribname{$attribname} = 'x';
          print "  $attribname:\n";
        }
        $attrib =~ /([^\/]*)$/;
        my $attrname = $1;

        $lfh->[1]->print("    ", $attrname, ": ", $info{$mailbox}->{$attribname}->{$attrib}, "\n");
      }
    }
  }
  0;
}

sub _sc_getmetadata {
  my ($cyrref, $name, $fh, $lfh, @argv) = @_;
  my (@nargv, $opt);
  shift(@argv);
  while (defined ($opt = shift(@argv))) {
    # gack.  bloody tcl.
    last if $opt eq '--';
    if ($opt =~ /^-/) {
      die "usage: getmetadata [mailbox]\n";
    }
    else {
      push(@nargv, $opt);
      last;
    }
  }
  while (defined ($opt = shift(@argv))) {
    if ($opt eq 'comment') {
       push(@nargv, '/private/comment');
    } elsif ($opt eq 'expire') {
       push(@nargv, '/shared/vendor/cmu/cyrus-imapd/expire');
    } elsif ($opt eq 'news2mail') {
       push(@nargv, '/shared/vendor/cmu/cyrus-imapd/news2mail');
    } elsif ($opt eq 'pop3showafter') {
       push(@nargv, '/shared/vendor/cmu/cyrus-imapd/pop3showafter');
    } elsif ($opt eq 'sharedseen') {
       push(@nargv, '/shared/vendor/cmu/cyrus-imapd/sharedseen');
    } elsif ($opt eq 'sieve') {
       push(@nargv, '/shared/vendor/cmu/cyrus-imapd/sieve');
    } elsif ($opt eq 'specialuse') {
       push(@nargv, '/private/specialuse');
    } elsif ($opt eq 'squat') {
       push(@nargv, '/shared/vendor/cmu/cyrus-imapd/squat');
    } else {
      push(@nargv, $opt);
    }
  }
  if (!$cyrref || !$$cyrref) {
    die "info: no connection to server\n";
  }
  my %info = $$cyrref->getmetadata(@nargv);
  if (defined $$cyrref->error) {
    $lfh->[2]->print($$cyrref->error, "\n");
    return 1;
  }

  foreach my $mailbox (sort keys %info) {
      if($mailbox eq "") {
        print "{Server Wide}\n";
      } else {
        print "{$mailbox}:\n";
      }

    my %attribname = ();
    foreach my $attribname (sort keys %{$info{$mailbox}}) {
      foreach my $attrib (sort keys %{$info{$mailbox}->{$attribname}}) {
        if(!exists $attribname{$attribname}) {
          $attribname{$attribname} = 'x';
          print "  $attribname:\n";
        }
        $attrib =~ /([^\/]*)$/;
        my $attrname = $1;

        $lfh->[1]->print("    ", $attrname, ": ", $info{$mailbox}->{$attribname}->{$attrib}, "\n");
      }
    }
  }
  0;
}

sub _sc_setmetadata {
  my ($cyrref, $name, $fh, $lfh, @argv) = @_;
  my (@nargv, $opt, $private);
  shift(@argv);
  while (defined ($opt = shift(@argv))) {
    last if $opt eq '--';
    if ($opt ne '' && '-private' =~ /^\Q$opt/ || $opt eq '--private') {
      $private = 1;
    } elsif ($opt =~ /^-/) {
      die "usage: setmetadata [--private] mailbox [comment|expire|news2mail|pop3showafter|sharedseen|sieve|specialuse|squat|/<explicit metadata>] value\n";
    }
    else {
      push(@nargv, $opt);
      last;
    }
  }
  push(@nargv, @argv);
  if (@nargv < 2) {
    die "usage: setmetadata [--private] mailbox [comment|expire|news2mail|pop3showafter|sharedseen|sieve|specialuse|squat|/<explicit metadata>] value\n";
  }
  if (defined ($private)) {
    push(@nargv, $private);
  }
  if (!$cyrref || !$$cyrref) {
    die "setmetadata: no connection to server\n";
  }
  $$cyrref->setmetadata(@nargv) || die "setmetadata: " . $$cyrref->error . "\n";
  0;
}

sub _sc_subscribe {
  my ($cyrref, $name, $fh, $lfh, @argv) = @_;
  my (@nargv, $opt);
  shift(@argv);
  while (defined ($opt = shift(@argv))) {
    # gack.  bloody tcl.
    last if $opt eq '--';
    if ($opt =~ /^-/) {
      die "usage: subscribe [mailbox]\n";
    }
    else {
      push(@nargv, $opt);
      last;
    }
  }
  push(@nargv, @argv);
  if (!$cyrref || !$$cyrref) {
    die "subscribe: no connection to server\n";
  }
  $$cyrref->subscribe(@nargv);
  if (defined $$cyrref->error) {
    $lfh->[2]->print($$cyrref->error, "\n");
    return 1;
  }
  0;
}

sub _sc_unsubscribe {
  my ($cyrref, $name, $fh, $lfh, @argv) = @_;
  my (@nargv, $opt);
  shift(@argv);
  while (defined ($opt = shift(@argv))) {
    # gack.  bloody tcl.
    last if $opt eq '--';
    if ($opt =~ /^-/) {
      die "usage: unsubscribe [mailbox]\n";
    }
    else {
      push(@nargv, $opt);
      last;
    }
  }
  push(@nargv, @argv);
  if (!$cyrref || !$$cyrref) {
    die "unsubscribe: no connection to server\n";
  }
  $$cyrref->unsubscribe(@nargv);
  if (defined $$cyrref->error) {
    $lfh->[2]->print($$cyrref->error, "\n");
    return 1;
  }
  0;
}

sub _sc_mboxcfg {
  my ($cyrref, $name, $fh, $lfh, @argv) = @_;
  my (@nargv, $opt, $private);
  shift(@argv);
  while (defined ($opt = shift(@argv))) {
    last if $opt eq '--';
    if ($opt ne '' && '-private' =~ /^\Q$opt/ || $opt eq '--private') {
      $private = 1;
    } elsif ($opt =~ /^-/) {
      die "usage: mboxconfig [--private] mailbox [comment|expire|news2mail|pop3showafter|sharedseen|sieve|squat|/<explicit annotation>] value\n";
    }
    else {
      push(@nargv, $opt);
      last;
    }
  }
  push(@nargv, @argv);
  if (@nargv < 2) {
    die "usage: mboxconfig [--private] mailbox [comment|expire|news2mail|pop3showafter|sharedseen|sieve|squat|/<explicit annotation>] value\n";
  }
  if (defined ($private)) {
    push(@nargv, $private);
  }
  if (!$cyrref || !$$cyrref) {
    die "mboxconfig: no connection to server\n";
  }
  $$cyrref->mboxconfig(@nargv) || die "mboxconfig: " . $$cyrref->error . "\n";
  0;
}

sub _sc_setinfo {
  my ($cyrref, $name, $fh, $lfh, @argv) = @_;
  my (@nargv, $opt);
  shift(@argv);
  while (defined ($opt = shift(@argv))) {
    last if $opt eq '--';
    if ($opt =~ /^-/) {
      die "usage: setinfo [motd|comment|admin|shutdown|expire|squat] text\n";
    }
    else {
      push(@nargv, $opt);
      last;
    }
  }
  push(@nargv, @argv);
  if (@nargv < 2) {
    die "usage: setinfo [motd|comment|admin|shutdown|expire|squat] text\n";
  }
  if (!$cyrref || !$$cyrref) {
    die "setinfo: no connection to server\n";
  }
  $$cyrref->setinfoserver(@nargv) || die "setinfo: " . $$cyrref->error . "\n";
  0;
}

###############################################################################

#
# This exists so I don't have to use a separate interface to read from a file.
#

package Cyrus::IMAP::DummyReadline;
use IO::File;

sub new {
  my ($class, $dummy, $in, $out) = @_;
  autoflush $out 1;
  bless {in => $in, out => $out}, $class;
}

sub ornaments {
  return;
}

sub readline {
  my ($self, $prompt) = @_;
  my $l;
  my $fh = $self->{in};
  my $ofh = $self->{out};
  print $ofh $prompt;
  return undef unless defined($l = <$fh>);
  chomp($l);
  $l;
}

1;

=for pod2rst .. DO NOT EDIT cyradm.rst: Autogenerated by tools/perl2rst from cyrus-imapd\perl\imap\IMAP\Shell.pm

=for pod2rst .. cyrusman:: cyradm(8)

=for pod2rst .. _imap-reference-manpages-systemcommands-cyradm:

=head1 NAME

Cyrus::IMAP::Shell - Perl version of cyradm

=head1 SYNOPSIS

  $ cyradm [--user authid] [--authz authzid] [--[no]rc] [--systemrc file] [--userrc file] \
  > [--port n] [--auth mechanism] [--server] server

but possibly

  $ perl -MCyrus::IMAP::Shell -e 'run("myscript")'

or even (not recommended)

  use Cyrus::IMAP::Admin::Shell;

  run('myscriptname');

=head1 DESCRIPTION

This module implements B<cyradm> in Perl.  It is a shell around
L<Cyrus::IMAP::Admin>.  Commands are provided in both Tcl-compatible
forms and GNU-style long option forms.

The ``cyradm`` utility is a simple command line for performing common
administrative tasks on a Cyrus IMAP server, written in Perl.

The cyradm utility can either be executed from a client where it has been
installed and connect to the server via IMAP or it can be executed
locally via a shell on the server.

cyradm understands /bin/sh-style redirection: any command can have its 
standard or error output redirected, with all sh-style redirections 
(except \<\>) supported. It does not currently understand pipes or 
backgrounding.

If the L<Term::Readline::Perl> or L<Term::Readline::GNU> modules are 
available, cyradm will use it.

=head1 COMMAND-LINE ARGUMENTS

=over 4

=item C<--u>, C<--user> I<user>

Authenticate with the specified username.

=item C<--authz> I<user>

Authorize the connection as being the specified username.

=item C<--norc>, C<--rc>

(Do not) load the configuration files.

=item C<--systemrc> I<file>

Use the system configuration file specified.

=item C<--userrc> I<file>

Use the user configuration file specified.

=item C<--port> I<port>

Connect to the *server* specified on the port specified.

=item C<--auth> I<mechanism>

Use the mechanism specified to authenticate. One of PLAIN, LOGIN, DIGEST-MD5, etc.

=item C<--help>

Show a help message about these command-line options.

=item C<--version>

Display the version of Cyrus IMAP the current ``cyradm`` command is a part of.

=item C<--server> I<server>

The server address to connect to.

=back
    
=head1 COMMANDS

=for pod2rst .. _imap-reference-manpages-systemcommands-cyradm-authenticate:

=head2 authenticate 

B<authenticate> [C<--minssf> I<N>] [C<--maxssf> I<N>] [C<--mechanisms> I<list>] [C<--service> I<name>] [C<--tlskey> I<keyfile>] [C<--notls>] [C<--cafile> I<cacertfile>] [C<--capath> I<cacertdir>] I<user>

Authenticate to server.  You must already be connected to a server and
Cyrus imapd will refuse to allow you to re-authenticate once you have
authenticated once.

aliases: C<auth>, C<login>

=for pod2rst .. _imap-reference-manpages-systemcommands-cyradm-chdir:

=head2 chdir

B<chdir> I<directory>

Change directory.  A C<pwd> builtin is not provided, but the default command
action will run C<pwd> from a shell if invoked.

aliases: C<cd>

=for pod2rst .. _imap-reference-manpages-systemcommands-cyradm-createmailbox:

=head2 createmailbox

B<createmailbox> [C<--partition> I<partition>] [C<--specialuse> I<specialuse>] I<mailbox>

B<createmailbox> [C<--specialuse> I<specialuse>] I<mailbox> I<partition>

Create a mailbox on the default or a specified partition.  Both old-style
and getopt-style usages are accepted (combining them will produce an error).
Optionally assign a special use to the mailbox.

New mailboxes inherit the ACL permissions of
their parent mailbox, except for top-level mailboxes such as the user's
INBOX. Mailboxes that are the user's INBOX are assigned all to the
corresponding user.

=over 4

=item Example Usage

    localhost> :command:`cm user.john`
    localhost> :command:`lm`
    user.john (\HasNoChildren)
    localhost> :command:`lam user.john`
    john lrswipkxtecda


Note that in the above example, the C<unixhierarchysep> setting in
imapd.conf is set to C<0>. When using the UNIX
hierarchy separator, the C</> (forward slash) character would be
used as the hierarchy separator, and the example would look as
follows:

=item Example Usage with C<unixhierarchysep: 1>

    localhost> :command:`cm user/john`
    localhost> :command:`lm`
    user/john (\HasNoChildren)
    localhost> :command:`lam user/john`
    john lrswipkxtecda
  
=item Note

The above examples use the unqualified, shorthand user
identifier john as the mailbox name.

With the use of virtual domains, controlled through the
C<virtdomains> setting in imapd.conf(5).

=back
    
aliases: C<cm>, C<create>

=for pod2rst .. _imap-reference-manpages-systemcommands-cyradm-deleteaclmailbox:

=head2 deleteaclmailbox

B<deleteaclmailbox> I<mailbox> I<id> [...]

Remove ACLs from the specified mailbox.

aliases: C<delteacl>, C<dam>

=for pod2rst .. _imap-reference-manpages-systemcommands-cyradm-deletemailbox:

=head2 deletemailbox

B<deletemailbox> I<mailbox>

Delete the specified mailbox.

Administrators do not have implicit delete rights on mailboxes.  Use the
L</setaclmailbox> command to grant the C<x> permission to your
principal if you need to delete a mailbox you do not own.

aliases: C<delete>, C<dm>

=for pod2rst .. _imap-reference-manpages-systemcommands-cyradm-disconnect:

=head2 disconnect

B<disconnect>

Disconnect from the current server.  The prompt will revert to C<cyradmE<gt>>. 
This does not quit cyradm.

aliases: C<disc>

=for pod2rst .. _imap-reference-manpages-systemcommands-cyradm-exit:

=head2 exit

B<exit> [I<number>]

Exit C<cyradm>, optionally with a specific exit status; the exit status of the
last command will be used if one is not specified.

aliases: C<quit>

=for pod2rst .. _imap-reference-manpages-systemcommands-cyradm-help:

=head2 help

B<help> [command]

Show help for C<command> or all commands.

aliases: C<?>

=for pod2rst .. _imap-reference-manpages-systemcommands-cyradm-getmetadata:

=head2 getmetadata

B<getmetadata> [I<mailbox>]

Display mailbox/server metadata

aliases: C<getmd>

=for pod2rst .. _imap-reference-manpages-systemcommands-cyradm-info:

=head2 info

B<info> [I<mailbox>]

Display the mailbox/server annotations.

=for pod2rst .. _imap-reference-manpages-systemcommands-cyradm-listaclmailbox:

=head2 listaclmailbox

B<listaclmailbox> I<mailbox>

List ACLs on the specified mailbox.

aliases: C<lam>, C<listacl>

=for pod2rst .. _imap-reference-manpages-systemcommands-cyradm-listmailbox:

=head2 listmailbox

B<listmailbox> [C<--subscribed>] [C<--specialuse>] [I<pattern> [I<reference>]]

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

aliases: C<list>, C<lm>

=for pod2rst .. _imap-reference-manpages-systemcommands-cyradm-listquota:

=head2 listquota

B<listquota> I<root>

List quotas on specified root.  If the specified mailbox path does not have
a quota assigned, an error will be raised; see L</listquotaroot> for a way to
find the quota root for a mailbox.

aliases: C<lq>

=for pod2rst .. _imap-reference-manpages-systemcommands-cyradm-listquotaroot:

=head2 listquotaroot

B<listquotaroot> I<mailbox>

Show quota roots and quotas for mailbox

aliases: C<lqm>, C<lqr>

=for pod2rst .. _imap-reference-manpages-systemcommands-cyradm-mboxconfig:

=head2 mboxconfig

B<mboxconfig> [C<--private>] I<mailbox> I<attribute> I<value>

Set mailbox metadata, optionally set the private instead of the shared
version of the metadata. A value of "none" will remove the attribute.

The currently supported attributes are:

=over 4

=item C<comment> I<description>

Sets a comment or description associated with the mailbox.

=item C<expire> I<days>

Sets the number of days after which messages will be expired from the mailbox.

=item C<news2mail> I<address>

Sets an email address to which messages injected into the server via NNTP
will be sent.

=item C<pop3showafter> I<time>

Sets a time (in RFC3501 format, for example "6-Jan-2011 11:45:32 +1100")
which specifies a cutoff date such that POP3 fetching of the folder does
not see messages whose internaldate is before or equal to the date.

=item C<sharedseen> I<true|false>

Enables the use of a shared \Seen flag on messages rather than a
per-user \Seen flag.  The 's' right in the mailbox ACL still controls
whether a user can set the shared \Seen flag.

=item C<sieve> I<scriptname>

Indicates the name of the global sieve script that should be run when
a message is delivered to the shared mailbox (not used for personal
mailboxes).

=item C<squat> I<true|false>

Indicates that the mailbox should have a squat index created for it.

=back

aliases: C<mboxcfg>

=for pod2rst .. _imap-reference-manpages-systemcommands-cyradm-reconstruct:

=head2 reconstruct

B<reconstruct> [C<-r>] I<mailbox>

Reconstruct the specified mailbox, optionally recursing and reconstructing child mailboxes if the C<-r> flag is given.

For more information see reconstruct(8).

=for pod2rst .. _imap-reference-manpages-systemcommands-cyradm-renamemailbox:

=head2 renamemailbox

B<renamemailbox> [C<--partition> I<partition>] I<oldname> I<newname>

B<renamemailbox> I<oldname> I<newname> [I<partition>]

Rename the specified mailbox, optionally moving it to a different partition.
Both old-style and getopt-style usages are accepted; combining them will
produce an error.

aliases: C<rename>, C<renm>

=for pod2rst .. _imap-reference-manpages-systemcommands-cyradm-server:

=head2 server

B<server>

B<server> I<[--noauthenticate]> I<[server]>

With no arguments, show the current server.  With an argument, connect to that
server.  It will prompt for automatic login unless the C<--noauthenticate>
option is specified.  (This may change; in particular, either automatic
authentication will be removed or all L</authenticate> options will be added.)

When connected to a server, B<cyradm>'s prompt changes from C<cyradmE<gt>> to
C<servernameE<gt>>, where I<servername> is the fully qualified domain name
of the connected server.

aliases: C<connect>, C<servername>

=for pod2rst .. _imap-reference-manpages-systemcommands-cyradm-setaclmailbox:

=head2 setaclmailbox

B<setaclmailbox> I<mailbox> I<id> I<rights> [I<id> I<rights> ...]

Set ACLs on a mailbox.  The ACL may be one of the special strings C<none>,
C<read> (C<lrs>), C<post> (C<lrsp>), C<append> (C<lrsip>), C<write>
(C<lrswipkxte>), C<delete> (C<lrxte>), or C<all> (C<lrswipkxte>), or
any combinations of the ACL codes:

=over 4

=item B<l>

Lookup (mailbox is visible to LIST/LSUB, SUBSCRIBE mailbox)

=item B<r>

Read (SELECT/EXAMINE the mailbox, perform STATUS)

=item B<s>

Seen (set/clear \SEEN flag via STORE, also set \SEEN flag during APPEND/COPY/FETCH BODY[...])

=item B<w>

Write flags other than \SEEN and \DELETED

=item B<i>

Insert (APPEND, COPY destination)

=item B<p>

Post (send mail to mailbox)

=item B<k>

Create mailbox (CREATE new sub-mailboxes, parent for new mailbox in RENAME)

=item B<x>

Delete mailbox (DELETE mailbox, old mailbox name in RENAME)

=item B<t>

Delete messages (set/clear \DELETED flag via STORE, also set \DELETED flag during APPEND/COPY)

=item B<e>

Perform EXPUNGE and expunge as part of CLOSE

=item B<a>

Administer (SETACL/DELETEACL/GETACL/LISTRIGHTS)

=back

aliases: C<setacl>, C<sam>

=for pod2rst .. _imap-reference-manpages-systemcommands-cyradm-setinfo:

=head2 setinfo

B<setinfo> I<attribute> I<value>

Set server metadata.  A value of "none" will remove the attribute.
The currently supported attributes are:

=over 4

=item C<motd> I<message>

Sets a "message of the day".  The message gets displayed as an ALERT upon
connection.

=item C<comment> I<note>

Sets a comment or description associated with the server.

=item C<admin> I<address>

Sets the administrator email address for the server.

=item C<shutdown> I<message>

Sets a shutdown message.  The message gets displayed as an ALERT and
all users are disconnected from the server (subsequent logins are disallowed).

=item C<expire> I<days>

Sets the number of days after which messages will be expired from the
server (unless overridden by a mailbox annotation).

=item C<squat> I<true|false>

Indicates that all mailboxes should have a squat indexes created for
them (unless overridden by a mailbox annotation).

=back

=for pod2rst .. _imap-reference-manpages-systemcommands-cyradm-setmetadata:

=head2 setmetadata

B<setmetadata> [--private] mailbox [I<annotation>] I<value>

Set metadata on mailbox, where I<annotation> is one of
[comment|expire|news2mail|pop3showafter|sharedseen|sieve|specialuse|
squat|/<explicit annotation>].

Note that I<value> with a leading backslash must be escaped with an
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

aliases: C<setmd>

=for pod2rst .. _imap-reference-manpages-systemcommands-cyradm-setquota:

=head2 setquota

B<setquota> I<root> I<resource> I<value> [I<resource> I<value> ...]

Set a quota on the specified root, which may or may not be an actual
mailbox. The I<resources> understood by B<Cyrus> are C<STORAGE>,
C<MESSAGE>, C<X-NUM-FOLDERS> and C<X-ANNOTATION-STORAGE>.  The storage
units are, as defined in RFC 2087, groups of 1024 octets (i.e.
Kilobytes). The I<value> may be the special string C<none> which will
remove the quota.

aliases: C<sq>

=for pod2rst .. _imap-reference-manpages-systemcommands-cyradm-subscribe:

=head2 subscribe

B<subscribe> I<mailbox>

Subscribe to the given mailbox.

=for pod2rst .. _imap-reference-manpages-systemcommands-cyradm-unsubscribe:

=head2 unsubscribe

B<unsubscribe> I<mailbox>

Unsubscribe to the given mailbox.

=for pod2rst .. _imap-reference-manpages-systemcommands-cyradm-version:

=head2 version

B<version>

Display the version info of the current server.

aliases: C<ver>

=for pod2rst .. _imap-reference-manpages-systemcommands-cyradm-xfermailbox:

=head2 xfermailbox

B<xfermailbox> [C<--partition> I<partition>] I<mailbox> I<server>

B<xfermailbox> I<mailbox> I<server> [I<partition>]

Transfer (relocate) the specified mailbox to a different server.
Both old-style and getopt-style usages are accepted; combining them will
produce an error.

aliases: C<xfer>

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

Cyrus::IMAP::Admin,
Term::ReadLine,
sh(1), perl(1), imapd(8), imapd.conf(5), reconstruct(8)

=for pod2rst :cyrusman:`imapd(8)`, :cyrusman:`imapd.conf(5)`, :cyrusman:`reconstruct(8)`.

=cut
