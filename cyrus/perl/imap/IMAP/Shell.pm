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
# A shell framework for IMAP::Cyrus::Admin
#
# run(*FH|'FH')
#	read commands from the filehandle and pass to exec(); defaults to
#	__DATA__
# shell
#	= run(*STDIN)
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
use Getopt::Long;
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
		  [\&_sc_list, '[-subscribed] [pattern [base]]',
		   'list mailboxes'],
		server =>
		  [\&_sc_server, '[-noauthenticate] [server]',
		   'show current server or connect to server'],
		servername => 'server',
		connect => 'server',
		authenticate =>
		  [\&_sc_auth,
		   '[-minssf N] [-maxssf N] [-mechanisms list] [user]',
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
		  [\&_sc_create, '[--partition partition] mailbox [partition]',
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
		setquota =>
		  [\&_sc_setquota,
		   'mailbox resource value [resource value ...]',
		   'set quota on mailbox or resource'],
		sq => 'setquota',
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

  my $q = '';
  my @tok = ('', undef);
  # this is cute.  (shells are funny that way)
  # we parse "words" which are delimited by whitespace.  except that if a
  # quote appears, we have to gobble to the closing quote and then continue
  # with what we were doing.  and outside quotes, we need to look for special
  # characters (in this case, /&<>;/) and break "words" there.
  while ($$lr ne '' && $$lr !~ /^\s/) {
    $tok[1] ||= 0;
    if ($$lr =~ /^([&<>;])/) {
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
    if ($$lr =~ /^([\'\"])/ && $q eq $1) {
      $q = '';
      $coll_command .= $1;
      $$lr =~ s///;
      next;
    }
    if ($$lr =~ /^([\'\"])/ && $q eq '') {
      $q = $1;
      $coll_command .= $1;
      $$lr =~ s///;
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
  my ($server, $port, $user, $systemrc, $userrc, $dorc, $mech) =
    ('', 143, $ENV{USER} || $ENV{LOGNAME}, '/usr/local/etc/cyradmrc.pl',
     "$ENV{HOME}/.cyradmrc.pl", 1, undef);
  GetOptions('user|u=s' => \$user,
	     'rc|r!' => \$dorc,
	     'systemrc|S=s' => \$systemrc,
	     'userrc=s' => \$userrc,
	     'server|s=s' => \$server,
	     'port|p=i' => \$port,
	     'auth|a=s' => \$mech,
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
#    print "trying to auth as [$user].\n";
    $cyradm->authenticate(-user => $user, -mechanism => $mech)
      or die "cyradm: cannot authenticate to server with $mech as $user\n";
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
  my (@nargv, $opt);
  shift(@argv);
  while (defined ($opt = shift(@argv))) {
    # gack.  bloody tcl.
    last if $opt eq '--';
    if ($opt ne '' && '-subscribed' =~ /^\Q$opt/ || $opt eq '--subscribed') {
      $cmd = 'listsubscribed';
    }
    elsif ($opt =~ /^-/) {
      die "usage: listmailbox [-subscribed] [pattern [base]]\n";
    }
    else {
      push(@nargv, $opt);
      last;
    }
  }
  push(@nargv, @argv);
  if (@nargv > 2) {
    die "usage: listmailbox [-subscribed] [pattern [base]]\n";
  }
  push(@nargv, '*') if !@nargv;
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
  my %acl = $$cyrref->listaclmailbox(@nargv);
  if (defined $$cyrref->error) {
    $lfh->[2]->print($$cyrref->error, "\n");
    return 1;
  }
  foreach my $acl (keys %acl) {
    $lfh->[1]->print($acl, " ", $acl{$acl}, "\n");
  }
  0;
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
    die "usage: authenticate [-minssf N] [-maxssf N] [-mechanisms STR]\n".
        "                    [-service name] [user]\n";
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
		     $quota{$quota}[1], " (",
		     $quota{$quota}[0] * 100 / $quota{$quota}[1], "%)");
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
		     $quota{$quota}[1], " (",
		     $quota{$quota}[0] * 100 / $quota{$quota}[1], "%)");
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
  my (@nargv, $opt, $part, $want);
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
      die "usage: createmailbox [--partition partition] mailbox [partition]\n";
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
  $part = pop(@nargv) if @nargv == 2 && !defined($part);
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
  if (!@nargv || @nargv > 2) {
    die "usage: deletemailbox mailbox [host]\n";
  }
  # @@ do I really care?
  if (@nargv == 2) {
    die "deletemailbox: host argument only supported in IMSP\n";
  }
  if (!$cyrref || !$$cyrref) {
    die "deletemailbox: no connection to server\n";
  }
  $$cyrref->delete(@nargv) || die "deletemailbox: " . $$cyrref->error . "\n";
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
  $$cyrref->deleteacl(@nargv) ||
    die "deleteaclmailbox: " . $$cyrref->error . "\n";
  0;
}

sub _sc_setacl {
  my ($cyrref, $name, $fh, $lfh, @argv) = @_;
  my (@nargv, $opt);
  shift(@argv);
  while (defined ($opt = shift(@argv))) {
    last if $opt eq '--';
    if ($opt =~ /^-/) {
      die "usage: setaclmailbox mailbox id [id ...]\n";
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
  $$cyrref->setacl(@nargv) || die "setaclmailbox: " . $$cyrref->error . "\n";
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
      @nargv = ($mbox, "STORAGE", $limit);
  }
  if (@nargv < 3 || (@nargv - 1) % 2) {
    die ("usage: setquota mailbox limit num [limit num ...]\n" .
	 "       setquota mailbox num\n");
  }
  if (!$cyrref || !$$cyrref) {
    die "setquota: no connection to server\n";
  }
  $$cyrref->setquota(@nargv) || die "setquota: " . $$cyrref->error . "\n";
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

=head1 NAME

Cyrus::IMAP::Shell - Perl version of cyradm

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

=item C<create> I<mailbox I<partition>

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

=item listaclmailbox I<mailbox>

=item listacl I<mailbox>

=item lam I<mailbox>

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
a quota assigned, an error will be raised; see L<listquotaroot> for a way to
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

Create (subfolders)

=item d

Delete (STORE \DELETED, EXPUNGE)

=item a

Administer (SETACL)

=back

=item C<setquota> I<root> I<resource> I<value> [I<resource> I<value> ...]

=item C<sq> I<root> I<resource> I<value> [I<resource> I<value> ...]

Set a quota on the specified root, which may or may not be an actual mailbox.
The only I<resource> understood by B<Cyrus> is C<STORAGE>.

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
