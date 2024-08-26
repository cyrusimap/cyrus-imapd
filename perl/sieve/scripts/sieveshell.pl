#!/usr/bin/perl
#
# Copyright (c) 1994-2020 Carnegie Mellon University.  All rights reserved.
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

use strict;
use warnings;

use Cyrus::SIEVE::managesieve;
use Getopt::Long;
use strict;
use File::Temp qw/ tempfile /;
use Pod::Usage;
use Term::ReadLine;
use POSIX qw(:sys_wait_h);

my $puthelp =        "put <filename> [<target name>]\n" .
                     "                 - upload script to server\n";
my $gethelp =        "get <name> [<filename>]\n" .
                     "                 - get script. if no filename display to stdout\n";
my $activatehelp =   "activate <name>  - set a script as the active script\n";
my $deactivatehelp = "deactivate       - deactivate all scripts\n";
my $deletehelp =     "delete <name>    - delete script.\n";

my $username = $ENV{USER};
my $authname = $ENV{USER};
my $realm = "";
my $password;
my $ex = "";
my $exfile = "";
my $help = 0;
my $man = 0;
my $ret;

GetOptions("a|authname:s" => \$authname,
    "u|username:s" => \$username,
    "r|realm:s" => \$realm,
    "p|password:s" => \$password,
    "e|exec:s" => \$ex,
    "f|execfile:s" => \$exfile,
    "help|?" => \$help,
    man => \$man) or pod2usage(2);
pod2usage(1) if $help;
pod2usage(-exitstatus => 0, -verbose => 2) if $man;

if ($#ARGV != 0) {
    pod2usage("$0: need a server\n");
}

my $acapserver = $ARGV[0];

my $filehandle;
my $interactive;

if (! $exfile eq "") {
    open(FILEH,"<$exfile") || die "unable to open file: $?";
    $filehandle = *FILEH;
    $interactive = 0;
} elsif (! $ex eq "") {
    $filehandle = tempfile();

    if (!$filehandle) { die "unable to open tmp file: $?"; }

    print $filehandle $ex;
    seek $filehandle, 0, 0; # rewind file
    $interactive = 0;
} else {
    $filehandle = *STDIN;
    $interactive = 1;
}

sub list_cb {

  my($name, $isactive) = @_ ;

  print "$name ";
  if ($isactive == 1) {
    print " <- active script\n";
  } else {
    print "\n";
  }

}

sub prompt {

  my($type, $prompt) = @_ ;

  if (($type eq "username") && (defined $username)) {
      return $username;
  } elsif (($type eq "authname") && (defined $authname)) {
      return $authname;
  } elsif (($type eq "realm") && (defined $realm)) {
      return $realm;
  } elsif (($type eq "password") && (defined $password)) {
      return $password;
  }

  my $ostty;
  my $str = "";
  chomp($ostty = `stty -g`);

  if ($type eq "password") {
      system "stty -echo -icanon min 1 time 0 2>/dev/null || " .
             "stty -echo cbreak";
      $str = "\n";
  }

  print "$prompt: ";

  $b = <STDIN>;
  chop($b);

  print $str;
  system "stty $ostty";

  return $b;
}

sub show_help {
  print "Usage:\n";
  print "  sieveshell [-u username] [-a authname] [-r realm] <server>\n";
  print "\n";
  print "help             - this screen\n";
  print "list             - list scripts on server\n";
  print $puthelp;
  print $gethelp;
  print $deletehelp;
  print $activatehelp;
  print $deactivatehelp;
  print "quit             - quit\n";
}

# main code

print "connecting to $acapserver\n";

my $obj = sieve_get_handle($acapserver,
                           "prompt", "prompt", "prompt", "prompt");

if (!defined $obj) {
    die "unable to connect to server";
}

my $term = Term::ReadLine->new("sieveshell");

my $exitcode = 0;

$term->ornaments(0);

while(defined($_  = ($interactive ? $term->readline('> ') : <$filehandle>))){

  $term->addhistory($_);

  my @words = split ' ',$_;
  my $str;
    if ($#words < 0) {
        next;
    }

    if (($words[0] eq "put") ||
        ($words[0] eq "p")) {
      if($#words == 1) {
        $ret = sieve_put_file($obj, $words[1]);
      } elsif ($#words == 2) {
        $ret = sieve_put_file_withdest($obj, $words[1], $words[2]);
      } else {
        print $puthelp;
        next;
      }
      if ($ret != 0) {
        my $errstr = sieve_get_error($obj);
        $errstr = "unknown error" if(!defined($errstr));
        print "upload failed: $errstr\n";
        $exitcode = 1;
      }
    } elsif (($words[0] eq "list") ||
             ($words[0] eq "l") ||
             ($words[0] eq "ls")) {
        $ret = sieve_list($obj, "list_cb");
        if ($ret != 0) {
            my $errstr = sieve_get_error($obj);
            $errstr = "unknown error" if(!defined($errstr));
            print "list failed: $errstr\n";
            $exitcode = 1;
        }
    } elsif (($words[0] eq "activate") ||
             ($words[0] eq "a")) {
        if ($#words != 1) {
            print $activatehelp;
            next;
        }
        $ret = sieve_activate($obj, $words[1]);
        if ($ret != 0) {
            my $errstr = sieve_get_error($obj);
            $errstr = "unknown error" if(!defined($errstr));
            print "activate failed: $errstr\n";
            $exitcode = 1;
        }
    } elsif (($words[0] eq "deactivate") ||
             ($words[0] eq "da")) {
        if ($#words != 0) {
            print $deactivatehelp;
            next;
        }
        $ret = sieve_activate($obj, "");
        if ($ret != 0) {
            my $errstr = sieve_get_error($obj);
            $errstr = "unknown error" if(!defined($errstr));
            print "deactivate failed: $errstr\n";
            $exitcode = 1;
        }
    } elsif (($words[0] eq "delete") ||
             ($words[0] eq "d")) {
        if ($#words != 1) {
            print $deletehelp;
            next;
        }
        $ret = sieve_delete($obj, $words[1]);
        if ($ret != 0) {
            my $errstr = sieve_get_error($obj);
            $errstr = "unknown error" if(!defined($errstr));
            print "delete failed: $errstr\n";
            $exitcode = 1;
        }
    } elsif (($words[0] eq "get") ||
             ($words[0] eq "g")) {
        if ($#words != 1 && $#words != 2) {
            print $gethelp;
            next;
        }
        $str = "";
        $ret = sieve_get($obj, $words[1], $str);
        if ($ret != 0) {
            my $errstr = sieve_get_error($obj);
            $errstr = "unknown error" if(!defined($errstr));
            print "get failed: $errstr\n";
            $exitcode = 1;
        } else {
            if ($words[2]) {
                open (OUTPUT,">$words[2]") || die "Unable to open $words[2]";
                print OUTPUT $str;
                close(OUTPUT);
            } else {
                print $str;
            }
        }
    } elsif (($words[0] eq "quit") || ($words[0] eq "q")) {
        sieve_logout($obj);
        last;
    } elsif (($words[0] eq "help") || ($words[0] eq "?")) {
        show_help();
    } else {
        print "Invalid command: $words[0]\n";
        $exitcode = 1;
    }
}

exit $exitcode

__END__

=for pod2rst .. DO NOT EDIT sieveshell.rst: Autogenerated by tools/perl2rst from perl/sieve/scripts/sieveshell.pl

=for pod2rst .. cyrusman:: sieveshell(1)

=for pod2rst .. _imap-reference-manpages-usercommands-sieveshell:

=head1 NAME

sieveshell - remotely manipulate sieve scripts

=head1 SYNOPSIS

sieveshell [B<--user>=I<user>] [B<--authname>=I<authname>]
[B<--realm>=I<realm>] [B<--password>=I<password>]
[B<--exec>=I<script>] [B<--execfile>=I<file>] I<server>[B<:>I<port>]

sieveshell B<--help>

=head1 DESCRIPTION

B<sieveshell> allows users to manipulate their scripts on a remote
server.  It works via MANAGESIEVE, a work in progress.

The following commands are recognized:

=over 4

B<list> list scripts on server.

B<put> <filename> upload script to server.

B<get> <name> [<filename>] get script. if no filename display to stdout

B<delete> <name> delete script.

B<activate> <name> activate script.

B<deactivate> deactivate all scripts.

=back

=head1 OPTIONS

=over 4

=item B<-u> I<user>, B<--user>=I<user>

The user whose mailboxes you want to work on. If not specified, it uses the same
as -a.

=item B<-a> I<authname>, B<--authname>=I<authname>

The user to use for authentication. If not specified, it defaults to the
current login user.

=item B<-r> I<realm>, B<--realm>=I<realm>

The realm to attempt authentication in.

=item B<-p> I<password>, B<--password>=I<password>

The password to use when authenticating to server. Note that this
parameter can be seen in the process list. B<Use with caution!>

=item B<-e> I<script>, B<--exec>=I<script>

Instead of working interactively, run commands from I<script>, and
exit when done.

=item B<-f> I<file>, B<--execfile>=I<file>

Instead of working interactively, run commands from file I<file> and
exit when done.

=back

=head1 REFERENCES

[MANAGESIEVE] Martin, T.; "A Protocol for Remotely Managing Sieve
Scripts", RFC 5804; May 2001

=head1 AUTHOR

Tim Martin E<lt>tmartin@mirapoint.comE<gt>, and the rest of the Cyrus
team.
