#!perl
# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

use strict;
use warnings;

use Cyrus::SIEVE::managesieve;
use Getopt::Long;
use File::Temp qw/ tempfile /;
use Pod::Usage;
use Term::ReadLine;
use POSIX qw(:termios_h);

my $termios_saved;
my $termios_fd;

sub term_noecho {
    $termios_fd = fileno(STDIN);
    $termios_saved = POSIX::Termios->new;
    $termios_saved->getattr($termios_fd);

    my $term_noecho = POSIX::Termios->new;
    $term_noecho->getattr($termios_fd);
    $term_noecho->setlflag($term_noecho->getlflag & ~ECHO);
    $term_noecho->setattr($termios_fd, TCSANOW);
}

sub term_restore {
    if (defined $termios_saved && defined $termios_fd) {
        $termios_saved->setattr($termios_fd, TCSANOW);
    }
}

END { term_restore() }

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

if ($exfile ne "") {
    open($filehandle, '<', $exfile) || die "unable to open file: $!";
    $interactive = 0;
} elsif ($ex ne "") {
    $filehandle = tempfile();

    if (!$filehandle) { die "unable to open tmp file: $!"; }

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

  my %defaults = (
      username => $username,
      authname => $authname,
      password => $password,
      realm    => $realm,
  );

  if (defined $defaults{$type}) {
      return $defaults{$type};
  }

  my $input;

  print "$prompt: ";

  if ($type eq "password") {
    term_noecho();
    $input = <STDIN>;
    term_restore();
    print "\n";
  } else {
    $input = <STDIN>;
  }

  return "" unless defined $input;
  chomp($input);
  return $input;
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

sub check_sieve_error {
    my ($obj, $action) = @_;
    my $errstr = sieve_get_error($obj) // "unknown error";
    print "$action failed: $errstr\n";
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

  my ($cmd, @args) = split ' ', $_;
  my $str;
    if (!defined $cmd) {
        next;
    }

    if ($cmd eq "put" || $cmd eq "p") {
        if (@args == 1) {
            $ret = sieve_put_file($obj, $args[0]);
        } elsif (@args == 2) {
            $ret = sieve_put_file_withdest($obj, $args[0], $args[1]);
        } else {
            print $puthelp;
            next;
        }
        if ($ret != 0) {
            check_sieve_error($obj, "upload");
            $exitcode = 1;
        }

    } elsif ($cmd eq "list" || $cmd eq "l" || $cmd eq "ls") {
        $ret = sieve_list($obj, "list_cb");
        if ($ret != 0) {
            check_sieve_error($obj, "list");
            $exitcode = 1;
        }

    } elsif ($cmd eq "activate" || $cmd eq "a") {
        if (@args != 1) {
            print $activatehelp;
            next;
        }
        $ret = sieve_activate($obj, $args[0]);
        if ($ret != 0) {
            check_sieve_error($obj, "activate");
            $exitcode = 1;
        }

    } elsif ($cmd eq "deactivate" || $cmd eq "da") {
        if (@args != 0) {
            print $deactivatehelp;
            next;
        }
        $ret = sieve_activate($obj, "");
        if ($ret != 0) {
            check_sieve_error($obj, "deactivate");
            $exitcode = 1;
        }

    } elsif ($cmd eq "delete" || $cmd eq "d") {
        if (@args != 1) {
            print $deletehelp;
            next;
        }
        $ret = sieve_delete($obj, $args[0]);
        if ($ret != 0) {
            check_sieve_error($obj, "delete");
            $exitcode = 1;
        }

    } elsif ($cmd eq "get" || $cmd eq "g") {
        if (@args != 1 && @args != 2) {
            print $gethelp;
            next;
        }
        $str = "";
        $ret = sieve_get($obj, $args[0], $str);
        if ($ret != 0) {
            check_sieve_error($obj, "get");
            $exitcode = 1;
        } else {
            if (defined $args[1]) {
                open(my $output, '>', $args[1]) || die "Unable to open $args[1]: $!";
                print $output $str;
                close($output);
            } else {
                print $str;
            }
        }

    } elsif ($cmd eq "quit" || $cmd eq "q") {
        sieve_logout($obj);
        last;

    } elsif ($cmd eq "help" || $cmd eq "?") {
        show_help();

    } else {
        print "Invalid command: $cmd\n";
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
