#! /bin/sh
exec perl -x -S $0 ${1+"$@"} # -*-perl-*-
#!perl -w
# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

use Cyrus::SIEVE::managesieve;
use Getopt::Long;

$username = "";

print "NOTE: This program is deprecated. Please use sieveshell\n";
print "\n";

$ret = GetOptions("v|views:s" => \$views,
                  "l|list" => \$list,
#                 "p|port:i" => \$port,
                  "i|installs:s" => \$installs,
                  "a|activates:s" => \$activates,
                  "d|deletes:s" => \$deletes,
#                 "m|mechanism:s" => \$mech,
                  "g|gets:s" => \$gets,
                  "u|username:s" => \$username,
#                 "w|password:s" => \$pass
                  );
if (!$ret || $#ARGV != 0) {
    show_help();
    exit;
}

$acapserver = $ARGV[0];

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
  } elsif (($type eq "authname") && (defined $username)) {
      return $username;
  } elsif (($type eq "realm") && (defined $realm)) {
      return $realm;
  }

  print "$prompt: ";

  $b = <STDIN>;
  chop($b);

  $b;
}

sub show_help {
  print "Usage:\n";
  print "  installsieve [options] <server>\n";
  print "\n";
  print "  -v <name>    view script\n";
  print "  -l           list available scripts\n";
#  print "  -p <port>    port to connect to\n";
  print "  -i <file>    filename of script to install\n";
  print "  -a <name>    Set <name> as the active script\n";
  print "  -d <name>    Delete <name> script from server\n";
#  print "  -m <mech>    Mechanism to use for authentication\n";
  print "  -g <name>    Get script <name> and save to disk\n";
  print "  -u <user>    Userid/Authname to use\n";
#  print "  -w <passwd>  Specify password (Should only be used for automated scripts)\n";
  print "\n";
}

sub error {
    my ($obj, $msg) = @_;
    my $errstr = sieve_get_error($obj);
    print STDERR "$msg\n$errstr";
    exit(1);
}

#main code
my $obj = sieve_get_handle($acapserver,"prompt","prompt","prompt","prompt");

if (!defined $obj) {
  die "Unable to connect to server";
}

if (defined $installs) {
  $ret = sieve_put_file($obj, $installs);
  if ($ret != 0) { error($obj, "upload failed"); }
}

if (defined $deletes) {
  $ret = sieve_delete($obj, $deletes);
  if ($ret != 0) { error($obj, "delete failed"); }
}

if (defined $activates) {
  $ret = sieve_activate($obj, $activates);
  if ($ret != 0) { error($obj, "activate failed"); }
}

if (defined $gets) {
    $str = "";
    $ret = sieve_get($obj, $gets, $str);
    if ($ret != 0) {
        error($obj, "get failed");
    } else {
        open (OUTPUT,">$gets") || die "Unable to open $gets";
        print OUTPUT $str;
        close(OUTPUT);
    }
}
if (defined $views) {
    $str = "";
    $ret = sieve_get($obj, $views, $str);
    if ($ret != 0) {
        error($obj, "get failed");
    } else {
        # view
        print $str;
    }
}

if (defined $list) {
  $ret = sieve_list($obj, "list_cb");
  if ($ret != 0) { error("List command failed"); }
}
