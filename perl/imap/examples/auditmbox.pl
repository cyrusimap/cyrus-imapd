#! /usr/bin/perl -w
# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

# This script WON'T work for you.  Guaranteed.
# It checks CMU ECE policy, and your policy *will* be different.
# Use it only as an example of how to use Cyrus::IMAP::Admin, as it will
# almost certainly be useless to you as an actual program.
#
# This script sanity-checks departmental accounts against both the password
# file and Cyrus.  It makes a LOT of CMU ECE-specific assumptions.  It also
# doesn't do much with Cyrus aside from authenticating and getting a list of
# top-level mailboxes, but this is currently all I have in the way of Perl
# that uses IMAP::Cyrus.
#

use strict;
use Cyrus::IMAP::Admin;
use IO::File;

# this sucks, but the current Authen::Krb4 doesn't support any ticket cache
# operations other than dest_tkt()
my $ccache;
chomp($ccache = `klist 2>/dev/null`);
$ccache =~ s/\r?\n.*\Z//sm;
$ccache =~ s!^[^/]+!!;
my $cache = IO::File->new($ccache, O_RDONLY) or die "No tickets.\n";
my ($user, $instance, $dot);
{
  local($/) = "\0";
  chomp($user = $cache->getline);
  chomp($instance = $cache->getline);
  $dot = ($instance eq '' ? '' : '.');
}
my $cyradm = Cyrus::IMAP::Admin->new('ece') or die "Can't connect to Cyrus.\n";
$cyradm->authenticate(-user => "$user$dot$instance")
  or die "Can't authenticate to Cyrus.\n";
my (%mailbox, $found);
$found = 0;
foreach my $mbx ($cyradm->list('user.', '%')) {
  $found = 1;
  $mbx->[0] =~ s/^user\Q$mbx->[2]\E//;
  $mbx->[0] =~ s/\Q$mbx->[2]\E.*$//;
  $mailbox{$mbx->[0]}{cyrus} = 1;
}
$cyradm = undef;
die "Cannot access user.*: non-admin credentials, or server horked?\n"
  unless $found;

my $passwd = IO::File->new('/etc/passwd', O_RDONLY) or die;
my $ok;
while (defined ($user = $passwd->getline)) {
  chomp($user);
  next unless $user =~ m!:/afs/ece/(usr|class)/[^:]+:[^:]+$!;
  $ok = ($user !~ /sh$/);
  $user =~ s/:.*$//;
  $mailbox{$user}{passwd} = $ok;
}
$passwd = undef;

my $wp = IO::File->new('/etc/mail/wp.txt', O_RDONLY) or die;
while (defined ($user = $wp->getline)) {
  chomp($user);
  next unless $user =~ /([^\@:]+):[^:]*:\1\@ece.cmu.edu$/;
  $mailbox{$1}{wp} = 1;
}

my $str;
foreach $user (keys %mailbox) {
  $str = '';
  next if defined($mailbox{$user}{passwd}) && !$mailbox{$user}{passwd} &&
    !$mailbox{$user}{wp} && !$mailbox{$user}{cyrus};
  if (!defined($mailbox{$user}{cyrus})) {
    if ($str eq '') {
      $str = $user . ': ';
    } else {
      $str .= ', ';
    }
    $str .= 'no cyrus mailbox';
  }
  if (!defined($mailbox{$user}{passwd})) {
    if ($str eq '') {
      $str = $user . ': ';
    } else {
      $str .= ', ';
    }
    $str .= 'no/invalid passwd entry';
  }
  if (!defined($mailbox{$user}{wp})) {
    if ($str eq '') {
      $str = $user . ': ';
    } else {
      $str .= ', ';
    }
    $str .= 'no/invalid wp.txt entry';
  }
  print $str, "\n" if $str ne '';
}
