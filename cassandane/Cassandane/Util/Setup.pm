# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Util::Setup;
use strict;
use warnings;
use base qw(Exporter);
use POSIX;
use User::pwent;
use Data::Dumper;

use Cassandane::Util::Log;

our @EXPORT = qw(&become_cyrus);

my $me = $0;
my @saved_argv = @ARGV;

sub become_cyrus
{
    my $cyrus = $ENV{CYRUS_USER};
    $cyrus //= 'cyrus';
    my $pw = getpwnam($cyrus);
    die "No user named '$cyrus'"
        unless defined $pw;
    my $uid = getuid();
    if ($uid == $pw->uid)
    {
        xlog "already running as user $cyrus" if get_verbose;
    }
    elsif ($uid == 0)
    {
        xlog "setuid from root to $cyrus" if get_verbose;
        setgid($pw->gid)
            or die "Cannot setgid to group $pw->gid: $!";
        setuid($pw->uid)
            or die "Cannot setuid to group $pw->uid: $!";
    }
    else
    {
        xlog "using sudo to re-run as user $cyrus" if get_verbose;
        my @cmd = ( qw(sudo -u), $cyrus, $me, @saved_argv );
        exec(@cmd);
    }
}

1;
