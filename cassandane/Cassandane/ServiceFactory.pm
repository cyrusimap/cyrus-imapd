# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::ServiceFactory;
use strict;
use warnings;

use Cassandane::Util::Log;
use Cassandane::Service;
use Cassandane::IMAPService;

sub create
{
    my ($class, %params) = @_;

    my $name = $params{name};
    die "No name specified"
        unless defined $name;

    # if caller knows what they're asking for, don't try to guess
    if (defined $params{argv}) {
        return Cassandane::Service->new(%params);
    }

    # try and guess some service-specific defaults
    if ($name =~ m/imap(s?)/)
    {
        my @argv = 'imapd';
        push @argv, '-s' if $1;
        return Cassandane::IMAPService->new(argv => \@argv, %params);
    }
    elsif ($name =~ m/sync/)
    {
        return Cassandane::Service->new(
                                argv => ['imapd'],
                                %params);
    }
    elsif ($name =~ m/http(s?)/)
    {
        my @argv = 'httpd';
        push @argv, '-s' if $1;
        return Cassandane::Service->new(argv => \@argv, %params);
    }
    elsif ($name =~ m/lmtp/)
    {
        return Cassandane::Service->new(
                                argv => ['lmtpd'],
                                %params);
    }
    elsif ($name =~ m/sieve/)
    {
        return Cassandane::Service->new(
                                argv => ['timsieved'],
                                %params);
    }
    elsif ($name =~ m/nntp/)
    {
        return Cassandane::Service->new(
                                argv => ['nntpd'],
                                %params);
    }
    elsif ($name =~ m/smmap/)
    {
        return Cassandane::Service->new(
                                argv => ['smmapd'],
                                %params);
    }
    elsif ($name =~ m/pop/)
    {
        return Cassandane::Service->new(
                                type => 'pop3',
                                argv => ['pop3d'],
                                %params);
    }
    elsif ($name =~ m/ptloader/)
    {
        return Cassandane::Service->new(
                                type => 'ptloader',
                                argv => ['ptloader', '-d', '99'],
                                port => '@basedir@/conf/ptsock',
                                %params);
    }
    elsif ($name =~ m/backupcyrusd/)
    {
        return Cassandane::Service->new(
                                argv => ['backupcyrusd'],
                                %params);
    }
    else
    {
        die "$name: No command specified and cannot guess a default";
    }
}

1;
