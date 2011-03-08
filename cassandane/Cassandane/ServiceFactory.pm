#!/usr/bin/perl

package Cassandane::ServiceFactory;
use strict;
use warnings;
use Cassandane::Util::Log;
use Cassandane::Service;
use Cassandane::IMAPService;

sub create
{
    my $class = shift;
    my $name = shift;
    my %params = @_;

    die "No name specified"
	unless defined $name;

    # try and guess some service-specific defaults
    if ($name =~ m/imap/)
    {
	return Cassandane::IMAPService->new($name,
				binary => 'imapd',
				%params);
    }
    elsif ($name =~ m/sync/)
    {
	return Cassandane::Service->new($name,
				binary => 'sync_server',
				%params);
    }
    else
    {
	die "No binary specified and cannot guess a default"
	    unless defined $params{binary};
	return Cassandane::Service->new($name, %params);
    }
}

1;
