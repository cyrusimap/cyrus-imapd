#!/usr/bin/perl

use warnings;
use strict;

use Config;

use lib '.';
use Cassandane::Cassini;

# XXX borrowed and tweaked from Cassandane::Instance
sub _cyrus_perl_search_path
{
    my ($prefix, $destdir) = @_;
    my @inc = (
        substr($Config{installvendorlib}, length($Config{vendorprefix})),
        substr($Config{installvendorarch}, length($Config{vendorprefix})),
        substr($Config{installsitelib}, length($Config{siteprefix})),
        substr($Config{installsitearch}, length($Config{siteprefix}))
    );

    my @paths;
    my $found = 0;
    foreach (@inc) {
        my $p = $destdir . $prefix . $_;
        $found++ if -d $p;
        push @paths, "-I $p";
    }

    warn "warning: Cyrus perl paths not found on disk.  Is Cyrus installed?\n"
        if not $found;
    return @paths;
}

my $cassini = Cassandane::Cassini->instance();

my $cyrus_prefix = $cassini->val('cyrus default', 'prefix', '/usr/cyrus');
my $cyrus_destdir = $cassini->val('cyrus default', 'destdir', '');

my @path = _cyrus_perl_search_path($cyrus_prefix, $cyrus_destdir);

print join(' ', @path), "\n";
