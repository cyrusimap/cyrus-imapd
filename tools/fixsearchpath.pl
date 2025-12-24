#!/usr/bin/perl
# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

use strict;
use warnings;
use Config;

sub normalise {
    my $s = shift;
    $s =~ s/\/+$//;
    return $s;
}

sub quote {
    my $s = shift;
    return "'$s'";
}

sub usage {
    die "Usage: $0 configure_prefix configure_bindir";
}

my $configure_prefix = normalise(shift || usage);
my $configure_bindir = normalise(shift || usage);
my $perl_prefix = normalise($Config{prefix});

# These directories are listed in the reverse of the order that we want
# them searched, assuming that we will emit multiple "use lib"
# directives each of which *prepends* its argument to @INC.
my @dirvars = (
    { dir => 'installvendorlib', prefix => 'vendorprefix' },
    { dir => 'installvendorarch', prefix => 'vendorprefix' },
    { dir => 'installsitelib', prefix => 'siteprefix' },
    { dir => 'installsitearch', prefix => 'siteprefix' },
);

my $boilerplate = << 'EOT'
## Boilerplate added by Cyrus fixsearchpath.pl
## XXX This might all be for naught because the top-level Cyrus build does
## XXX not pass DESTDIR down to the perl modules anyway.
my $__cyrus_destdir;
BEGIN {
    $__cyrus_destdir = '';
    if ($0 =~ m/\//) {
        my $d = $0;
EOT
;
$boilerplate .= "        my \$bindir = "
                . quote($configure_prefix . $configure_bindir)
                . ";\n";
$boilerplate .= << 'EOT'
        # remove the filename, $d is now the installed bindir
        $d =~ s/\/[^\/]+$//;
        # check if the path ends in the configured bindir
        my $len = length($d)-length($bindir);
        if (substr($d, $len) eq $bindir) {
            # if so then the installed destdir is what remains
            $__cyrus_destdir = substr($d, 0, $len);
        }
    }
};
EOT
;

foreach my $dv (@dirvars) {
    my $dir = $Config{$dv->{dir}};
    if ($configure_prefix ne $perl_prefix) {
        # Expect to be installed into a non-default location
        # because Cyrus was built with a non-default --prefix
        my $install_prefix = normalise($Config{$dv->{prefix}});
        $dir = $configure_prefix . substr($dir, length($install_prefix));
    }
    $boilerplate .= 'use lib $__cyrus_destdir . ' . quote($dir) .  ";\n";
}
$boilerplate .= "##\n\n";

# Filter stdin to stdout
while (<STDIN>)
{
    if (defined $boilerplate && m/^use\s/) {
        print $boilerplate;
        $boilerplate = undef;
    }
    print $_;
}
