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
my $perl_prefix = normalise($Config{prefix});

# These directories are listed in the reverse of the order that we want
# them searched, assuming that we will emit multiple "use lib"
# directives each of which *prepends* its argument to @INC.
# XXX This set of mappings works when Cyrus was configured with
# XXX --prefix=/usr/local, but on my system it fails for --prefix=/usr.
# XXX It still looks for some things in /usr/local, but doesn't find them
# XXX because they were installed to /usr.  Might just need more mappings.
# XXX In practice I don't think anyone configures Cyrus with either of
# XXX these prefixes.
my @dirvars = (
    { dir => 'installvendorlib', prefix => 'vendorprefix' },
    { dir => 'installvendorarch', prefix => 'vendorprefix' },
    { dir => 'installsitelib', prefix => 'siteprefix' },
    { dir => 'installsitearch', prefix => 'siteprefix' },
);

my $boilerplate = << 'EOT';
## Boilerplate added by Cyrus fixsearchpath.pl
use Cwd qw(abs_path);
use FindBin;

my $__cyrus_destdir;
BEGIN {
    $__cyrus_destdir = '';
    my $real_prefix = abs_path("$FindBin::Bin/..");
EOT

$boilerplate .= "    my \$configure_prefix = '$configure_prefix';\n";

$boilerplate .= << 'EOT';
    my $len = length($real_prefix) - length($configure_prefix);
    # check if the real prefix ends in the configured prefix
    if (substr($real_prefix, $len) eq $configure_prefix) {
        # if so then the installed destdir is what remains
        $__cyrus_destdir = substr($real_prefix, 0, $len);
    }
}
EOT

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
    if ($. == 1 && m/^#!perl$/) {
        # replace bare perl shebang with the running perl
        $_ = "#!$Config{perlpath}\n";
    }

    if (defined $boilerplate && m/^use\s+(?!strict|warnings)/) {
        print $boilerplate;
        $boilerplate = undef;
    }

    print $_;
}
