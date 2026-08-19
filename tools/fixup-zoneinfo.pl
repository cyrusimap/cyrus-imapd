#!/usr/bin/perl
# fixup-zoneinfo.pl --
#   Normalise the TZIDs in a zoneinfo directory that vzic just wrote
# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.
#
# Usage: fixup-zoneinfo.pl [-v] <zoneinfo-dir>
#
# We keep quiet about a zoneinfo directory that needed no fixing up, and report
# what we found and stripped otherwise.  -v reports either way.
#
# The TZID of every VTIMEZONE must be exactly its path below <zoneinfo-dir>,
# minus the ".ics": http_tzdist serves a time zone by opening
# <zoneinfo_dir>/<tzid>.ics, ctl_zoneinfo keys zoneinfo.db on the TZID it reads
# out of the file, and guesstz recognises the canonical zones by name.  vzic
# writes a vendor prefix in front of that name unless it was compiled with an
# empty TZID_PREFIX -- see the TZDist chapter of the docs.
#
# We take the path as the authority and strip whatever prefix precedes it,
# which also works when the prefix is already empty.  Anything we cannot
# explain as a prefix is a fatal error: better a failed build than time zone
# data that Cyrus quietly fails to resolve.

use strict;
use warnings;
use File::Find;

# A tzdata name: one or more '/'-separated components of alphanumerics, '_',
# '-' and '+', e.g. "GMT+0", "W-SU", "America/Argentina/Buenos_Aires".
my $TZID_RE = qr{[A-Za-z0-9_+-]+(?:/[A-Za-z0-9_+-]+)*};

my $verbose = @ARGV && $ARGV[0] eq '-v' ? shift @ARGV : 0;
my $zonedir = shift @ARGV;
die "usage: $0 [-v] <zoneinfo-dir>\n" if !defined $zonedir || @ARGV;
$zonedir =~ s{/+\z}{};

my @files;
find({
    no_chdir => 1,
    wanted => sub {
        # Skip symlinks: vzic writes an alias either as its own VTIMEZONE or
        # as a link to the zone it aliases, and we fix that zone's own file.
        push @files, $File::Find::name if /\.ics\z/ && -f && !-l;
    },
}, $zonedir);
die "no VTIMEZONEs in $zonedir\n" if !@files;

my ($naliases, $ntoplevel) = (0, 0);
my %prefixes;

for my $file (sort @files) {
    my $name = substr $file, length($zonedir) + 1, -length('.ics');
    die "$file: not an IANA time zone name: $name\n" if $name !~ /\A$TZID_RE\z/;

    open my $fh, '<:raw', $file or die "$file: $!\n";
    my @lines = split /\r\n/, do { local $/; <$fh> }, -1;
    close $fh;

    # Rejoin the folded lines of the two properties we rewrite, and leave
    # every other line of the file byte for byte as vzic wrote it.
    my (@out, $itzid, $ialias);
    while (defined(my $line = shift @lines)) {
        if ($line =~ /\A(?:TZID|TZID-ALIAS-OF):/) {
            $line .= substr shift(@lines), 1 while @lines && $lines[0] =~ /\A[ \t]/;
            $itzid  = @out if $line =~ /\ATZID:/;
            $ialias = @out if $line =~ /\ATZID-ALIAS-OF:/;
        }
        push @out, $line;
    }

    die "$file: no TZID property\n" if !defined $itzid;
    my $tzid = substr $out[$itzid], length 'TZID:';
    if ($tzid !~ s/\Q$name\E\z//) {
        die "$file: TZID is $tzid, expected it to end in $name\n";
    }
    my $prefix = $tzid;
    $prefixes{$prefix} = 1;

    my $aliasof;
    if (defined $ialias) {
        $naliases++;
        $ntoplevel++ if $name !~ m{/};
        $aliasof = substr $out[$ialias], length 'TZID-ALIAS-OF:';
        if (length $prefix && $aliasof !~ s/\A\Q$prefix\E//) {
            die "$file: TZID-ALIAS-OF is $aliasof, expected the prefix $prefix\n";
        }
        if ($aliasof !~ /\A$TZID_RE\z/) {
            die "$file: TZID-ALIAS-OF is not an IANA time zone name: $aliasof\n";
        }
    }

    # Only rewrite what we changed, so that a correctly built vzic leaves the
    # mtimes -- and the incremental build -- alone.
    next if !length $prefix;

    $out[$itzid] = "TZID:$name";
    $out[$ialias] = "TZID-ALIAS-OF:$aliasof" if defined $ialias;

    open $fh, '>:raw', $file or die "$file: $!\n";
    print $fh join "\r\n", @out or die "$file: $!\n";
    close $fh or die "$file: $!\n";
}

die "inconsistent TZID prefixes in $zonedir: ",
    join(' ', map { qq{"$_"} } sort keys %prefixes), "\n" if keys %prefixes > 1;

# A vzic built the way we expect it leaves us nothing to say, so say nothing
# unless we changed the data or the caller asked to hear it either way.
my ($prefix) = keys %prefixes;
if ($verbose || length $prefix) {
    printf "zoneinfo: %d VTIMEZONEs, %d aliases (%d top-level)%s\n",
        scalar @files, $naliases, $ntoplevel,
        length $prefix ? qq{, stripped TZID prefix "$prefix"} : '';
}
