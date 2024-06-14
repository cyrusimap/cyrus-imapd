#!/usr/bin/env perl
#
# mkchartable.pl -- Generate character set mapping table
#
# Copyright (c) 1994-2008 Carnegie Mellon University.  All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in
#    the documentation and/or other materials provided with the
#    distribution.
#
# 3. The name "Carnegie Mellon University" must not be used to
#    endorse or promote products derived from this software without
#    prior written permission. For permission or any legal
#    details, please contact
#      Carnegie Mellon University
#      Center for Technology Transfer and Enterprise Creation
#      4615 Forbes Avenue
#      Suite 302
#      Pittsburgh, PA  15213
#      (412) 268-7393, fax: (412) 268-7395
#      innovation@andrew.cmu.edu
#
# 4. Redistributions of any form whatsoever must retain the following
#    acknowledgment:
#    "This product includes software developed by Computing Services
#     at Carnegie Mellon University (http://www.cmu.edu/computing/)."
#
# CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
# THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
# FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
# AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
# OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

use strict;
use warnings;

# n.b. this script MUST NOT 'use locale' as it depends on the stability
# of perl's default sort order (which is changed by locale-awareness)

use IO::File;
use Getopt::Long;

my @maps;
my @charsets;
my $aliasfile;
my %codemap;
my $output;

GetOptions( 'map|m=s'    => \@maps,      #strings
            'aliases|a=s' => \$aliasfile, #string
            'output|o=s' => \$output);    #string
open (OUTPUT, ">$output");

# charsets were probably specified in shell-glob order, which can vary by locale.
# sort them here, so that the ordering in our generated files is stable.
@charsets = sort @ARGV;

printheader(\@maps, \@charsets);

# first we parse the chartable unicode mappings and the fixes
# file to build the unicode to search canonical form tables.
foreach my $map (@maps) {
    readmapfile(\%codemap, $map);
}

# we follow any mappings repeatedly until nothing in the
# table doesn't change any more
mungemap(\%codemap);

# then print out the translation tables
printmap(\%codemap, $aliasfile);

# XXX - should probably require all files that are
# mentioned in the lookup table to be specified,
# or this sucker aintn't gunna compile.
foreach my $opt (@charsets) {
    print "mkchartable: mapping $opt...\n";
    my $table = readcharfile($opt);
    printtable($table, $opt);
}

printlookup();
close (OUTPUT);

exit 0;

sub usage {
    print "usage: mkchartable -m mapfile -o outputfile charsetfile...\n";
    exit(1);
}

# Read a Unicode table, deriving useful mappings from it
sub readmapfile {
    my ($codemap, $name) = @_;

    my $mapfile = IO::File->new($name, 'r') || die "Failed to open $name\n";

    while (my $line = $mapfile->getline()) {
        chomp $line;
        $line =~ s/^\s+//; # strip leading space
        next if $line =~ m/^\#/; # comment
        next if $line eq ''; # blank

        my ($hexcode, $name, $category, $combiningclass, $bidicat,
            $decomposition, $decimal, $digit, $numeric, $mirroredchar,
            $uni1name, $comment, $upper, $lower, $title, @rest) = split ';', $line;
        my $code = hex($hexcode);

        # This is not RFC 5051
        if ($code != 32 and $category =~ m/^Z/) {
           $codemap->{$code}{chars} = [32]; # space
           next;
        }

        # has a mapping to titlecase
        $codemap->{$code}{title} = hex($title)
            if $title;

        # Compatability mapping, skip over the <type>
        while ($decomposition ne '') {
            # This is not RFC 5051
            if ($decomposition =~ s/^<[^>]*>\s+//) {
                # Ignore compat mappings to SP followed by combining char
                $decomposition = '' if $decomposition =~ m/^0020 /
            }

            if ($decomposition =~ s/([0-9a-fA-F]+)\s*//) {
                push @{$codemap->{$code}{chars}}, hex($1);
            }
        }

        $codemap->{$code}{chars} ||= [$code];
    }
}

# Perform the transitive closure on the unicode mapping table
# Calculate translations for mappings
sub mungemap {
    my ($codemap) = @_;

    my $total = keys %$codemap;
    my $changed;

    # Keep scanning the table until no changes are made
    do {
        $changed = 0;

        foreach my $code (sort { $a <=> $b } keys %$codemap) {
            my @new;
            my $chars = $codemap->{$code}{chars};

            # check if there are any translations for the mapped chars
            foreach my $char (@$chars) {
                if ($codemap->{$char}) {
                    my $newchars = $codemap->{$char}{chars};
                    push @new, @$newchars;
                }
                else {
                    push @new, $char;
                }
            }

            # strip all whitespace, but put back one if nothing left
            if (grep { $_ == 32 } @new) {
                @new = grep { $_ != 32 } @new;
                @new = (32) unless @new;
            }

            # no change
            next if ("@new" eq "@$chars");

            $changed++;
            $codemap->{$code}{chars} = \@new;
        }

        print "mkchartable: expanded unicode mappings... ($changed/$total)\n"
            if $changed;
    } while ($changed);

    print "mkchartable: building expansion table...\n";

    print OUTPUT <<EOF;
/* Table of translations */
HIDDEN const int chartables_translation_multichar[] = {
  0, /* the index of 0 is reserved to mean "no translation" */
EOF

    my $offset = 1;
    my $maxlen = 1;

    foreach my $code (sort { $a <=> $b } keys %$codemap) {
        my $chars = $codemap->{$code}{chars};
        if (@$chars > 1) {
            $maxlen = @$chars if $maxlen < @$chars;

            # add to the translation table
            print OUTPUT "  ";
            print OUTPUT join(", ", (map { sprintf("0x%04x", $_) } @$chars));
            printf OUTPUT ", 0, /* Translation for %04x (offset %d) */\n", $code, $offset;

            # update tracking
            $codemap->{$code}{trans} = $offset;
            $offset += @$chars + 1;
        }
    }

    print OUTPUT <<EOF;
};

EOF
}

# output the tables used for canonising the unicode
# into search normal form.
sub printmap {
    my ($codemap) = @_;

    print "mkchartable: building translation table...\n";

    # record which blocks we need mappings for
    my @needblock;
    foreach my $code (keys %$codemap) {
        $needblock[($code >> 16) & 0xff][($code >> 8) & 0xff] = 1;
    }

    print OUTPUT << "EOF";
/* The next two tables are used for doing translations from
 * 24-bit unicode values to canonical form.  First look up the
 * code >> 16 (highest order block) in the block16 table to
 * find the index to the block8 table for that block.
 * If the index is 255, there are no translations for that
 * block, so return the same value.  Otherwise, repeat for
 * code >> 8 (middle block) to get an index into the
 * direct translation block.  Again, 255 means no translations
 * for that block.  Finally the translation can be one of.
 *
 * 0: no output
 * +ve char: return this single char
 * -ve number: offset into the chartables_translation_multichar
 *             table.  Read chars until 0 encountered.
 */
HIDDEN const unsigned char chartables_translation_block16[256] = {
EOF

    my $n16 = 0;
    foreach my $block16 (0..255) {
        if ($needblock[$block16]) {
            printf OUTPUT (" %3d,", $n16++);
        } else {
            printf OUTPUT " 255,";
        }
        print OUTPUT "\n" if ($block16 % 8 == 7);
    }

    print OUTPUT <<EOF;
};

HIDDEN const unsigned char chartables_translation_block8[$n16][256] = {
EOF
    my $n8 = 0;
    foreach my $block16 (0..255) {
        my $need8 = $needblock[$block16];
        next unless $need8;
        print OUTPUT " { /* translation for 16 bit offset $block16 */\n ";
        foreach my $block8 (0..255) {
            if ($need8->[$block8]) {
                printf OUTPUT (" %3d,", $n8++);
            } else {
                printf OUTPUT " 255,";
            }
            print OUTPUT "\n " if ($block8 % 8 == 7);
        }
        print OUTPUT "},\n";
    }

    print OUTPUT <<EOF;
};

/* NOTE: Unlike other charset translation tables, the
 * chartables_translation table is NOT used to directly parse
 * a charset.  Instead, it's used to convert from a unicode
 * character to the "canonical form", possibly multiple
 * characters.
 */
HIDDEN const int chartables_translation[$n8][256] = {
EOF

    foreach my $block16 (0..255) {
        my $need8 = $needblock[$block16];
        next unless $need8;
        foreach my $block8 (0..255) {
            next unless $need8->[$block8];
            print OUTPUT " { /* Mapping for unicode chars in block $block16 $block8 */\n ";
            foreach my $i (0..255) {
                my $codepoint = ($block16 << 16) + ($block8 << 8) + $i;
                my $titlepoint = $codemap->{$codepoint}{title} || $codepoint;
                if (not $codemap->{$titlepoint} or not keys %{$codemap->{$titlepoint}}) {
                    printf OUTPUT " 0x%04x,", $titlepoint;
                }
                elsif ($codemap->{$titlepoint}{trans}) {
                    printf OUTPUT " - %4d,", $codemap->{$titlepoint}{trans};
                }
                else {
                    printf OUTPUT " 0x%04x,", $codemap->{$titlepoint}{chars}[0];
                }
                print OUTPUT "\n " if ($i % 8 == 7);
            }
            print OUTPUT "},\n";
        }
    }
    printf OUTPUT "};\n\n";
}

# read a charset table, building intermediate state tables
# for multibyte sequences and named state tables for mode
# switches
sub readcharfile {
    my ($name) = @_;

    my $charfile = IO::File->new($name, 'r') || die "Failed to read $name";

    my %data = (
        currstate => -1,
        num => 0,
        tables => [],
        states => {},
    );

    my $state;

    while (my $line = $charfile->getline()) {
        chomp $line;
        my $comment = $line;
        $line =~ s/^\s+//; # strip leading space
        next if $line =~ m/^\#/; # comment
        next if $line eq ''; # blank

        if ($line =~ m/^:(\S+)/) {
            # New state
            $state = getstate(\%data, $1);
            next;
        }

        $state ||= getstate(\%data, "");

        die "Invalid data line $line\n" unless $line =~ s/^([0-9a-fA-F]+)\s+//;

        my $code = hex($1);

        my $basestate = $state;

        if ($code > 0xffffff) {
           my $char = ($code >> 24) & 0xff;
           my $newname = sprintf "%s_%02x", $state->{name} || 'state', $char;
           my $newstate = getstate(\%data, $newname);
           $state->{chars}[$char] = [0, $newstate->{num}, "Auto multibyte state 4 bytes $newname"];
           $state = $newstate;
        }
        if ($code > 0xffff) {
           my $char = ($code >> 16) & 0xff;
           my $newname = sprintf "%s_%02x", $state->{name} || 'state', $char;
           my $newstate = getstate(\%data, $newname);
           $state->{chars}[$char] = [0, $newstate->{num}, "Auto multibyte state 3 bytes $newname"];
           $state = $newstate;
        }
        if ($code > 0xff) {
           my $char = ($code >> 8) & 0xff;
           my $newname = sprintf "%s_%02x", $state->{name} || 'state', $char;
           my $newstate = getstate(\%data, $newname);
           $state->{chars}[$char] = [0, $newstate->{num}, "Auto multibyte state 2 bytes $newname"];
           $state = $newstate;
        }

        my $char = $code & 0xff;
        die "Duplicate defs for $char in $state->{name}"
            if $state->{chars}[$char];

        # nothing
        if ($line =~ m/^\?/) {
            next;
        }

        # state switch
        if ($line =~ m/^:(\S*)/) {
            my $targetstate = getstate(\%data, $1);
            $state->{chars}[$char] = [0, $targetstate->{num}, $comment];
        }
        else {
            # otherwise it's a regular char
            die "Invalid data line $line\n" unless $line =~ s/^([0-9a-fA-F]+)\s+//;
            my $target = hex($1);
            $state->{chars}[$char] = [$target, $basestate->{num}, $comment];
        }

        $state = $basestate;
    }

    return \%data;
}

# helper function to create a new state within a charset
sub getstate {
    my ($data, $name) = @_;

    if (exists $data->{states}{$name}) { # could be 0
        return $data->{tables}[$data->{states}{$name}];
    }

    my $num = $data->{num};

    my $next = $num;
    if ($name =~ s/ \<$//) {
        $next = -1;
    }

    my $state = $data->{tables}[$num] = {
        name => $name,
        num => $num,
        next => $next,
        codes => {},
    };
    $data->{states}{$name} = $num;

    $data->{num}++;

    return $state;
}

# output the table used for charset->unicode translation
sub printtable {
    my ($data, $name) = @_;

    my $num = $data->{num};
    my $tables = $data->{tables};

    $name =~ s{.*[\\/]}{}; # strip anything up to the last separator;
    $name =~ s{\..*}{}; # after a dot
    $name =~ s{-}{_}g; # underscores

    print OUTPUT "static const struct charmap chartables_$name\[$num][256] = {\n";

    foreach my $table (@$tables) {
        my $chars = $table->{chars};
        print OUTPUT " {";
        if ($table->{name}) {
            print OUTPUT " /* $table->{name} */";
        }
        print OUTPUT "\n";
        foreach my $i (0..255) {
            my $char = $chars->[$i];
            if ($char) {
                print OUTPUT "   { $char->[0], $char->[1] }, /* $char->[2] */\n";
            }
            else {
                print OUTPUT "   { 0xfffd, 0 }, /* no such character */\n";
            }
        }
        print OUTPUT " },\n";
    }
    print OUTPUT "};\n\n";
}

# print the header of the chartable.c file
sub printheader {
    my ($maps, $charsets) = @_;

    print OUTPUT <<EOF;
/* This file is generated by mkchartable.pl with the following arguments
 *
EOF
    foreach my $map (@$maps) {
        my $sha1 = getsha1($map);
        print OUTPUT " * map:     $sha1 $map\n";
    }
    foreach my $charset (@$charsets) {
        my $sha1 = getsha1($charset);
        print OUTPUT " * charset: $sha1 $charset\n";
    }
    print OUTPUT <<EOF;
 */

#include "chartable.h"
#include "config.h"

EOF
}

# print the lookup table for charactersets at the end
# of the chartable.c file.
sub printlookup {
    print OUTPUT <<EOF;

/*
 * Mapping of character sets to tables. This table is deprecated and
 * is only used for backward compatibility.
 */

HIDDEN const struct charset chartables_charset_table[] = {
    { "us-ascii", chartables_us_ascii },        /* US-ASCII must be charset number 0 */
    { "utf-8", 0 }, /* handled directly */
    /* All remaining legacy charsets are handled by ICU */
    { "utf-7", 0 }, 
    { "iso-8859-1", 0 },
    { "iso-8859-2", 0 },
    { "iso-8859-3", 0 },
    { "iso-8859-4", 0 },
    { "iso-8859-5", 0 },
    { "iso-8859-6", 0 },
    { "iso-8859-7", 0 },
    { "iso-8859-8", 0 },
    { "iso-8859-9", 0 },
    { "koi8-r", 0 },
    { "iso-2022-jp", 0 },
    { "iso-2022-kr", 0 },
    { "gb2312", 0 },
    { "big5", 0 },
    /* Compatibility names */
    { "unicode-1-1-utf-7", 0 }, 
    { "unicode-2-0-utf-7", 0 },
    { "x-unicode-2-0-utf-7", 0 },
    /* End Compatibility Names */
    { "iso-8859-15", 0 },
    { "windows-1252", 0 },
    { "windows-1256", 0 },
    { "windows-1250", 0 },
    { "windows-1251", 0 },
    { "windows-1255", 0 },
    { "iso-8859-10", 0 },
    { "iso-8859-11", 0 },
    { "iso-8859-13", 0 },
    { "iso-8859-14", 0 },
    { "iso-8859-16", 0 },
    { "windows-1254", 0 },
    { "windows-1258", 0 },
    { "windows-874", 0 },
    { "imap-utf-7", 0 }, 
    { "windows-850", 0 },
    { "windows-31j", 0 },
    { "windows-936", 0 },
    { "windows-1257", 0 },
    { "koi8-u", 0 },

    /* New character sets should only be added to end so that
     * cache files stay with valid information */
};

HIDDEN const struct charset_alias charset_aliases[] = {
EOF

    my %aliases;
    if ($aliasfile and -f $aliasfile) {
        open(FH, "<$aliasfile") || die "can't read alias file $aliasfile";
        while (<FH>) {
            next if m/^#/;
            next unless m/(\S+)\s+(\S+)/;
            $aliases{$1} = $2;
        }
        close(FH);
    }

    foreach my $alias (sort keys %aliases) {
        print OUTPUT qq[    { "$alias", "$aliases{$alias}" },\n];
    }

    print OUTPUT <<EOF;
    { 0, 0 }
};

HIDDEN const int chartables_num_charsets = (sizeof(chartables_charset_table)/sizeof(*chartables_charset_table));
EOF
}

# calculate the sha1 of a file
sub getsha1 {
    my $file = shift;
    my $fh = IO::File->new($file, 'r') || return "<none>";
    if (eval { require "Digest/SHA1.pm" }) {
        my $digest = Digest::SHA1->new();
        $digest->addfile($fh);
        return $digest->hexdigest();
    }
    else {
        return "(install Digest::SHA1 for checksums)";
    }
}

__END__
