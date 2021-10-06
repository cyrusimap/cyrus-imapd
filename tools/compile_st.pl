#!/usr/bin/env perl
#
# compile_st.pl - compile string table into .h and .c files
#
# Copyright (c) 1994-2010 Carnegie Mellon University.  All rights reserved.
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
#

use strict;
use warnings;
use File::Temp qw/ tempfile /;

my $c_flag = 0;
my $h_flag = 0;
my $infile;

sub usage()
{
    print STDERR "Usage: compile_st.pl -c input.st | gperf > output.c\n";
    print STDERR "       compile_st.pl -h input.st > output.h\n";
    exit 1;
}

while (my $a = shift)
{
    if ($a eq "-c")
    {
        $c_flag = 1;
    }
    elsif ($a eq "-h")
    {
        $h_flag = 1;
    }
    elsif ($a eq "--help")
    {
        usage();
    }
    elsif ($a =~ m/^-/)
    {
        usage();
    }
    else
    {
        usage()
            if defined $infile;
        $infile = $a;
    }
}

usage()
    unless defined $infile;

die "Please specify exactly one of -c or -h"
    unless ($c_flag + $h_flag == 1);

# variables containing the logical contents of the string table file
my @gperf_directives = (
    "includes",
    "compare-strncmp",
    "language=ANSI-C",
    "readonly-tables",
    "struct-type"
);
my $name;
my $unknown;
my $next_unknown = -1;
my $next_known = 0;
my @entries;
my $nliterals = 0;
my $nenums = 0;
my $type;

#
# Slurp the .st stringtab file into variables.
#

open ST,'<',$infile
    or die "Cannot open $infile for reading: $!";
while (<ST>)
{
    chomp;
    next if m/^\s*#/;       # skip comments
    next if m/^\s*$/;       # skip empty lines
    my @a = split;

    if ($a[0] eq "%ignore-case" && scalar(@a) == 1)
    {
        push(@gperf_directives, "ignore-case");
    }
    elsif ($a[0] =~ m/^%/)
    {
        die "Unrecognised gperf declaration \"$_\"";
    }
    elsif ($a[0] eq "table")
    {
        die "Wrong number of arguments for \"table\""
            unless scalar(@a) == 2;
        $name = $a[1];
    }
    elsif ($a[0] eq "ent")
    {
        my $enum;
        my $literal;
        my $string;
        my $value;

        ($enum) = ($a[1] =~ m/^([A-Za-z_][A-Za-z_0-9]*)$/);
        if (!defined $enum)
        {
            ($literal) = ($a[1] =~ m/^([0-9]+|0x[0-9a-fA-F]+)$/);
        }
        die "Bad syntax for \"ent\" at or near \"$_\""
            unless (defined $enum || defined $literal);

        if (defined $a[2])
        {
            ($string) = m/^\s*ent\s+\S+\s+"([^"]+)"\s*$/;
            die "Bad syntax for \"ent\" at or near \"$_\""
                unless defined $string;
        }

        if (!defined $string)
        {
            $value = $next_unknown;
            $next_unknown--;
            $unknown = $enum
                unless defined $unknown;
        }
        else
        {
            $value = $next_known;
            $next_known++;
        }

        push(@entries, {
            enum => $enum,
            literal => $literal,
            value => $value,
            string => $string
        });
        $nenums++ if defined $enum;
        $nliterals++ if defined $literal;
    }
    else
    {
        die "Unrecognised keyword at or near \"$_\"";
    }
}
close ST;

die "No table name defined in $infile"
    unless defined $name;
die "No string entries defined"
    unless scalar(@entries) > 0;
$unknown = "-1"
    unless defined $unknown;
$type = ($nenums ? "enum $name" : "int");

# Emit the C header file is requested
if ($h_flag)
{
    printf "/* Automatically generated by compile_st.pl, do not edit */\n";
    printf "#ifndef __STRING_TABLE_%s_H_\n", $name;
    printf "#define __STRING_TABLE_%s_H_ 1\n", $name;
    printf "\n";
    printf "#include <string.h>\n";
    printf "\n";

    if ($nenums)
    {
        printf "enum %s {\n", $name;
        foreach my $e (@entries)
        {
            next if !defined $e->{enum};
            printf "    %s", $e->{enum};
            printf "=%d", $e->{value}
                if defined $e->{value};
            printf ",\n"
        }
        printf "};\n";
    }

    printf "extern %s %s_from_string(const char *s);\n", $type, $name;
    printf "extern %s %s_from_string_len(const char *s, size_t len);\n", $type, $name;
    if (!$nliterals)
    {
        printf "extern const char *%s_to_string(%s v);\n", $name, $type;
    }

    printf "\n";
    printf "#endif /* __STRING_TABLE_%s_H_ */\n", $name;
}

# Emit the gperf source file if requested
if ($c_flag)
{
    my ($fh, $filename) = tempfile('compile_st_XXXXXX', TMPDIR => 1, SUFFIX => '.gperf');

    printf $fh "%%define lookup-function-name __%s_lookup\n", $name;
    foreach my $d (@gperf_directives)
    {
        printf $fh "%%%s\n", $d;
    }

    printf $fh "%%{\n";
    printf $fh "/* Automatically generated by compile_st.pl, do not edit */\n";
    printf $fh "#include \"%s.h\"\n", $name;
    printf $fh "%%}\n";

    printf $fh "struct %s_desc { const char *name; %s value; };\n", $name, $type;
    printf $fh "%%%%\n";

    foreach my $e (@entries)
    {
        next unless defined $e->{string};
        if (defined $e->{enum})
        {
            printf $fh "%s, %s\n", $e->{string}, $e->{enum};
        }
        elsif (defined $e->{literal})
        {
            printf $fh "%s, %s\n", $e->{string}, $e->{literal};
        }
    }

    printf $fh "%%%%\n";

    printf $fh "%s %s_from_string(const char *s)\n", $type, $name;
    printf $fh "{\n";
    printf $fh "    const struct %s_desc *d = __%s_lookup(s, strlen(s));\n", $name, $name;
    printf $fh "    return (d == NULL ? %s : d->value);\n", $unknown;
    printf $fh "}\n";
    printf $fh "\n";
    printf $fh "%s %s_from_string_len(const char *s, size_t len)\n", $type, $name;
    printf $fh "{\n";
    printf $fh "    const struct %s_desc *d = __%s_lookup(s, len);\n", $name, $name;
    printf $fh "    return (d == NULL ? %s : d->value);\n", $unknown;
    printf $fh "}\n";
    printf $fh "\n";
    if (!$nliterals)
    {
        printf $fh "const char *%s_to_string(%s v)\n", $name, $type;
        printf $fh "{\n";
        printf $fh "    static const char * const strs[] = {\n";
        foreach my $e (@entries)
        {
            next unless defined $e->{string};
            printf $fh "\t\"%s\", /* %s */\n", $e->{string}, $e->{enum};
        }
        printf $fh "    };\n";
        printf $fh "    return (v >= 0 && v < (int)(sizeof(strs)/sizeof(strs[0])) ? strs[v] : NULL);\n";
        printf $fh "}\n";
    }

    close $fh;

    my @cmd = ( 'gperf', $filename );
    open GPERF,'-|',@cmd
        or die "Couldn't run gperf";

    # Post-process to fix warnings due to missing
    # initializers in the wordlist.
    my $s = 0;
    while (<GPERF>)
    {
        chomp;

        next if m/^#line/;
        s/{""}/{"", 0}/g if ($s);
        $s = 1 if m/wordlist/;
        $s = 0 if ($s && m/};/);

        print "$_\n";
    }

    close GPERF;

    unlink($filename);
}

