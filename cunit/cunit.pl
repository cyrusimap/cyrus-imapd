#!/usr/bin/env perl
#
# Build time front end for CUnit
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
use Cwd;
use File::Basename;
use File::Compare;

my $unitdir = dirname($0);
my $project;
my $DEFAULT_PROJECT = "default.cunit";
my @suites;
my @libraries;
my $here = getcwd();
my $verbose = 0;

#
# Emit a message if we're in verbose mode
# Args: void
# Returns: void
#
sub vmsg(@)
{
    print STDERR "## ". join(' ', @_) . "\n" if ($verbose);
}

#
# Given an absolute path, construct and return the simplest possible
# absolute path that points to the same file, in particular by flattening
# ".." components.  Similar to the libc realpath() function but without
# the behaviour of looking up symlinks.
# Args: absolute pathname
# Returns: absolute pathname
#
sub path_sanitise($)
{
    my ($path) = @_;
    my @comps;

    die "$path: not an absolute path"
        unless ($path =~ m/^\//);

    foreach my $comp (split('/', $path))
    {
        if ($comp eq "." || $comp eq "")
        {
            next;
        }
        elsif ($comp eq "..")
        {
            # Note: will silently fail if we try to pop more
            # components than we've added, which is exactly
            # the right behaviour for trying to walk past
            # the root directory with ".."s.
            pop(@comps);
        }
        else
        {
            push(@comps, $comp);
        }
    }
    return "/" . join("/",@comps);
}

#
# Given a (sanitised) absolute path, calculate and return a path
# relative to the given directory.
# Args: absolute pathname, base directory
# Returns: relative pathname
#
sub path_relativise($$)
{
    my ($path, $base) = @_;
    my @pathcomps;
    my @basecomps;

    die "$path: not an absolute path"
        unless ($path =~ m/^\//);

    @pathcomps = split("/", $path);
    @basecomps = split("/", $base);

    # Remove the components of the common
    # ancestor of both paths
    while (defined $pathcomps[0] &&
           defined $basecomps[0] &&
           $pathcomps[0] eq $basecomps[0])
    {
        shift(@pathcomps);
        shift(@basecomps);
    }

    # Prepend enough ".."s to the path
    # to reach the common ancestor
    while (defined $basecomps[0])
    {
        shift(@basecomps);
        unshift(@pathcomps, "..");
    }

    return join("/", @pathcomps);
}

#
# Return the initial common subset of two sanitised paths
# Args: absolute path, absolute path
# Returns: absolute path
#
sub path_common($$)
{
    my ($path1, $path2) = @_;
    my @path1comps;
    my @path2comps;
    my @common;

    die "$path1: not an absolute path"
        unless ($path1 =~ m/^\//);
    die "$path2: not an absolute path"
        unless ($path2 =~ m/^\//);

    @path1comps = split("/", $path1);
    @path2comps = split("/", $path2);

    # Remove the components of the common
    # ancestor of both paths
    while (defined $path1comps[0] &&
           defined $path2comps[0] &&
           $path1comps[0] eq $path2comps[0])
    {
        push(@common, $path1comps[0]);
        shift(@path1comps);
        shift(@path2comps);
    }

    return join("/", @common);
}

#
# Given either a relative or absolute path,
# calculate and return both.
# Args: pathname, directory to be relative to
# Returns: absolute pathname, relative pathname
#
sub path_absrel($$)
{
    my ($path, $basedir) = @_;
    my ($abspath, $relpath);

    if ($path =~ m/^\//)
    {
        # Given an absolute path
        $abspath = path_sanitise($path);
        # Calculate the relative path from the absolute path.
        $relpath = path_relativise($abspath, $basedir);
    }
    else
    {
        # Given a relative path
        $relpath = $path;
        # Calculate the absolute path
        $abspath = path_sanitise("$basedir/$relpath");
    }
    return ($abspath, $relpath);
}

#
# Given a pathname of the C source file of a suite, return
# the name by which the suite will be known to CUnit.
# Args: absolute pathname
# Returns: name
#
sub suite_path_to_name($)
{
    my ($path) = @_;

    # Generate a path from the "top" directory down to this
    # C source file.  The "top" directory should be something
    # like @top_srcdir@ in autoconf speak, but we have to
    # infer it from the location of the project file.
    my ($projdir, $whatever) = path_absrel($project, $here);
    my $topdir = path_common($path, $projdir);
    vmsg("inferred top_srcdir is \"$topdir\"");
    my $name = path_relativise($path, $topdir);

    $name =~ s/\.(testc|c)$//;
    $name =~ s/\/test_?/\//g;
    $name =~ s/_?test\//\//g;
    $name =~ s/\/+/\//g;
    $name =~ s/^\/+/\//;
    return $name;
}

#
# Given a pathname (relative or absolute, doesn't matter)
# of the C source file of a suite, return the relative
# path of the wrapper C source file.  This is always in
# the basedir.
# Args: pathname
# Returns: pathname
#
sub suite_path_to_wrapper($)
{
    my ($path) = @_;
    return $path . "-cunit.c";
}

#
# Given a pathname (relative or absolute, doesn't matter)
# of the C source file of a suite, return the relative
# path of the object file.  This is always in the basedir.
# Args: pathname
# Returns: pathname
#
sub suite_path_to_object($)
{
    my ($path) = @_;
    my $obj = basename($path);
    $obj =~ s/^/.cunit-/;
    $obj =~ s/\.c$/.o/;
    return $obj;
}

#
# Given a suite name return the name of a C variable which will
# be used to name the CU_SuiteInfo object.  Only needed because
# we allow test names to contain characters which are not legal
# in C symbols, notably '/'.
# Args: string name
# Returns: string symbol name
#
sub suite_name_to_var($)
{
    my ($name) = @_;

    $name =~ s/\W/_/g;
    $name =~ s/_+/_/g;
    $name = "__cunit_suite_" . $name;
    return $name;
}


#
# Create a new suite hash.
#
# Note that we maintain the basedirectory and relative path
# separately instead of taking the easy route of smooshing
# them together.  This allows us to handle the case where
# the C source file for a suite is in a subdirectory relative
# to the Makefile which is invoking us e.g. test/splunk.c
# rather than test_splunk.c, without stuffing up and putting
# the wrapper, object file, and archive in places where we
# won't be able to find them again later.
#
# Args: relative path, directory the path is relative to.
# Returns: ref to new suite hash
#
sub suite_new($$)
{
    my ($relpath, $basedir) = @_;

    # recalculate relpath to ensure canonical value
    my ($abspath, $whatever) = path_absrel($relpath, $basedir);
    $relpath = path_relativise($abspath, $basedir);

    my $suite =
    {
        basedir => $basedir,
        relpath => $relpath,
        abspath => $abspath,
        name => suite_path_to_name($abspath),
        wrap => suite_path_to_wrapper($relpath),
        object => suite_path_to_object($relpath),
        setupfn => undef,
        teardownfn => undef,
        params => [],
        tests => []
    };
    $suite->{suitevar} = suite_name_to_var($suite->{name});
    return $suite;
}

#
# Compare two suite hashes; suitable for use as a sort function.
# Args: ref to suite hash, ref to suite hash
# Returns: 0 if the same, <0 or >0 if not the same.
#
sub suite_cmp($$)
{
    my ($s1, $s2) = @_;
    return ($s1->{abspath} cmp $s2->{abspath});
}

#
# Return the linker argument for a suite hash, adjusted
# to be relative to the current working directory if
# appropriate.
# Args: ref to suite hash
# Returns: string linker argument
#
sub suite_get_linkable($)
{
    my ($suite) = @_;
    return path_relativise($suite->{basedir} . "/" . $suite->{object}, $here);
}

# Any of these (case insensitive) names can be used as the setup function
my %setup_names = (
    'setup' => 1,       # standard name from Kent Beck's original paper
    'set_up' => 1,      # standard, C style with underscore
    'init' => 1,        # allowed in older versions of cunit.pl
    'before' => 1,      # like jUnit's @Before annotation
);
# Any of these (case insensitive) names can be used as the teardown function
my %teardown_names = (
    'teardown' => 1,    # standard name from Kent Beck's original paper
    'tear_down' => 1,   # standard, C style with underscore
    'cleanup' => 1,     # allowed in older versions of cunit.pl
    'after' => 1,       # like jUnit's @After annotation
);

#
# Helper for suite_scan_for_tests
#
sub suite_found_function
{
    my ($suite, $rtype, $fn) = @_;

    if (defined $teardown_names{lc($fn)} && (!defined($rtype) || $rtype eq 'int'))
    {
        vmsg("Found teardown function");
        die "$suite->{abspath}: Too many teardown functions: " .
            "both \"$fn\" and \"$suite->{teardownfn}\" found"
            if defined($suite->{teardownfn});
        $suite->{teardownfn} = $fn;
    }
    elsif (defined $setup_names{lc($fn)} && (!defined($rtype) || $rtype eq 'int'))
    {
        vmsg("Found setup function");
        die "$suite->{abspath}: too many setup functions: both " .
            "\"$fn\" and \"$suite->{setupfn}\" found"
            if defined($suite->{setupfn});
        $suite->{setupfn} = $fn;
    }
    else
    {
        my ($name) = ($fn =~ m/^test_*(\w+)/);
        if (defined $name && (!defined($rtype) || $rtype eq 'void'))
        {
            vmsg("Found test function \"$fn\" -> name \"$name\"");
            push(@{$suite->{tests}},
                    {
                        name => $name,
                        func => $fn
                    });
        }
    }
}

#
# Helper for suite_scan_for_tests
#
sub suite_found_param
{
    my ($suite, $param) = @_;

    die "$suite->{abspath}: parameter \"$param\" declared " .
        "more than once"
        if grep { $_ eq $param } @{$suite->{params}};
    vmsg("Found parameter \"$param\"");

    # Note: we preserve the order of discovery in the
    # source file to provide a predictable order of
    # walking the parameter space at runtime.
    push (@{$suite->{params}}, $param);
}

#
# Scan the C source file of the given suite for function
# definitions of one of the signatures:
#
# [static] void test_WHATEVER(void)
#       we map this to a CUnit test called "WHATEVER"
#
# [static] void init(void)
#       we use this as the suite's initialisation function
#
# [static] void cleanup(void)
#       we use this as the suite's cleanup function
#
# The names of any such functions found are added to the
# suite hash, using {setupfn}, {teardownfn} and {tests}.
#
# Also scan for variable declarations of the form
#
# [static] char * foo = CUNIT_PARAM("stringliteral");
#
# and make them a parameter for the containing test suite.
#
# Args: ref to suite hash
# Returns: number of tests found
#
sub suite_scan_for_tests($)
{
    my ($suite) = @_;
    my $state = 0;
    my $fn;
    my $rtype;

    open FH,'<',$suite->{abspath}
        or die "Can't open $suite->{abspath} for reading: $!";
    while (<FH>)
    {
        chomp;

        if ($state == 0)
        {
            # Detect definitions of functions with the signature
            # void func(void), static void func(void), int func(void),
            # and static int func(void).
            ($rtype, $fn) = m/^(?:static\s+)(int|void)\s+(\w+)\s*\(\s*void\s*\)\s*$/;
            if (defined $fn)
            {
                suite_found_function($suite, $rtype, $fn);
                next;
            }

            ($fn) = m/^(\w+)\s*\(\s*void\s*\)\s*$/;
            if (defined $fn)
            {
                # old fashioned function declarations with no return type
                suite_found_function($suite, undef, $fn);
                next;
            }

            ($rtype) = m/^(?:static\s+)(int|void)\s*$/;
            if (defined $rtype)
            {
                $state = 1;
                next;
            }

            my ($param) = m/^(?:static\s+)char\s*\*\s*(\w+)\s*=\s*CUNIT_PARAM\s*\(/;
            if (defined $param)
            {
                suite_found_param($suite, $param);
                next;
            }

        }
        elsif ($state == 1)
        {
            # $rtype is left over from previous line
            ($fn) = m/^(\w+)\s*\(\s*void\s*\)\s*$/;
            if (defined $fn)
            {
                # split-line declaration of the form:
                # static void
                # test_foo(void)
                suite_found_function($suite, $rtype, $fn);
                next;
            }
            $state = 0;
        }
    }
    close FH;

    return scalar(@{$suite->{tests}});
}

#
# Return the subset of @suites located in or below the current directory.
# Args: void
# Returns: list refs to suite hash
#
sub suites_for_here()
{
    my $heresl = "$here/";
    my $l = length($heresl);
    return grep { substr($_->{abspath},0,$l) eq $heresl } @suites;
}

#
# Return the suite which corresponds to the given C source file.
# Args: C source file name
# Returns: ref to suite hash, or undef if not found
#
sub suite_find($)
{
    my ($path) = @_;

    foreach my $suite (@suites)
    {
        # canonicalise path before comparison
        my ($abs, $rel) = path_absrel($path, $suite->{basedir});

        return $suite
            if ($suite->{relpath} eq $rel);
    }
    return undef;
}

#
# Create a new library hash.
#
# Note that we maintain the basedirectory and relative path
# separately, like for suites, but only after partially
# parsing the argument to see if comprises or contains
# a path.
#
# Args: linker argument, directory which any path is relative to.
# Returns: ref to new library hash
#
sub library_new($$)
{
    my ($arg, $basedir) = @_;
    my $abspath;
    my $relpath;

    if ($arg =~ m/\.[oa]$/)
    {
        ($abspath, $relpath) = path_absrel($arg, $basedir);
    }
    elsif (my ($dir) = ($arg =~ m/^-L(.+)$/))
    {
        ($abspath, $relpath) = path_absrel($dir, $basedir);
    }
    elsif (!($arg =~ m/^-[lBW]/))
    {
        die "Don't know what to do with library \"$arg\"";
    }

    my $lib =
    {
        arg => $arg,
        basedir => $basedir,
        relpath => $relpath,    # might be undef
        abspath => $abspath,    # might be undef
    };
    return $lib;
}

#
# Compare two library hashes; suitable for use as a sort function.
# Args: ref to library hash, ref to library hash
# Returns: 0 if the same, <0 or >0 if not the same.
#
sub library_cmp($$)
{
    my ($l1, $l2) = @_;
    return ($l1->{basedir} cmp $l2->{basedir} ||
            $l1->{arg} cmp $l2->{arg});
}

#
# Return the linker argument for a library hash, adjusted
# to be relative to the current working directory if
# appropriate.
# Args: ref to library hash
# Returns: string linker argument
#
sub library_get_linkable($)
{
    my ($lib) = @_;
    my $arg = $lib->{arg};

    if ($arg =~ m/\.[oa]$/)
    {
        my ($abspath, $relpath) = path_absrel($arg, $lib->{basedir});
        $arg = path_relativise($abspath, $here);
    }
    elsif (my ($dir) = ($arg =~ m/^-L(.+)$/))
    {
        my ($abspath, $relpath) = path_absrel($dir, $lib->{basedir});
        $arg = "-L" . path_relativise($abspath, $here);
    }
    return $arg;
}

#
# Atomic rewrite: atomic update of file contents.
#
# We use the standard trick for POSIX filesystems of writing all
# the data to a new file in the same directory, then renaming
# (relying on the atomicity of the rename() system call).  This
# ensures that no process ever sees a partially updated version
# of the file, without the use of POSIX file locking.
#
# The atomic_rewrite_begin() call just returns a new filename to
# write to.  Call this first, then open the returned filename
# and write to it, then call atomic_rewrite_end() with your
# original filename.
#
# Note: this relies on the PIDs being unique to avoid a race
# between two writers, which is true on local filesystems.  If
# we were doing this properly we would use one of the library
# routines for generating a temporary filename and opening it
# atomically, then return a ref to a filehandle.
#
# Args: filename
# Returns: temporary filename to actually write to.
#
sub atomic_rewrite_begin($)
{
    my ($real) = @_;
    return "$real.$$.TMP";
}

#
# The second half of the atomic rewite; performs the comparison
# of file contents and the rename.
# Args: filename (the original one, not the temporary file)
# Returns: 1 if the file was changed, 0 if not.
#
sub atomic_rewrite_end($)
{
    my ($real) = @_;
    my $tmp = "$real.$$.TMP";
    my $different = 1;

    if ( -f $real )
    {
        $different = compare($real, $tmp);
    }
    if ($different == 1)
    {
        rename($tmp, $real)
            or die "Cannot rename $tmp to $real: $!";
        vmsg("rewrote $real");
        return 1;
    }
    else
    {
        unlink($tmp)
            or die "Cannot remove $tmp: $!";
        return 0;
    }
}

#
# Generate a C file which is used to wrap the C source file containing
# a suite.  The wrapper #includes the original C code and defines
# CUnit data structures which describe the suite and all it's tests.
# Uses atomic rewrite.
# Args: ref to suite hash
# Returns: void
#
sub suite_generate_wrap($)
{
    my ($suite) = @_;
    my $file = atomic_rewrite_begin($suite->{wrap});
    my $cfile = $suite->{abspath};

    open WRAP,'>',$file
        or die "Cannot open $file for writing: $!";
    print WRAP "/* Automatically generated by cunit.pl, do not edit */\n";
    print WRAP "#include \"$suite->{relpath}\"\n";
    print WRAP "#ifdef HAVE_CONFIG_H\n";
    print WRAP "#include <config.h>\n";
    print WRAP "#endif\n";

    if (scalar @{$suite->{params}})
    {
        print WRAP "static struct cunit_param params[] = {\n";
        map
        {
            print WRAP "__CUNIT_DECLARE_PARAM($_),\n";
        } @{$suite->{params}};
        print WRAP "__CUNIT_LAST_PARAM };\n";
    }

    my $setupfn = $suite->{setupfn};
    my $teardownfn = $suite->{teardownfn};

    foreach my $test (@{$suite->{tests}})
    {
        my $fn = $test->{func};
        print WRAP "static void __cunit_$fn(void)\n";
        print WRAP "{\n";

        print WRAP "__cunit_params_begin(params);\ndo {\n"
            if (scalar @{$suite->{params}});

        print WRAP "     CU_syslogMatchReset();\n";
        print WRAP "    if (__cunit_wrap_fixture(" .
                   "\"$cfile:$setupfn\", $setupfn)) " .
                   "CU_FAIL_FATAL(\"$setupfn failed\");\n"
            if defined $setupfn;
        print WRAP "    __cunit_wrap_test(\"$cfile:$fn\", $fn);\n";
        print WRAP "    if (__cunit_wrap_fixture(" .
                   "\"$cfile:$teardownfn\", $teardownfn)) " .
                   "CU_FAIL_FATAL(\"$teardownfn failed\");\n"
            if defined $teardownfn;
        print WRAP "} while (__cunit_params_next(params));\n__cunit_params_end();\n"
            if (scalar @{$suite->{params}});
        print WRAP "}\n";
    }

    print WRAP "static CU_TestInfo _tests[] = {\n";
    foreach my $test (@{$suite->{tests}})
    {
        print WRAP "    { \"$test->{name}\", __cunit_$test->{func} },\n";
    }
    print WRAP "    CU_TEST_INFO_NULL\n};\n";

    print WRAP "#ifdef HAVE_CU_SETUPFUNC\n";

    print WRAP "const CU_SuiteInfo $suite->{suitevar} = {" .
               "\"$suite->{name}\", NULL, NULL, NULL, NULL, _tests};\n";

    print WRAP "#else\n";

    print WRAP "const CU_SuiteInfo $suite->{suitevar} = {" .
               "\"$suite->{name}\", NULL, NULL, _tests};\n";

    print WRAP "#endif\n";

    close WRAP;

    atomic_rewrite_end($suite->{wrap});
}

#
# Load the $project file into the arrays @suites and @libraries.
# Args: void
# Returns: void
#
sub project_load()
{
    open PROJ,'<',$project
        or return;      # TODO: should be silent on ENOENT only

    # TODO: should check file version header

    while (<PROJ>)
    {
        chomp;
        next if (m/^#/);    # skip comments
        my @a = split;

        if ($a[0] eq 'suite')
        {
            die "Invalid format"
                unless scalar(@a) == 3;
            push(@suites, suite_new($a[1], $a[2]));
        }
        elsif ($a[0] eq 'library')
        {
            die "Invalid format"
                unless scalar(@a) == 3;
            push(@libraries, library_new($a[1], $a[2]));
        }
    }
    close PROJ;

    vmsg("loaded project $project");
}

#
# Add a suite to @suites, if it's not already present.
# Args: ref to a suite hash
# Returns: void
#
sub project_add_suite($)
{
    my ($suite) = @_;

    return if grep { !suite_cmp($_,$suite) } @suites;
    #
    # Note: appending is an important semantic.  It ensures
    # that the order of suites in the CUnit run matches the
    # order in which test source is specified, in SUBDIRS
    # in the top-level Makefile and then in TESTSOURCES
    # in each Makefile below that.
    #
    vmsg("adding suite $suite->{relpath} $suite->{basedir}");
    push(@suites, $suite);
}

#
# Add a library to the @libraries if it's not already present.
# Args: library string
# Returns: void
#
sub project_add_library($)
{
    my ($lib) = @_;

    @libraries = grep { library_cmp($_, $lib) } @libraries;
    vmsg("adding library $lib->{arg} $lib->{basedir}");
    push(@libraries, $lib);
}

#
# Save the @suites and @libraries arrays to the $project file
# Uses atomic rewrite.
# Args: void
# Returns: void
#
sub project_save()
{
    my $file = atomic_rewrite_begin($project);

    open PROJ,'>',$file
        or die "Failed to open $file for writing: $!";

    print PROJ "#CUnitProject-1.0\n";

    foreach my $suite (@suites)
    {
        print PROJ "suite $suite->{relpath} $suite->{basedir}\n";
    }
    foreach my $lib (@libraries)
    {
        print PROJ "library $lib->{arg} $lib->{basedir}\n";
    }
    close PROJ;

    atomic_rewrite_end($project);
}

#
# Add the named test sources (which are C source files) to the
# project, and rewrite the project file.  Re-adding is deliberately
# a harmless no-op; in particular the project file is not written
# if it's contents would not change.
#
sub add_sources(@)
{
    my (@args) = @_;

    project_load();

    foreach my $path (@args)
    {
        die "$path: not a C source file"
            unless (-f $path && $path =~ m/\.(test)?(c|C|cc|cxx|c\+\+)$/);
        project_add_suite(suite_new($path, $here));
    }

    project_save();
}

#
# Add the named libraries (which may be object files, lib.a archives,
# or -llibrary -Ldirectory -Bfoo -Wl,-foo ldflags, to the project,
# and rewrite the project file.  Re-adding is deliberately a harmless
# no-op; in particular the project file is not written if it's contents
# would not change.
#
sub add_libraries(@)
{
    my (@args) = @_;

    project_load();

    foreach my $arg (@args)
    {
        project_add_library(library_new($arg, $here));
    }

    project_save();
}

#
# Generate a wrapper C source file for each of the suites
# specified by their C source files on the commandline.
#
sub generate_wrapper(@)
{
    my @args = @_;
    my $nfails = 0;

    project_load();

    foreach my $a (@args)
    {
        my $suite = suite_find($a);
        if (!defined $suite)
        {
            print STDERR "$a: unknown suite, did you use --add-sources?\n";
            $nfails++;
            next;
        }
        my $ntests = suite_scan_for_tests($suite);
        if ($ntests == 0)
        {
            vmsg("No tests in $suite->{relpath}");
            if ( -f $suite->{wrap})
            {
                vmsg("Removing stale $suite->{wrap}");
                unlink($suite->wrap)
                    or die "Cannot unlink $suite->{wrap}: $!";
            }
            next;
        }
        suite_generate_wrap($suite);
    }

    exit 1
        if ($nfails > 0);
}

#
# Emit to the MAKE filehandle, a makefile fragment which contains
# variable definitions which list the objects/libraries/linkflags
# for the final link step, and which list the objects/libraries to
# depend on for the final link step, assuming we want all the tests
# in all the suites mentioned in the project.  We rely on the calling
# Makefile to define the actual link rule.
#
# Note that the order and uniqueness of @linkables matters
# but not in obvious ways, and may interact in interesting
# ways with weird linker switches.  We try to optimise by
# listing each individual linkable exactly once, so it's
# only searched once.  This will break if the libraries
# have circular dependencies, so don't do stupid things
# like that!  To preserve link order semantics, the *last*
# instance of each library seen is used.
#
# We should probably disable this optimisation if fancy
# order-dependent options like -Bstatic were given.  Also,
# we don't handle GNU linker groups very well either.
#
# Args: void
# Returns: void
#
sub emit_final_makefile_bits()
{
    my ($makefile) = @_;
    my %seen;
    my @all_linkables;
    my @linkables;
    my @deplibs;

    push(@all_linkables, map { suite_get_linkable($_) } @suites );
    push(@all_linkables, map { library_get_linkable($_) } @libraries );
    map { $seen{$_}++ } @all_linkables;
    foreach my $arg (@all_linkables)
    {
        push (@linkables, $arg)
            if ($seen{$arg} == 1);
        $seen{$arg}--;
    }

    @deplibs = grep { m/\.[oa]$/ } @linkables;

    print MAKE "CUNIT_OBJECTS = " . join(' ', @linkables) . "\n";
    print MAKE "CUNIT_DEPLIBS = " . join(' ', @deplibs) . "\n";
}

#
# Emit to the MAKE filehandle, a makefile fragment which contains
# rules to build wrappers around each test source in this directory
# or it's descendents, and to build object files from those wrappers.
#
# Args: name of output makefile
# Returns: void
#
sub emit_partial_makefile_bits($)
{
    my ($makefile) = @_;
    my $cunit;

    $cunit = "$0";
    $cunit .= " --project $project"
        unless ($project eq $DEFAULT_PROJECT);

    print MAKE "CUNIT_TEST_WRAPS =";
    foreach my $suite (suites_for_here())
    {
        print MAKE " $suite->{wrap}";
    }
    print MAKE "\n";

    print MAKE "CUNIT_TEST_OBJS =";
    foreach my $suite (suites_for_here())
    {
        print MAKE " $suite->{object}";
    }
    print MAKE "\n";

    foreach my $suite (suites_for_here())
    {
        print MAKE "$suite->{object}: $suite->{wrap} $suite->{relpath}\n";
    }
    print MAKE "\n";

    foreach my $suite (suites_for_here())
    {
        print MAKE "$suite->{wrap}: $suite->{relpath}\n";
        print MAKE "\t$cunit --generate-wrapper \$<\n";
    }
    print MAKE "\n";

    print MAKE "clean::\n";
    print MAKE "\t\$(RM) -f \$(CUNIT_TEST_WRAPS) \$(CUNIT_TEST_OBJS) $makefile\n";
    print MAKE "\n";
}

#
# Generate a makefile fragment which contains rules to build
# wrappers around each test source in this directory or it's
# descendents, and to build object files from those wrappers.
#
sub generate_partial_makefile(@)
{
    my ($makefile) = @_;

    project_load();

    my $file = atomic_rewrite_begin($makefile);

    open MAKE,'>',$file
        or die "Cannot open $file for writing: $!";

    print MAKE "# Automatically generated by cunit.pl, do not edit\n";
    print MAKE "\n";

    emit_partial_makefile_bits($makefile);

    print MAKE "check:: \$(CUNIT_TEST_OBJS)\n";
    print MAKE "\n";

    atomic_rewrite_end($makefile);
}

#
# Generate a makefile fragment which contains variable definitions
# which list the objects/libraries/linkflags for the final link
# step, and which list the objects/libraries to depend on for
# the final link step, assuming we want all the tests in all the
# suites mentioned in the project.  We rely on the calling Makefile
# to define the actual link rule.
#
sub generate_final_makefile(@)
{
    my ($makefile) = @_;

    project_load();

    my $file = atomic_rewrite_begin($makefile);

    open MAKE,'>',$file
        or die "Cannot open $file for writing: $!";

    print MAKE "# Automatically generated by cunit.pl, do not edit\n";
    print MAKE "\n";

    emit_final_makefile_bits();

    atomic_rewrite_end($makefile);
}

#
# Generate a combined makefile fragment which does both the
# partial and final stages.
#
sub generate_makefile(@)
{
    my ($makefile) = @_;

    project_load();

    my $file = atomic_rewrite_begin($makefile);

    open MAKE,'>',$file
        or die "Cannot open $file for writing: $!";

    print MAKE "# Automatically generated by cunit.pl, do not edit\n";
    print MAKE "\n";

    emit_partial_makefile_bits($makefile);
    emit_final_makefile_bits();

    atomic_rewrite_end($makefile);
}


#
# Generate a file containing a C function register_cunit_suites()
# which registers all the CUnit suites in the project.
#
sub generate_register_function(@)
{
    my ($cfile) = @_;

    project_load();

    my $file = atomic_rewrite_begin($cfile);

    open CFILE,'>',$file
        or die "Cannot open $file for writing: $!";

    print CFILE "/* Automatically generated by cunit.pl, do not edit */\n";

    foreach my $suite (@suites)
    {
        print CFILE "extern const CU_SuiteInfo $suite->{suitevar};\n";
    }

    print CFILE "void register_cunit_suites(void)\n";
    print CFILE "{\n";
    print CFILE "    CU_SuiteInfo ss[2] = { CU_SUITE_INFO_NULL, CU_SUITE_INFO_NULL };\n";
    foreach my $suite (@suites)
    {
        print CFILE "    ss[0] = $suite->{suitevar};\n";
        print CFILE "    CU_register_suites(ss);\n";
    }
    print CFILE "}\n";

    atomic_rewrite_end($cfile);
}

#
# Parse arguments
#

sub usage()
{
    print STDERR "Usage: cunit.pl [flags] --add-sources file.c ...\n";
    print STDERR "Usage: cunit.pl [flags] --add-libraries [-llib|-Ldir] ...\n";
    print STDERR "       cunit.pl [flags] --generate-partial-makefile foo.mk\n";
    print STDERR "       cunit.pl [flags] --generate-wrapper testfoo.c\n";
    print STDERR "       cunit.pl [flags] --generate-final-makefile foo.mk\n";
    print STDERR "       cunit.pl [flags] --generate-makefile foo.mk\n";
    print STDERR "       cunit.pl [flags] --emit-register-function foo.c\n";
    print STDERR "\n";
    print STDERR "flags include:\n";
    print STDERR "    --project PROJ, -p PROJ       specify the project file (default is \"$DEFAULT_PROJECT\")\n";
    print STDERR "    --verbose, -v                 be more verbose\n";
    exit 1;
}

my $modefn = undef;
my @args;
my $want_args = 0;
while (my $a = shift)
{
    if ($a eq '--project' || $a eq '-p')
    {
        $project = shift;
        usage() unless defined $project;
    }
    elsif ($a eq '--add-sources' || $a eq '-a')
    {
        $modefn = \&add_sources;
        $want_args = 1;
    }
    elsif ($a eq '--add-libraries' || $a eq '-A')
    {
        $modefn = \&add_libraries;
        $want_args = 2;
    }
    elsif ($a eq '--generate-partial-makefile' || $a eq '-p')
    {
        $modefn = \&generate_partial_makefile;
        my $makefile = shift;
        usage() unless defined $makefile;
        push(@args, $makefile);
    }
    elsif ($a eq '--generate-final-makefile' || $a eq '-f')
    {
        $modefn = \&generate_final_makefile;
        my $makefile = shift;
        usage() unless defined $makefile;
        push(@args, $makefile);
    }
    elsif ($a eq '--generate-makefile' || $a eq '-m')
    {
        $modefn = \&generate_makefile;
        my $makefile = shift;
        usage() unless defined $makefile;
        push(@args, $makefile);
    }
    elsif ($a eq '--generate-wrapper' || $a eq '-w')
    {
        $modefn = \&generate_wrapper;
        $want_args = 1;
    }
    elsif ($a eq '--generate-register-function' || $a eq '-r')
    {
        $modefn = \&generate_register_function;
        my $cfile = shift;
        usage() unless defined $cfile;
        push(@args, $cfile);
    }
    elsif ($a eq '--verbose' || $a eq '-v')
    {
        $verbose++;
    }
    elsif ($a =~ /^-[lLBW]/ && $want_args == 2)
    {
        push(@args, $a);
    }
    elsif ($a =~ /^-/)
    {
        usage();
    }
    elsif ($want_args)
    {
        push(@args, $a);
    }
    else
    {
        usage();
    }
}

if (!defined $project)
{
    $project = $DEFAULT_PROJECT;
}
elsif ( -d $project)
{
    $project = "$project/$DEFAULT_PROJECT";
}

# Actually run the selected mode
usage() unless defined $modefn;
$modefn->(@args);

