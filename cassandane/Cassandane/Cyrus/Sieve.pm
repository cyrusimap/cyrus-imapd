#!/usr/bin/perl
#
#  Copyright (c) 2011 Opera Software Australia Pty. Ltd.  All rights
#  reserved.
#
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions
#  are met:
#
#  1. Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#
#  2. Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#
#  3. The name "Opera Software Australia" must not be used to
#     endorse or promote products derived from this software without
#     prior written permission. For permission or any legal
#     details, please contact
# 	Opera Software Australia Pty. Ltd.
# 	Level 50, 120 Collins St
# 	Melbourne 3000
# 	Victoria
# 	Australia
#
#  4. Redistributions of any form whatsoever must retain the following
#     acknowledgment:
#     "This product includes software developed by Opera Software
#     Australia Pty. Ltd."
#
#  OPERA SOFTWARE AUSTRALIA DISCLAIMS ALL WARRANTIES WITH REGARD TO
#  THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
#  AND FITNESS, IN NO EVENT SHALL OPERA SOFTWARE AUSTRALIA BE LIABLE
#  FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
#  WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
#  AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
#  OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#

use strict;
use warnings;
package Cassandane::Cyrus::Sieve;
use base qw(Cassandane::Cyrus::TestCase);
use File::Path qw(mkpath);
use IO::File;
use Cassandane::Util::Log;

sub new
{
    my $class = shift;
    return $class->SUPER::new({ deliver => 1 }, @_);
}

sub set_up
{
    my ($self) = @_;
    $self->SUPER::set_up();
}

sub tear_down
{
    my ($self) = @_;
    $self->SUPER::tear_down();
}

sub install_sieve_script
{
    my ($self, $script, %params) = @_;

    my $user = $params{username} || 'cassandane';
    my $uhash = substr($user, 0, 1);
    my $name = $params{name} || 'test1';
    my $basedir = $self->{instance}->{basedir};
    my $sieved = "$basedir/conf/sieve/$uhash/$user";

    xlog "Installing sieve script $name for user $user";

    mkpath $sieved
	or die "Cannot make path $sieved: $!";
    $self->assert(( -d $sieved ));

    open(FH, '>', "$sieved/$name.script")
	or die "Cannot open $sieved/$name.script for writing: $!";
    print FH $script;
    close(FH);

    $self->{instance}->run_command({ cyrus => 1 },
				   "sievec",
				   "$sieved/$name.script",
				   "$sieved/$name.bc");
    $self->assert(( -f "$sieved/$name.bc" ));

    symlink("$name.bc", "$sieved/defaultbc")
	or die "Cannot symlink testsieve.bc to $sieved/defaultbc";
    $self->assert(( -l "$sieved/defaultbc" ));

    xlog "Sieve script installed successfully";
}

sub compile_sieve_script
{
    my ($self, $name, $script) = @_;

    my $basedir = $self->{instance}->{basedir};

    xlog "Checking preconditions for compiling sieve script $name";

    $self->assert(( ! -f "$basedir/$name.script" ));
    $self->assert(( ! -f "$basedir/$name.bc" ));
    $self->assert(( ! -f "$basedir/$name.errors" ));

    open(FH, '>', "$basedir/$name.script")
	or die "Cannot open $basedir/$name.script for writing: $!";
    print FH $script;
    close(FH);

    xlog "Running sievec on script $name";
    my $result = 'success';
    eval
    {
	$self->{instance}->run_command(
	    {
		cyrus => 1,
		redirects => { stderr => "$basedir/$name.errors" },
	    },
	    "sievec", "$basedir/$name.script", "$basedir/$name.bc");
    };
    if ($@)
    {
	$result = $@;
	chomp $result;
	$result =~ s/.*exited with code.*/failure/;
    }

    # Read the errors file in @errors
    my @errors;
    if ( -f "$basedir/$name.errors" )
    {
	open FH, '<', "$basedir/$name.errors"
	    or die "Cannot open $basedir/$name.errors for reading: $!";
	@errors = readline(FH);
	close FH;
	if (get_verbose)
	{
	    xlog "sievec errors: ";
	    map { xlog $_ } @errors;
	}
    }

    if ($result eq 'success')
    {
	xlog "Checking that sievec wrote the output .bc file";
	$self->assert(( -f "$basedir/$name.bc" ));
	xlog "Checking that sievec didn't write anything to stderr";
	$self->assert_equals(0, scalar(@errors));
    }
    elsif ($result eq 'failure')
    {
	xlog "Checking that sievec didn't write the output .bc file";
	$self->assert(( ! -f "$basedir/$name.bc" ));
    }

    return ($result, @errors);
}

sub test_deliver
{
    my ($self) = @_;

    my $target = "INBOX.target";

    xlog "Install a sieve script filing all mail into a nonexistant folder";
    $self->install_sieve_script(<<EOF
require ["fileinto"];
fileinto "$target";
EOF
    );

    xlog "Deliver a message";
    my $msg1 = $self->{gen}->generate(subject => "Message 1");
    $self->{instance}->deliver($msg1);

    xlog "Actually create the target folder";
    my $imaptalk = $self->{store}->get_client();

    $imaptalk->create($target);
    $self->{store}->set_fetch_attributes('uid');

    xlog "Deliver another message";
    my $msg2 = $self->{gen}->generate(subject => "Message 2");
    $self->{instance}->deliver($msg2);
    $msg2->set_attribute(uid => 1);

    xlog "Check that only the 1st message made it to INBOX";
    $self->{store}->set_folder('INBOX');
    $self->check_messages({ 1 => $msg1 }, check_guid => 0);

    xlog "Check that only the 2nd message made it to the target";
    $self->{store}->set_folder($target);
    $self->check_messages({ 1 => $msg2 }, check_guid => 0);
}

sub test_badscript
{
    my ($self) = @_;

    xlog "Testing sieve script compile failures";
    my $res;
    my @errs;

    ($res, @errs) = $self->compile_sieve_script('badrequire',
	"require [\"nonesuch\"];\n");
    $self->assert_str_equals('failure', $res);
    $self->assert(grep m/Unsupported feature.*nonesuch/, @errs);

    ($res, @errs) = $self->compile_sieve_script('badreject1',
	"reject \"foo\"\n");
    $self->assert_str_equals('failure', $res);
    $self->assert(grep m/line 1: reject MUST be enabled/, @errs);

    ($res, @errs) = $self->compile_sieve_script('badreject2',
	"require [\"reject\"];\nreject\n");
    $self->assert_str_equals('failure', $res);
    $self->assert(grep m/line 3: syntax error.*expecting STRING/, @errs);

    ($res, @errs) = $self->compile_sieve_script('badreject3',
	"require [\"reject\"];\nreject 42\n");
    $self->assert_str_equals('failure', $res);
    $self->assert(grep m/line 2: syntax error.*expecting STRING/, @errs);

    # TODO: test UTF-8 verification of the string parameter

    ($res, @errs) = $self->compile_sieve_script('badfileinto1',
	"fileinto \"foo\"\n");
    $self->assert_str_equals('failure', $res);
    $self->assert(grep m/line 1: fileinto MUST be enabled/, @errs);

    ($res, @errs) = $self->compile_sieve_script('badfileinto2',
	"require [\"fileinto\"];\nfileinto\n");
    $self->assert_str_equals('failure', $res);
    $self->assert(grep m/line 3: syntax error.*expecting STRING/, @errs);

    ($res, @errs) = $self->compile_sieve_script('badfileinto3',
	"require [\"fileinto\"];\nfileinto 42\n");
    $self->assert_str_equals('failure', $res);
    $self->assert(grep m/line 2: syntax error.*expecting STRING/, @errs);

    ($res, @errs) = $self->compile_sieve_script('badfileinto4',
	"require [\"fileinto\"];\nfileinto :copy \"foo\"\n");
    $self->assert_str_equals('failure', $res);
    $self->assert(grep m/line 2: copy MUST be enabled/, @errs);

    ($res, @errs) = $self->compile_sieve_script('badfileinto5',
	"require [\"fileinto\",\"copy\"];\nfileinto \"foo\"\n");
    $self->assert_str_equals('failure', $res);
    $self->assert(grep m/line 3: syntax error.*expecting.*;/, @errs);

    ($res, @errs) = $self->compile_sieve_script('badfileinto6',
	"require [\"fileinto\",\"copy\"];\nfileinto :copy \"foo\"\n");
    $self->assert_str_equals('failure', $res);
    $self->assert(grep m/line 3: syntax error.*expecting.*;/, @errs);

    ($res, @errs) = $self->compile_sieve_script('goodfileinto7',
	"require [\"fileinto\",\"copy\"];\nfileinto \"foo\";\n");
    $self->assert_str_equals('success', $res);

    ($res, @errs) = $self->compile_sieve_script('goodfileinto8',
	"require [\"fileinto\",\"copy\"];\nfileinto :copy \"foo\";\n");
    $self->assert_str_equals('success', $res);

    # TODO: test UTF-8 verification of the string parameter
}

1;
