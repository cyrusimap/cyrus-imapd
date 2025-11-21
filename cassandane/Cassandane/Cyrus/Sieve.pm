#!/usr/bin/perl
#
#  Copyright (c) 2011-2017 FastMail Pty Ltd. All rights reserved.
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
#  3. The name "Fastmail Pty Ltd" must not be used to
#     endorse or promote products derived from this software without
#     prior written permission. For permission or any legal
#     details, please contact
#      FastMail Pty Ltd
#      PO Box 234
#      Collins St West 8007
#      Victoria
#      Australia
#
#  4. Redistributions of any form whatsoever must retain the following
#     acknowledgment:
#     "This product includes software developed by Fastmail Pty. Ltd."
#
#  FASTMAIL PTY LTD DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
#  INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY  AND FITNESS, IN NO
#  EVENT SHALL OPERA SOFTWARE AUSTRALIA BE LIABLE FOR ANY SPECIAL, INDIRECT
#  OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF
#  USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
#  TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE
#  OF THIS SOFTWARE.
#

package Cassandane::Cyrus::Sieve;
use Net::CalDAVTalk 0.12;
use strict;
use warnings;
use IO::File;
use version;
use utf8;
use File::Temp qw/tempfile/;
use DateTime;
use Date::Parse;

use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;
use Encode qw(decode);
use MIME::Base64 qw(encode_base64);
use Data::Dumper;

sub new
{
    my $class = shift;
    my $config = Cassandane::Config->default()->clone();

    my ($maj, $min) = Cassandane::Instance->get_version();
    if ($maj == 3 && $min == 0) {
        # need to explicitly add 'body' to sieve_extensions for 3.0
        $config->set(sieve_extensions =>
            "fileinto reject vacation vacation-seconds imap4flags notify " .
            "envelope relational regex subaddress copy date index " .
            "imap4flags mailbox mboxmetadata servermetadata variables " .
            "body");
    }
    elsif ($maj < 3) {
        # also for 2.5 (the earliest Cyrus that Cassandane can test)
        $config->set(sieve_extensions =>
            "fileinto reject vacation vacation-seconds imap4flags notify " .
            "envelope relational regex subaddress copy date index " .
            "imap4flags body");
    }
    $config->set(sievenotifier => 'mailto');
    $config->set(caldav_realm => 'Cassandane');
    $config->set(httpmodules => ['caldav', 'carddav', 'jmap']);
    $config->set(calendar_user_address_set => 'example.com');
    $config->set(httpallowcompress => 'no');
    $config->set(caldav_historical_age => -1);
    $config->set(icalendar_max_size => 100000);
    $config->set(virtdomains => 'no');
    $config->set(jmap_nonstandard_extensions => 'yes');
    $config->set(conversations => 'yes');

    my $self = $class->SUPER::new({
            config => $config,
            deliver => 1,
            jmap => 1,
            services => [ 'imap', 'sieve' ],
            adminstore => 1,
    }, @_);

    $self->needs('component', 'sieve');
    return $self;
}

sub set_up
{
    my ($self) = @_;
    $self->SUPER::set_up();
    if ($self->{jmap}) {
        $self->{jmap}->DefaultUsing([
            'urn:ietf:params:jmap:core',
            'urn:ietf:params:jmap:mail',
            'urn:ietf:params:jmap:calendars',
            'urn:ietf:params:jmap:principals',
            'urn:ietf:params:jmap:calendars:preferences',
            'https://cyrusimap.org/ns/jmap/calendars',
            'https://cyrusimap.org/ns/jmap/mail',
            'https://cyrusimap.org/ns/jmap/debug',
        ]);
    }
}

sub tear_down
{
    my ($self) = @_;
    $self->SUPER::tear_down();
}

sub read_errors
{
    my ($filename) = @_;

    my @errors;
    if ( -f $filename )
    {
        open FH, '<', $filename
            or die "Cannot open $filename for reading: $!";
        @errors = readline(FH);
        close FH;
        if (get_verbose)
        {
            xlog "errors: ";
            map { xlog $_ } @errors;
        }
        # Hack to remove spurious junk generated when
        # running coveraged code under ggcov-run
        @errors = grep { ! m/libggcov:/ && ! m/profiling:/ } @errors;
    }
    return @errors;
}

sub compile_sievec
{
    my ($self, $name, $script) = @_;

    my $basedir = $self->{instance}->{basedir};

    xlog $self, "Checking preconditions for compiling sieve script $name";

    $self->assert_not_file_test("$basedir/$name.script", '-f');
    $self->assert_not_file_test("$basedir/$name.bc", '-f');
    $self->assert_not_file_test("$basedir/$name.errors", '-f');

    open(FH, '>', "$basedir/$name.script")
        or die "Cannot open $basedir/$name.script for writing: $!";
    print FH $script;
    close(FH);

    xlog $self, "Running sievec on script $name";
    my $result = $self->{instance}->run_command(
            {
                cyrus => 1,
                redirects => { stderr => "$basedir/$name.errors" },
                handlers => {
                    exited_normally => sub { return 'success'; },
                    exited_abnormally => sub { return 'failure'; },
                },
            },
            "sievec", "$basedir/$name.script", "$basedir/$name.bc");

    # Read the errors file in @errors
    my (@errors) = read_errors("$basedir/$name.errors");

    if ($result eq 'success')
    {
        xlog $self, "Checking that sievec wrote the output .bc file";
        $self->assert_file_test("$basedir/$name.bc", '-f');
        xlog $self, "Checking that sievec didn't write anything to stderr";
        $self->assert_equals(0, scalar(@errors));
    }
    elsif ($result eq 'failure')
    {
        xlog $self, "Checking that sievec didn't write the output .bc file";
        $self->assert_not_file_test("$basedir/$name.bc", '-f');
    }

    return ($result, join("\n", @errors));
}

sub compile_timsieved
{
    my ($self, $name, $script) = @_;

    my $basedir = $self->{instance}->{basedir};
    my $bindir = $self->{instance}->{cyrus_destdir} .
                 $self->{instance}->{cyrus_prefix} . '/bin';
    my $srv = $self->{instance}->get_service('sieve');

    xlog $self, "Checking preconditions for compiling sieve script $name";

    $self->assert_not_file_test("$basedir/$name.script", '-f');
    $self->assert_not_file_test("$basedir/$name.errors", '-f');

    open(FH, '>', "$basedir/$name.script")
        or die "Cannot open $basedir/$name.script for writing: $!";
    print FH $script;
    close(FH);

    if (! -f "$basedir/sieve.passwd" )
    {
        open(FH, '>', "$basedir/sieve.passwd")
            or die "Cannot open $basedir/sieve.passwd for writing: $!";
        print FH "\ntestpw\n";
        close(FH);
    }

    xlog $self, "Running installsieve on script $name";
    my $result = $self->{instance}->run_command({
                redirects => {
                    # No cyrus => 1 as installsieve is a Perl
                    # script which doesn't need Valgrind and
                    # doesn't understand the Cyrus -C option
                    stdin => "$basedir/sieve.passwd",
                    stderr => "$basedir/$name.errors"
                },
                handlers => {
                    exited_normally => sub { return 'success'; },
                    exited_abnormally => sub { return 'failure'; },
                },
            },
            "$bindir/installsieve",
            "-i", "$basedir/$name.script",
            "-u", "cassandane",
            $srv->host() . ":" . $srv->port());

    # Read the errors file in @errors
    my (@errors) = read_errors("$basedir/$name.errors");

    if ($result eq 'success')
    {
        xlog $self, "Checking that installsieve didn't write anything to stderr";
        $self->assert_equals(0, scalar(@errors));
    }

    return ($result, join("\n", @errors));
}

sub compile_sieve_script
{
    my ($self, $name, $script) = @_;

    my $meth = 'compile_' . $self->{compile_method};
    return $self->$meth($name, $script);
}

sub badscript_common
{
    my ($self) = @_;

    my $res;
    my $errs;

    ($res, $errs) = $self->compile_sieve_script('badrequire',
        "require [\"nonesuch\"];\n");
    $self->assert_str_equals('failure', $res);
    $self->assert_matches(qr/Unsupported feature.*nonesuch/, $errs);

    ($res, $errs) = $self->compile_sieve_script('badreject1',
        "reject \"foo\"\n");
    $self->assert_str_equals('failure', $res);
    $self->assert_matches(qr/reject.*MUST be enabled/, $errs);

    ($res, $errs) = $self->compile_sieve_script('badreject2',
        "require [\"reject\"];\nreject\n");
    $self->assert_str_equals('failure', $res);
    $self->assert_matches(qr/syntax error/, $errs);

    ($res, $errs) = $self->compile_sieve_script('badreject3',
        "require [\"reject\"];\nreject 42\n");
    $self->assert_str_equals('failure', $res);
    $self->assert_matches(qr/syntax error/, $errs);

    # TODO: test UTF-8 verification of the string parameter

    ($res, $errs) = $self->compile_sieve_script('badfileinto1',
        "fileinto \"foo\"\n");
    $self->assert_str_equals('failure', $res);
    $self->assert_matches(qr/fileinto.*MUST be enabled/, $errs);

    ($res, $errs) = $self->compile_sieve_script('badfileinto2',
        "require [\"fileinto\"];\nfileinto\n");
    $self->assert_str_equals('failure', $res);
    $self->assert_matches(qr/syntax error/, $errs);

    ($res, $errs) = $self->compile_sieve_script('badfileinto3',
        "require [\"fileinto\"];\nfileinto 42\n");
    $self->assert_str_equals('failure', $res);
    $self->assert_matches(qr/syntax error/, $errs);

    ($res, $errs) = $self->compile_sieve_script('badfileinto4',
        "require [\"fileinto\"];\nfileinto :copy \"foo\"\n");
    $self->assert_str_equals('failure', $res);
    $self->assert_matches(qr/copy.*MUST be enabled/, $errs);

    ($res, $errs) = $self->compile_sieve_script('badfileinto5',
        "require [\"fileinto\",\"copy\"];\nfileinto \"foo\"\n");
    $self->assert_str_equals('failure', $res);
    $self->assert_matches(qr/syntax error/, $errs);

    ($res, $errs) = $self->compile_sieve_script('badfileinto6',
        "require [\"fileinto\",\"copy\"];\nfileinto :copy \"foo\"\n");
    $self->assert_str_equals('failure', $res);
    $self->assert_matches(qr/syntax error/, $errs);

    ($res, $errs) = $self->compile_sieve_script('badchar1',
        "require [\"fileinto\"];\n☃;\nfileinto \"foo\";\n");
    $self->assert_str_equals('failure', $res);
    $self->assert_matches(qr/non-ASCII/, $errs);

    ($res, $errs) = $self->compile_sieve_script('goodfileinto7',
        "require [\"fileinto\",\"copy\"];\nfileinto \"foo\";\n");
    $self->assert_str_equals('success', $res);

    ($res, $errs) = $self->compile_sieve_script('goodfileinto8',
        "require [\"fileinto\",\"copy\"];\nfileinto :copy \"foo\";\n");
    $self->assert_str_equals('success', $res);

    my $badregex1 = << 'EOF';
require ["regex"];
if header :regex "Subject" "Message (x)?(.*" {
    stop;
}
EOF
    ($res, $errs) = $self->compile_sieve_script('badregex1', $badregex1);
    $self->assert_str_equals('failure', $res);
    $self->assert_matches(qr/unbalanced/, $errs);

    # TODO: test UTF-8 verification of the string parameter
}

# Disabled for now - addflag does not work
# on shared mailboxes in 2.5.
# https://github.com/cyrusimap/cyrus-imapd/issues/1453
sub XXXtest_shared_delivery_addflag
    :Admin
    :needs_component_sieve
{
    my ($self) = @_;

    xlog $self, "Testing setting a flag on a sieve script on a";
    xlog $self, "shared folder.  Bug 3617 / issue #1453";

    my $imaptalk = $self->{store}->get_client();
    $self->{store}->set_fetch_attributes(qw(uid flags));

    xlog $self, "Create the target folder";
    my $admintalk = $self->{adminstore}->get_client();
    my $target = "shared.departments.cis";
    $admintalk->create($target)
        or die "Cannot create folder \"$target\": $@";
    $admintalk->setacl($target, admin => 'lrswipkxtecda')
        or die "Cannot setacl for \"$target\": $@";
    $admintalk->setacl($target, 'cassandane' => 'lrswipkxtecd')
        or die "Cannot setacl for \"$target\": $@";
    $admintalk->setacl($target, 'anyone' => 'p')
        or die "Cannot setacl for \"$target\": $@";

    xlog $self, "Install the sieve script";
    my $scriptname = 'cosbySweater';
    $self->{instance}->install_sieve_script(<<EOF
require ["imap4flags"];
if header :comparator "i;ascii-casemap" :is "Subject" "quinoa"  {
    addflag "\\\\Flagged";
    keep;
    stop;
}
EOF
    , username => undef,
    name => $scriptname);

    xlog $self, "Tell the folder to run the sieve script";
    $admintalk->setmetadata($target, "/shared/vendor/cmu/cyrus-imapd/sieve", $scriptname)
        or die "Cannot set metadata: $@";

    xlog $self, "Deliver a message";
    my $msg1 = $self->{gen}->generate(subject => "quinoa");
    $self->{instance}->deliver($msg1, users => [], folder => $target);

    xlog $self, "Check that the message made it to target";
    $self->{store}->set_folder($target);
    $msg1->set_attribute(flags => [ '\\Recent', '\\Flagged' ]);
    $self->check_messages({ 1 => $msg1 }, check_guid => 0);
}

use Cassandane::Tiny::Loader 'tiny-tests/Sieve';

1;
