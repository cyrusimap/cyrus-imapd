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

use lib '.';
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
    $config->set(httpmodules => ['caldav', 'jmap']);
    $config->set(calendar_user_address_set => 'example.com');
    $config->set(httpallowcompress => 'no');
    $config->set(caldav_historical_age => -1);
    $config->set(icalendar_max_size => 100000);
    $config->set(virtdomains => 'no');
    $config->set(jmap_nonstandard_extensions => 'yes');
    $config->set(conversations => 'yes');

    return $class->SUPER::new({
            config => $config,
            deliver => 1,
            jmap => 1,
            services => [ 'imap', 'sieve', 'http' ],
            adminstore => 1,
    }, @_);
}

sub set_up
{
    my ($self) = @_;
    $self->SUPER::set_up();
    if ($self->{jmap}) {
        $self->{jmap}->DefaultUsing([
            'urn:ietf:params:jmap:core',
            'urn:ietf:params:jmap:calendars',
            'urn:ietf:params:jmap:principals',
            'urn:ietf:params:jmap:calendars:preferences',
            'https://cyrusimap.org/ns/jmap/calendars',
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

    $self->assert(( ! -f "$basedir/$name.script" ));
    $self->assert(( ! -f "$basedir/$name.bc" ));
    $self->assert(( ! -f "$basedir/$name.errors" ));

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
        $self->assert(( -f "$basedir/$name.bc" ));
        xlog $self, "Checking that sievec didn't write anything to stderr";
        $self->assert_equals(0, scalar(@errors));
    }
    elsif ($result eq 'failure')
    {
        xlog $self, "Checking that sievec didn't write the output .bc file";
        $self->assert(( ! -f "$basedir/$name.bc" ));
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

    $self->assert(( ! -f "$basedir/$name.script" ));
    $self->assert(( ! -f "$basedir/$name.errors" ));

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

sub test_vacation_with_following_rules
    :needs_component_sieve :min_version_3_0
{
    my ($self) = @_;

    my $target = "INBOX.target";

    xlog $self, "Install a sieve script filing all mail into a nonexistant folder";
    $self->{instance}->install_sieve_script(<<'EOF'

require ["fileinto", "reject", "vacation", "imap4flags", "notify", "envelope", "relational", "regex", "subaddress", "copy", "mailbox", "mboxmetadata", "servermetadata", "date", "index", "comparator-i;ascii-numeric", "variables"];

### 5. Sieve generated for vacation responses
if
  allof(
  currentdate :zone "+0000" :value "ge" "iso8601" "2017-06-08T05:00:00Z",
  currentdate :zone "+0000" :value "le" "iso8601" "2017-06-13T19:00:00Z"
  )
{
  vacation :days 3 :addresses ["one@example.com", "two@example.com"] text:
I am out of the office today. I will answer your email as soon as I can.
.
;
}

### 7. Sieve generated for organise rules
if header :contains ["To","Cc","From","Subject","Date","Content-Type","Delivered-To","In-Reply-To","List-Post","List-Id","Mailing-List","Message-Id","Received","References","Reply-To","Return-Path","Sender","X-AntiAbuse","X-Apparently-From","X-Attached","X-Delivered-To","X-LinkName","X-Mail-From","X-Resolved-To","X-Sender","X-Sender-IP","X-Spam-Charsets","X-Spam-Hits","X-Spam-Known-Sender","X-Spam-Source","X-Version"] "urgent@example.com" {
  addflag "\\Flagged";
  fileinto "INBOX.Work";
  removeflag "\\Flagged";
}

EOF
    );

    xlog $self, "Deliver a message";
    my $msg1 = $self->{gen}->generate(subject => "Message 1");
    $self->{instance}->deliver($msg1);

    # This will crash if we have broken parsing of vacation
}

sub test_deliver
    :needs_component_sieve
{
    my ($self) = @_;

    my $target = "INBOX.target";

    xlog $self, "Install a sieve script filing all mail into a nonexistant folder";
    $self->{instance}->install_sieve_script(<<EOF
require ["fileinto"];
fileinto "$target";
EOF
    );

    xlog $self, "Deliver a message";
    my $msg1 = $self->{gen}->generate(subject => "Message 1");
    $self->{instance}->deliver($msg1);

    xlog $self, "Actually create the target folder";
    my $imaptalk = $self->{store}->get_client();

    $imaptalk->create($target)
         or die "Cannot create $target: $@";
    $self->{store}->set_fetch_attributes('uid');

    xlog $self, "Deliver another message";
    my $msg2 = $self->{gen}->generate(subject => "Message 2");
    $self->{instance}->deliver($msg2);
    $msg2->set_attribute(uid => 1);

    xlog $self, "Check that only the 1st message made it to INBOX";
    $self->{store}->set_folder('INBOX');
    $self->check_messages({ 1 => $msg1 }, check_guid => 0);

    xlog $self, "Check that only the 2nd message made it to the target";
    $self->{store}->set_folder($target);
    $self->check_messages({ 1 => $msg2 }, check_guid => 0);
}

sub test_deliver_specialuse
    :min_version_3_0
    :needs_component_sieve
    :NoAltNameSpace
{
    my ($self) = @_;

    my $target = "INBOX.target";

    xlog $self, "create the target folder";
    my $imaptalk = $self->{store}->get_client();

    $imaptalk->create($target, "(use (\\Trash))")
         or die "Cannot create $target: $@";
    $self->{store}->set_fetch_attributes('uid');

    xlog $self, "Install a sieve script filing all mail into the Trash role";
    $self->{instance}->install_sieve_script(<<EOF
require ["fileinto"];
fileinto "\\\\Trash";
EOF
    );

    xlog $self, "Deliver a message";
    my $msg = $self->{gen}->generate(subject => "Message 1");
    $self->{instance}->deliver($msg);
    $msg->set_attribute(uid => 1);

    xlog $self, "Check that no messages are in INBOX";
    $self->{store}->set_folder('INBOX');
    $self->check_messages({}, check_guid => 0);

    xlog $self, "Check that the message made it into the target folder";
    $self->{store}->set_folder($target);
    $self->check_messages({ 1 => $msg }, check_guid => 0);
}

sub test_deliver_compile
    :min_version_3_0
    :needs_component_sieve
{
    my ($self) = @_;

    my $target = "INBOX.target";

    xlog $self, "Create the target folder";
    my $imaptalk = $self->{store}->get_client();
    $imaptalk->create($target)
         or die "Cannot create $target: $@";
    $self->{store}->set_fetch_attributes('uid');

    xlog $self, "Install a sieve script filing all mail into the target folder";
    $self->{instance}->install_sieve_script(<<EOF
require ["fileinto"];
fileinto "$target";
EOF
    );

    xlog $self, "Deliver a message";
    my $msg1 = $self->{gen}->generate(subject => "Message 1");
    $self->{instance}->deliver($msg1);

    xlog $self, "Delete the compiled bytecode";
    my $sieve_dir = $self->{instance}->get_sieve_script_dir('cassandane');
    my $fname = "$sieve_dir/test1.bc";
    unlink $fname or die "Cannot unlink $fname: $!";

    sleep 1; # so the two deliveries get different syslog timestamps

    xlog $self, "Deliver another message - lmtpd should rebuild the missing bytecode";
    my $msg2 = $self->{gen}->generate(subject => "Message 2");
    $self->{instance}->deliver($msg2);

    xlog $self, "Check that both messages made it to the target";
    $self->{store}->set_folder($target);
    $self->check_messages({ 1 => $msg1, 2 => $msg2 }, check_guid => 0);
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

    ($res, $errs) = $self->compile_sieve_script('goodfileinto7',
        "require [\"fileinto\",\"copy\"];\nfileinto \"foo\";\n");
    $self->assert_str_equals('success', $res);

    ($res, $errs) = $self->compile_sieve_script('goodfileinto8',
        "require [\"fileinto\",\"copy\"];\nfileinto :copy \"foo\";\n");
    $self->assert_str_equals('success', $res);

    # TODO: test UTF-8 verification of the string parameter
}

sub test_badscript_sievec
    :needs_component_sieve
{
    my ($self) = @_;

    xlog $self, "Testing sieve script compile failures, via sievec";
    $self->{compile_method} = 'sievec';
    $self->badscript_common();
}

sub test_badscript_timsieved
    :needs_component_sieve
{
    my ($self) = @_;

    xlog $self, "Testing sieve script compile failures, via timsieved";
    $self->{compile_method} = 'timsieved';
    $self->badscript_common();
}

sub test_dup_keep_keep
    :needs_component_sieve
{
    my ($self) = @_;

    xlog $self, "Testing duplicate suppression between 'keep' & 'keep'";

    $self->{instance}->install_sieve_script(<<EOF
keep;
keep;
EOF
    );

    xlog $self, "Deliver a message";
    my $msg1 = $self->{gen}->generate(subject => "Message 1");
    $self->{instance}->deliver($msg1);

    xlog $self, "Check that only one copy of the message made it to INBOX";
    $self->{store}->set_folder('INBOX');
    $self->check_messages({ 1 => $msg1 }, check_guid => 0);
}

# Note: experiment indicates that duplicate suppression
# with sieve's fileinto does not work if the mailbox has
# the OPT_IMAP_DUPDELIVER option enabled.  This is not
# really broken, although perhaps unexpected, and it not
# tested for here.

sub test_dup_keep_fileinto
    :needs_component_sieve
{
    my ($self) = @_;

    xlog $self, "Testing duplicate suppression between 'keep' & 'fileinto'";

    $self->{instance}->install_sieve_script(<<EOF
require ["fileinto"];
keep;
fileinto "INBOX";
EOF
    );

    xlog $self, "Deliver a message";
    my $msg1 = $self->{gen}->generate(subject => "Message 1");
    $self->{instance}->deliver($msg1);

    xlog $self, "Check that only one copy of the message made it to INBOX";
    $self->{store}->set_folder('INBOX');
    $self->check_messages({ 1 => $msg1 }, check_guid => 0);
}

sub test_deliver_fileinto_autocreate_globalshared
    :needs_component_sieve :NoStartInstances :NoAltNameSpace
{
    my ($self) = @_;

    $self->{instance}->{config}->set('anysievefolder' => 'yes');
    $self->_start_instances();

    # sieve script should not be able to create a new global shared mailbox
    my $target = "TopLevel";

    $self->{instance}->install_sieve_script(<<EOF
require ["fileinto"];
fileinto "$target";
EOF
    , username => 'cassandane');

    my $msg1 = $self->{gen}->generate(subject => "Message 1");
    $self->{instance}->deliver($msg1, users => [ 'cassandane' ]);

    # autosievefolder should have failed to create the target, because the
    # user doesn't have permission to create a folder in the global shared
    # namespace
    my $admintalk = $self->{adminstore}->get_client();
    $admintalk->select($target);
    $self->assert_str_equals('no', $admintalk->get_last_completion_response());
    $self->assert_matches(qr/does not exist/i, $admintalk->get_last_error());

    # then the fileinto should fail, and the message be delivered to inbox
    # instead
    $self->{store}->set_folder('INBOX');
    $self->check_messages({ 1 => $msg1 }, check_guid => 0);
}

sub test_deliver_fileinto_autocreate_otheruser
    :needs_component_sieve :NoStartInstances :NoAltNameSpace
{
    my ($self) = @_;

    $self->{instance}->{config}->set('anysievefolder' => 'yes');
    $self->_start_instances();

    $self->{instance}->create_user('other');

    # sieve script should not be able to create a mailbox in some other
    # user's account
    my $target = "user.other.SomeFolder";

    $self->{instance}->install_sieve_script(<<EOF
require ["fileinto"];
fileinto "$target";
EOF
    , username => 'cassandane');

    my $msg1 = $self->{gen}->generate(subject => "Message 1");
    $self->{instance}->deliver($msg1, users => [ 'cassandane' ]);

    # autosievefolder should have failed to create the target, because the
    # user doesn't have permission to create a folder in another user's
    # account
    my $admintalk = $self->{adminstore}->get_client();
    $admintalk->select($target);
    $self->assert_str_equals('no', $admintalk->get_last_completion_response());
    $self->assert_matches(qr/does not exist/i, $admintalk->get_last_error());

    # then the fileinto should fail, and the message be delivered to inbox
    # instead
    $self->{store}->set_folder('INBOX');
    $self->check_messages({ 1 => $msg1 }, check_guid => 0);
}

sub test_deliver_fileinto_autocreate_newuser
    :needs_component_sieve :NoStartInstances :NoAltNameSpace
{
    my ($self) = @_;

    $self->{instance}->{config}->set('anysievefolder' => 'yes');
    $self->_start_instances();

    # sieve script should not be able to create a new user account
    my $target = "user.other";

    $self->{instance}->install_sieve_script(<<EOF
require ["fileinto"];
fileinto "$target";
EOF
    , username => 'cassandane');

    my $msg1 = $self->{gen}->generate(subject => "Message 1");
    $self->{instance}->deliver($msg1, users => [ 'cassandane' ]);

    # autosievefolder should have failed to create the target, because the
    # user doesn't have permission to create a mailbox under user.
    my $admintalk = $self->{adminstore}->get_client();
    $admintalk->select($target);
    $self->assert_str_equals('no', $admintalk->get_last_completion_response());
    $self->assert_matches(qr/does not exist/i, $admintalk->get_last_error());

    # then the fileinto should fail, and the message be delivered to inbox
    # instead
    $self->{store}->set_folder('INBOX');
    $self->check_messages({ 1 => $msg1 }, check_guid => 0);
}

sub test_deliver_fileinto_create_globalshared
    :needs_component_sieve :min_version_3_0 :NoAltNameSpace
{
    my ($self) = @_;

    # sieve script should not be able to create a new global shared mailbox
    my $target = "TopLevel";

    $self->{instance}->install_sieve_script(<<EOF
require ["fileinto", "mailbox"];
fileinto :create "$target";
EOF
    , username => 'cassandane');

    my $msg1 = $self->{gen}->generate(subject => "Message 1");
    $self->{instance}->deliver($msg1, users => [ 'cassandane' ]);

    # autosievefolder should have failed to create the target, because the
    # user doesn't have permission to create a folder in the global shared
    # namespace
    my $admintalk = $self->{adminstore}->get_client();
    $admintalk->select($target);
    $self->assert_str_equals('no', $admintalk->get_last_completion_response());
    $self->assert_matches(qr/does not exist/i, $admintalk->get_last_error());

    # then the fileinto should fail, and the message be delivered to inbox
    # instead
    $self->{store}->set_folder('INBOX');
    $self->check_messages({ 1 => $msg1 }, check_guid => 0);
}

sub test_deliver_fileinto_create_otheruser
    :needs_component_sieve :min_version_3_0 :NoAltNameSpace
{
    my ($self) = @_;

    $self->{instance}->create_user('other');

    # sieve script should not be able to create a mailbox in some other
    # user's account
    my $target = "user.other.SomeFolder";

    $self->{instance}->install_sieve_script(<<EOF
require ["fileinto", "mailbox"];
fileinto :create "$target";
EOF
    , username => 'cassandane');

    my $msg1 = $self->{gen}->generate(subject => "Message 1");
    $self->{instance}->deliver($msg1, users => [ 'cassandane' ]);

    # autosievefolder should have failed to create the target, because the
    # user doesn't have permission to create a folder in another user's
    # account
    my $admintalk = $self->{adminstore}->get_client();
    $admintalk->select($target);
    $self->assert_str_equals('no', $admintalk->get_last_completion_response());
    $self->assert_matches(qr/does not exist/i, $admintalk->get_last_error());

    # then the fileinto should fail, and the message be delivered to inbox
    # instead
    $self->{store}->set_folder('INBOX');
    $self->check_messages({ 1 => $msg1 }, check_guid => 0);
}

sub test_deliver_fileinto_create_newuser
    :needs_component_sieve :min_version_3_0 :NoAltNameSpace
{
    my ($self) = @_;

    # sieve script should not be able to create a new user
    my $target = "user.other";

    $self->{instance}->install_sieve_script(<<EOF
require ["fileinto", "mailbox"];
fileinto :create "$target";
EOF
    , username => 'cassandane');

    my $msg1 = $self->{gen}->generate(subject => "Message 1");
    $self->{instance}->deliver($msg1, users => [ 'cassandane' ]);

    # autosievefolder should have failed to create the target, because the
    # user doesn't have permission to create a mailbox under user.
    my $admintalk = $self->{adminstore}->get_client();
    $admintalk->select($target);
    $self->assert_str_equals('no', $admintalk->get_last_completion_response());
    $self->assert_matches(qr/does not exist/i, $admintalk->get_last_error());

    # then the fileinto should fail, and the message be delivered to inbox
    # instead
    $self->{store}->set_folder('INBOX');
    $self->check_messages({ 1 => $msg1 }, check_guid => 0);
}

sub test_deliver_fileinto_create_nonimap
    :needs_component_sieve :min_version_3_0 :NoAltNameSpace
{
    my ($self) = @_;

    # sieve script should not be able to create a non-IMAP mailbox
    my $target = "INBOX.#calendars.target";

    $self->{instance}->install_sieve_script(<<EOF
require ["fileinto", "mailbox"];
fileinto :create "$target";
EOF
    , username => 'cassandane');

    my $msg1 = $self->{gen}->generate(subject => "Message 1");
    $self->{instance}->deliver($msg1, users => [ 'cassandane' ]);

    # autosievefolder should have failed to create the target,
    # because the the target is in a non-IMAP namespace
    my $admintalk = $self->{adminstore}->get_client();
    $admintalk->select($target);
    $self->assert_str_equals('no', $admintalk->get_last_completion_response());
    $self->assert_matches(qr/does not exist/i, $admintalk->get_last_error());

    # then the fileinto should fail,
    # and the message be delivered to inbox instead
    $self->{store}->set_folder('INBOX');
    $self->check_messages({ 1 => $msg1 }, check_guid => 0);
}

sub test_deliver_fileinto_dot
    :UnixHierarchySep
    :needs_component_sieve
{
    my ($self) = @_;

    xlog $self, "Testing a sieve script which does a 'fileinto' a mailbox";
    xlog $self, "when the user has a dot in their name.  Bug 3664";
    # NOTE: The commit https://github.com/cyrusimap/cyrus-imapd/commit/73af8e19546f235f6286cc9147a3ea74bde19ebb
    # in Cyrus-imapd changes this behaviour where in we don't do a '.' -> '^' anymore.

    xlog $self, "Create the dotted user";
    my $user = 'betty.boop';
    $self->{instance}->create_user($user);

    xlog $self, "Connect as the new user";
    my $svc = $self->{instance}->get_service('imap');
    $self->{store} = $svc->create_store(username => $user, folder => 'INBOX');
    $self->{store}->set_fetch_attributes('uid');
    my $imaptalk = $self->{store}->get_client();

    xlog $self, "Create the target folder";

    my $target = Cassandane::Mboxname->new(config => $self->{instance}->{config},
                                           userid => $user,
                                           box => 'target')->to_external();
    $imaptalk->create($target)
         or die "Cannot create $target: $@";

    xlog $self, "Install the sieve script";
    $self->{instance}->install_sieve_script(<<EOF
require ["fileinto"];
fileinto "$target";
EOF
    , username => 'betty.boop');

    xlog $self, "Deliver a message";
    my $msg1 = $self->{gen}->generate(subject => "Message 1");
    $self->{instance}->deliver($msg1, users => [ $user ]);

    xlog $self, "Check that the message made it to target";
    $self->{store}->set_folder($target);
    $self->check_messages({ 1 => $msg1 }, check_guid => 0);
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

sub test_rfc5490_create
    :min_version_3_0
    :needs_component_sieve
{
    my ($self) = @_;

    xlog $self, "Testing the \"fileinto :create\" syntax";

    my $talk = $self->{store}->get_client();

    my $hitfolder = "INBOX.newfolder";
    my $missfolder = "INBOX";

    xlog $self, "Install the sieve script";
    my $scriptname = 'lazySusan';
    $self->{instance}->install_sieve_script(<<EOF
require ["fileinto", "mailbox"];
if header :comparator "i;ascii-casemap" :is "Subject" "quinoa"  {
    fileinto :create "$hitfolder";
}
EOF
    );

    my @cases = (
        { subject => 'quinoa', filedto => $hitfolder },
        { subject => 'QUINOA', filedto => $hitfolder },
        { subject => 'Quinoa', filedto => $hitfolder },
        { subject => 'QuinoA', filedto => $hitfolder },
        { subject => 'qUINOa', filedto => $hitfolder },
        { subject => 'selvage', filedto => $missfolder },
    );

    my %uid = ($hitfolder => 1, $missfolder => 1);
    my %exp;
    foreach my $case (@cases)
    {
        xlog $self, "Deliver a message with subject \"$case->{subject}\"";
        my $msg = $self->{gen}->generate(subject => $case->{subject});
        $msg->set_attribute(uid => $uid{$case->{filedto}});
        $uid{$case->{filedto}}++;
        $self->{instance}->deliver($msg);
        $exp{$case->{filedto}}->{$case->{subject}} = $msg;
    }

    xlog $self, "Check that the messages made it";
    foreach my $folder (keys %exp)
    {
        $self->{store}->set_folder($folder);
        $self->check_messages($exp{$folder}, check_guid => 0);
    }
}

sub test_rfc5490_mailboxexists
    :min_version_3_0
    :needs_component_sieve
{
    my ($self) = @_;

    xlog $self, "Testing the \"mailboxexists\" test";

    my $talk = $self->{store}->get_client();

    my $hitfolder = "INBOX.newfolder";
    my $testfolder = "INBOX.testfolder";
    my $missfolder = "INBOX";

    xlog $self, "Install the sieve script";
    my $scriptname = 'flatPack';
    $self->{instance}->install_sieve_script(<<EOF
require ["fileinto", "mailbox"];
if mailboxexists "$testfolder"  {
    fileinto "$hitfolder";
}
EOF
    );

    $talk->create($hitfolder);

    my %uid = ($hitfolder => 1, $missfolder => 1);
    my %exp;
    xlog $self, "Deliver a message";
    {
        my $msg = $self->{gen}->generate(subject => "msg1");
        $msg->set_attribute(uid => $uid{$missfolder});
        $uid{$missfolder}++;
        $self->{instance}->deliver($msg);
        $exp{$missfolder}->{"msg1"} = $msg;
    }

    xlog $self, "Create the test folder";
    $talk->create($testfolder);

    xlog $self, "Deliver a message now that the folder exists";
    {
        my $msg = $self->{gen}->generate(subject => "msg2");
        $msg->set_attribute(uid => $uid{$hitfolder});
        $uid{$hitfolder}++;
        $self->{instance}->deliver($msg);
        $exp{$hitfolder}->{"msg2"} = $msg;
    }

    xlog $self, "Check that the messages made it";
    foreach my $folder (keys %exp)
    {
        $self->{store}->set_folder($folder);
        $self->check_messages($exp{$folder}, check_guid => 0);
    }
}

sub test_rfc5490_mailboxexists_variables
    :min_version_3_0
    :needs_component_sieve
{
    my ($self) = @_;

    xlog $self, "Testing the \"mailboxexists\" test with variables";

    my $talk = $self->{store}->get_client();

    my $hitfolder = "INBOX.newfolder";
    my $testfolder = "INBOX.testfolder";
    my $missfolder = "INBOX";

    xlog $self, "Install the sieve script";
    my $scriptname = 'flatPack';
    $self->{instance}->install_sieve_script(<<EOF
require ["fileinto", "mailbox", "variables"];
set "testfolder" "$testfolder";
set "testfolder" "\${testfolder}";  # test setting variable value from itself
if mailboxexists "\${testfolder}"  {
    fileinto "$hitfolder";
}
EOF
    );

    $talk->create($hitfolder);

    my %uid = ($hitfolder => 1, $missfolder => 1);
    my %exp;
    xlog $self, "Deliver a message";
    {
        my $msg = $self->{gen}->generate(subject => "msg1");
        $msg->set_attribute(uid => $uid{$missfolder});
        $uid{$missfolder}++;
        $self->{instance}->deliver($msg);
        $exp{$missfolder}->{"msg1"} = $msg;
    }

    xlog $self, "Create the test folder";
    $talk->create($testfolder);

    xlog $self, "Deliver a message now that the folder exists";
    {
        my $msg = $self->{gen}->generate(subject => "msg2");
        $msg->set_attribute(uid => $uid{$hitfolder});
        $uid{$hitfolder}++;
        $self->{instance}->deliver($msg);
        $exp{$hitfolder}->{"msg2"} = $msg;
    }

    xlog $self, "Check that the messages made it";
    foreach my $folder (keys %exp)
    {
        $self->{store}->set_folder($folder);
        $self->check_messages($exp{$folder}, check_guid => 0);
    }
}

sub test_rfc5490_metadata
    :min_version_3_0
    :needs_component_sieve
{
    my ($self) = @_;

    xlog $self, "Testing the \"metadata\" test";

    my $talk = $self->{store}->get_client();

    my $hitfolder = "INBOX.newfolder";
    my $missfolder = "INBOX";

    xlog $self, "Install the sieve script";
    $self->{instance}->install_sieve_script(<<EOF
require ["fileinto", "mboxmetadata"];
if metadata "INBOX" "/private/comment" "awesome" {
    fileinto "$hitfolder";
}
EOF
    );

    $talk->create($hitfolder);

    my %uid = ($hitfolder => 1, $missfolder => 1);
    my %exp;
    xlog $self, "Deliver a message";
    {
        my $msg = $self->{gen}->generate(subject => "msg1");
        $msg->set_attribute(uid => $uid{$missfolder});
        $uid{$missfolder}++;
        $self->{instance}->deliver($msg);
        $exp{$missfolder}->{"msg1"} = $msg;
    }

    xlog $self, "Create the annotation";
    $talk->setmetadata("INBOX", "/private/comment", "awesome");

    xlog $self, "Deliver a message now that the folder exists";
    {
        my $msg = $self->{gen}->generate(subject => "msg2");
        $msg->set_attribute(uid => $uid{$hitfolder});
        $uid{$hitfolder}++;
        $self->{instance}->deliver($msg);
        $exp{$hitfolder}->{"msg2"} = $msg;
    }

    xlog $self, "Check that the messages made it";
    foreach my $folder (keys %exp)
    {
        $self->{store}->set_folder($folder);
        $self->check_messages($exp{$folder}, check_guid => 0);
    }
}

sub test_rfc5490_metadata_matches
    :min_version_3_0
    :needs_component_sieve
{
    my ($self) = @_;

    xlog $self, "Testing the \"metadata\" test";

    my $talk = $self->{store}->get_client();

    my $hitfolder = "INBOX.newfolder";
    my $missfolder = "INBOX";

    xlog $self, "Install the sieve script";
    $self->{instance}->install_sieve_script(<<EOF
require ["fileinto", "mboxmetadata"];
if metadata :contains "INBOX" "/private/comment" "awesome" {
    fileinto "$hitfolder";
}
EOF
    );

    xlog $self, "Set the initial annotation";
    $talk->setmetadata("INBOX", "/private/comment", "awesomesauce");

    $talk->create($hitfolder);

    my %uid = ($hitfolder => 1, $missfolder => 1);
    my %exp;
    xlog $self, "Deliver a message";
    {
        my $msg = $self->{gen}->generate(subject => "msg1");
        $msg->set_attribute(uid => $uid{$hitfolder});
        $uid{$hitfolder}++;
        $self->{instance}->deliver($msg);
        $exp{$hitfolder}->{"msg1"} = $msg;
    }

    xlog $self, "Create the annotation";
    $talk->setmetadata("INBOX", "/private/comment", "awesome");

    xlog $self, "Deliver a message now that the folder exists";
    {
        my $msg = $self->{gen}->generate(subject => "msg2");
        $msg->set_attribute(uid => $uid{$hitfolder});
        $uid{$hitfolder}++;
        $self->{instance}->deliver($msg);
        $exp{$hitfolder}->{"msg2"} = $msg;
    }

    xlog $self, "Check that the messages made it";
    foreach my $folder (keys %exp)
    {
        $self->{store}->set_folder($folder);
        $self->check_messages($exp{$folder}, check_guid => 0);
    }
}

sub test_rfc5490_metadataexists
    :min_version_3_0 :AnnotationAllowUndefined
    :needs_component_sieve
{
    my ($self) = @_;

    xlog $self, "Testing the \"metadataexists\" test";

    my $talk = $self->{store}->get_client();

    my $hitfolder = "INBOX.newfolder";
    my $missfolder = "INBOX";

    xlog $self, "Install the sieve script";
    $self->{instance}->install_sieve_script(<<EOF
require ["fileinto", "mboxmetadata"];
if metadataexists "INBOX" "/private/magic" {
    fileinto "$hitfolder";
}
EOF
    );

    $talk->create($hitfolder);

    my %uid = ($hitfolder => 1, $missfolder => 1);
    my %exp;
    xlog $self, "Deliver a message";
    {
        my $msg = $self->{gen}->generate(subject => "msg1");
        $msg->set_attribute(uid => $uid{$missfolder});
        $uid{$missfolder}++;
        $self->{instance}->deliver($msg);
        $exp{$missfolder}->{"msg1"} = $msg;
    }

    xlog $self, "Create the annotation";
    $talk->setmetadata("INBOX", "/private/magic", "hello");

    xlog $self, "Deliver a message now that the folder exists";
    {
        my $msg = $self->{gen}->generate(subject => "msg2");
        $msg->set_attribute(uid => $uid{$hitfolder});
        $uid{$hitfolder}++;
        $self->{instance}->deliver($msg);
        $exp{$hitfolder}->{"msg2"} = $msg;
    }

    xlog $self, "Check that the messages made it";
    foreach my $folder (keys %exp)
    {
        $self->{store}->set_folder($folder);
        $self->check_messages($exp{$folder}, check_guid => 0);
    }
}

sub test_rfc5490_servermetadata
    :min_version_3_0 :AnnotationAllowUndefined
    :needs_component_sieve
{
    my ($self) = @_;

    xlog $self, "Testing the \"metadata\" test";

    my $talk = $self->{store}->get_client();
    my $admintalk = $self->{adminstore}->get_client();

    my $hitfolder = "INBOX.newfolder";
    my $missfolder = "INBOX";

    xlog $self, "Install the sieve script";
    $self->{instance}->install_sieve_script(<<EOF
require ["fileinto", "servermetadata"];
if servermetadata "/shared/magic" "awesome" {
    fileinto "$hitfolder";
}
EOF
    );

    $talk->create($hitfolder);

    # have a value
    $admintalk->setmetadata("", "/shared/magic", "awesomesauce");

    my %uid = ($hitfolder => 1, $missfolder => 1);
    my %exp;
    xlog $self, "Deliver a message";
    {
        my $msg = $self->{gen}->generate(subject => "msg1");
        $msg->set_attribute(uid => $uid{$missfolder});
        $uid{$missfolder}++;
        $self->{instance}->deliver($msg);
        $exp{$missfolder}->{"msg1"} = $msg;
    }

    xlog $self, "Create the annotation";
    $admintalk->setmetadata("", "/shared/magic", "awesome");

    xlog $self, "Deliver a message now that the folder exists";
    {
        my $msg = $self->{gen}->generate(subject => "msg2");
        $msg->set_attribute(uid => $uid{$hitfolder});
        $uid{$hitfolder}++;
        $self->{instance}->deliver($msg);
        $exp{$hitfolder}->{"msg2"} = $msg;
    }

    xlog $self, "Check that the messages made it";
    foreach my $folder (keys %exp)
    {
        $self->{store}->set_folder($folder);
        $self->check_messages($exp{$folder}, check_guid => 0);
    }
}

sub test_rfc5490_servermetadataexists
    :min_version_3_0 :AnnotationAllowUndefined
    :needs_component_sieve
{
    my ($self) = @_;

    xlog $self, "Testing the \"servermetadataexists\" test";

    my $talk = $self->{store}->get_client();
    my $admintalk = $self->{adminstore}->get_client();

    my $hitfolder = "INBOX.newfolder";
    my $missfolder = "INBOX";

    xlog $self, "Install the sieve script";
    $self->{instance}->install_sieve_script(<<EOF
require ["fileinto", "servermetadata"];
if servermetadataexists ["/shared/magic", "/shared/moo"] {
    fileinto "$hitfolder";
}
EOF
    );

    $admintalk->setmetadata("", "/shared/magic", "foo");
    $talk->create($hitfolder);

    my %uid = ($hitfolder => 1, $missfolder => 1);
    my %exp;
    xlog $self, "Deliver a message";
    {
        my $msg = $self->{gen}->generate(subject => "msg1");
        $msg->set_attribute(uid => $uid{$missfolder});
        $uid{$missfolder}++;
        $self->{instance}->deliver($msg);
        $exp{$missfolder}->{"msg1"} = $msg;
    }

    xlog $self, "Create the annotation";
    $admintalk->setmetadata("", "/shared/moo", "hello");

    xlog $self, "Deliver a message now that the folder exists";
    {
        my $msg = $self->{gen}->generate(subject => "msg2");
        $msg->set_attribute(uid => $uid{$hitfolder});
        $uid{$hitfolder}++;
        $self->{instance}->deliver($msg);
        $exp{$hitfolder}->{"msg2"} = $msg;
    }

    xlog $self, "Check that the messages made it";
    foreach my $folder (keys %exp)
    {
        $self->{store}->set_folder($folder);
        $self->check_messages($exp{$folder}, check_guid => 0);
    }
}

sub test_variables_basic
    :min_version_3_0
    :needs_component_sieve
{
    my ($self) = @_;

    xlog $self, "Actually create the target folder";
    my $imaptalk = $self->{store}->get_client();

    $imaptalk->create("INBOX.target");
    $imaptalk->create("INBOX.target.Folder1");
    $imaptalk->create("INBOX.target.Folder2");

    xlog $self, "Install a sieve script filing all mail into a nonexistant folder";
    $self->{instance}->install_sieve_script(<<EOF
require ["fileinto", "variables"];
set "folder" "target";
if header :matches "Subject" "Message *" {
    fileinto "INBOX.\${folder}.Folder\${1}";
    stop;
}
fileinto "INBOX.\${folder}";
EOF
    );

    xlog $self, "Deliver a message";

    # should go in Folder1
    my $msg1 = $self->{gen}->generate(subject => " \r\n Message\r\n 1 ");
    $self->{instance}->deliver($msg1);

    # should go in Folder2
    my $msg2 = $self->{gen}->generate(subject => "Message 2");
    $self->{instance}->deliver($msg2);

    # should fail to deliver and wind up in INBOX
    my $msg3 = $self->{gen}->generate(subject => "Message 3");
    $self->{instance}->deliver($msg3);

    # should not match the if, and file into target
    my $msg4 = $self->{gen}->generate(subject => "Totally different");
    $self->{instance}->deliver($msg4);

    $imaptalk->select("INBOX.target.Folder1");
    $self->assert_num_equals(1, $imaptalk->get_response_code('exists'));

    $imaptalk->select("INBOX.target.Folder2");
    $self->assert_num_equals(1, $imaptalk->get_response_code('exists'));

    $imaptalk->select("INBOX");
    $self->assert_num_equals(1, $imaptalk->get_response_code('exists'));

    $imaptalk->select("INBOX.target");
    $self->assert_num_equals(1, $imaptalk->get_response_code('exists'));
}

sub test_sieve_setflag
    :min_version_3_0
    :needs_component_sieve
{
    my ($self) = @_;

    xlog $self, "Actually create the target folder";
    my $imaptalk = $self->{store}->get_client();

    xlog $self, "Install a sieve script filing all mail into a nonexistant folder";
    $self->{instance}->install_sieve_script(<<EOF
require ["fileinto", "imap4flags"];
if header :matches "Subject" "Message 2" {
    setflag "\\\\Flagged";
}
EOF
    );

    xlog $self, "Deliver a message";

    # should go in Folder1
    my $msg1 = $self->{gen}->generate(subject => "Message 1");
    $self->{instance}->deliver($msg1);

    # should go in Folder2
    my $msg2 = $self->{gen}->generate(subject => "Message 2");
    $self->{instance}->deliver($msg2);

    # should fail to deliver and wind up in INBOX
    my $msg3 = $self->{gen}->generate(subject => "Message 3");
    $self->{instance}->deliver($msg3);

    $imaptalk->unselect();
    $imaptalk->select("INBOX");
    $self->assert_num_equals(3, $imaptalk->get_response_code('exists'));

    my @uids = $imaptalk->search('1:*', 'NOT', 'FLAGGED');

    $self->assert_num_equals(2, scalar(@uids));
}

sub test_variables_regex
    :min_version_3_0
    :needs_component_sieve
{
    my ($self) = @_;

    xlog $self, "Actually create the target folder";
    my $imaptalk = $self->{store}->get_client();

    $imaptalk->create("INBOX.target");
    $imaptalk->create("INBOX.target.Folder1");
    $imaptalk->create("INBOX.target.Folder2");

    xlog $self, "Install a sieve script filing all mail into a nonexistant folder";
    $self->{instance}->install_sieve_script(<<EOF
require ["fileinto", "variables", "regex"];
set "folder" "target";
if header :regex "Subject" "Message (x)?(.*)" {
    fileinto "INBOX.\${folder}.Folder\${2}";
    stop;
}
fileinto "INBOX.\${folder}";
EOF
    );

    xlog $self, "Deliver a message";

    # should go in Folder1
    my $msg1 = $self->{gen}->generate(subject => "Message 1");
    $self->{instance}->deliver($msg1);

    # should go in Folder2
    my $msg2 = $self->{gen}->generate(subject => "Message x2");
    $self->{instance}->deliver($msg2);

    # should fail to deliver and wind up in INBOX
    my $msg3 = $self->{gen}->generate(subject => "Message 3");
    $self->{instance}->deliver($msg3);

    # should not match the if, and file into target
    my $msg4 = $self->{gen}->generate(subject => "Totally different");
    $self->{instance}->deliver($msg4);

    $imaptalk->select("INBOX.target.Folder1");
    $self->assert_num_equals(1, $imaptalk->get_response_code('exists'));

    $imaptalk->select("INBOX.target.Folder2");
    $self->assert_num_equals(1, $imaptalk->get_response_code('exists'));

    $imaptalk->select("INBOX");
    $self->assert_num_equals(1, $imaptalk->get_response_code('exists'));

    $imaptalk->select("INBOX.target");
    $self->assert_num_equals(1, $imaptalk->get_response_code('exists'));
}

sub test_nested_tests_and_discard
    :needs_component_sieve
{
    my ($self) = @_;

    xlog $self, "Install a sieve script discarding all mail";
    $self->{instance}->install_sieve_script(<<EOF
if anyof (false,
          allof (not false,
                 true)
          ) {
  discard;
  stop;
}
EOF
    );

    xlog $self, "Attempt to deliver a message";
    my $msg1 = $self->{gen}->generate(subject => "Message 1");
    $self->{instance}->deliver($msg1);

    # should fail to deliver and NOT appear in INBOX
    my $imaptalk = $self->{store}->get_client();
    $imaptalk->select("INBOX");
    $self->assert_num_equals(0, $imaptalk->get_response_code('exists'));
}

sub test_editheader_basic
    :min_version_3_1
    :needs_component_sieve
{
    my ($self) = @_;

    my $target = "INBOX.target";

    xlog $self, "Install a sieve script with editheader actions";
    $self->{instance}->install_sieve_script(<<EOF
require ["editheader", "index", "regex", "fileinto", "copy"];
fileinto :copy "$target";
addheader "X-Cassandane-Test" "prepend1";
addheader "X-Cassandane-Test2" "prepend2";
addheader "X-Cassandane-Test2" "prepend3";
addheader :last "X-Cassandane-Test" "append1";
addheader :last "X-Cassandane-Test" "append2";
addheader :last "X-Cassandane-Test" "append3";
addheader :last "X-Cassandane-Test" "append4";
addheader :last "X-Cassandane-Test" "append5";
addheader :last "X-Cassandane-Test" "append6";
deleteheader :index 3 :contains "X-Cassandane-Test" "append";
deleteheader :regex "X-Cassandane-Test" "append4";
deleteheader :index 1 :last "X-Cassandane-Test";
deleteheader "X-Cassandane-Test2";
EOF
    );

    xlog $self, "Create the target folder";
    my $imaptalk = $self->{store}->get_client();

    $imaptalk->create($target)
         or die "Cannot create $target: $@";

    xlog $self, "Deliver a message";
    my $msg1 = $self->{gen}->generate(subject => "Message 1");
    $self->{instance}->deliver($msg1);

    $imaptalk->select("INBOX");
    my $res = $imaptalk->fetch(1, 'rfc822');

    $msg1 = $res->{1}->{rfc822};

    $self->assert_matches(qr/^X-Cassandane-Test: prepend1\r\n/, $msg1);
    $self->assert_matches(qr/X-Cassandane-Test: append1\r\nX-Cassandane-Test: append3\r\nX-Cassandane-Test: append5\r\n\r\n/, $msg1);

    $imaptalk->select($target);
    $res = $imaptalk->fetch(1, 'rfc822');

    $msg1 = $res->{1}->{rfc822};

    $self->assert_matches(qr/^Return-Path: /, $msg1);
    $self->assert_matches(qr/X-Cassandane-Unique: .*\r\n\r\n/, $msg1);
}

sub test_editheader_complex
    :min_version_3_3
    :needs_component_sieve
{
    my ($self) = @_;

    my $target = "INBOX.target";

    xlog $self, "Install a sieve script with editheader actions";
    $self->{instance}->install_sieve_script(<<EOF
require ["editheader", "index", "regex", "fileinto", "copy", "encoded-character", "variables"];
addheader "X-Hello" "World\${unicode:2217}";
if header :contains "X-Hello" "World\${unicode:2217}" {
    fileinto :copy "$target";
}
set "x" text:
prepend1
.
;
addheader "X-Cassandane-Test" text:
\${x}
.
;
addheader "X-Cassandane-Test2" "prepend2";
addheader "X-Cassandane-Test2" "prepend3";
addheader :last "X-Cassandane-Test" "append1";
addheader :last "X-Cassandane-Test" "append2";
addheader :last "X-Cassandane-Test" "append3";
addheader :last "X-Cassandane-Test" text:

 append4
.
;
addheader :last "X-Cassandane-Test" "append5";
addheader :last "X-Cassandane-Test" "append6";
deleteheader :index 3 :contains "X-Cassandane-Test" "append";
deleteheader :regex "X-Cassandane-Test" "append4";
deleteheader :index 1 :last "X-Cassandane-Test";
deleteheader "X-Cassandane-Test2";
EOF
    );

    xlog $self, "Create the target folder";
    my $imaptalk = $self->{store}->get_client();

    $imaptalk->create($target)
         or die "Cannot create $target: $@";

    xlog $self, "Deliver a message";
    my $msg1 = $self->{gen}->generate(subject => "Message 1");
    $self->{instance}->deliver($msg1);

    $imaptalk->select("INBOX");
    my $res = $imaptalk->fetch(1, 'rfc822');

    $msg1 = $res->{1}->{rfc822};

    $self->assert_matches(qr/^X-Cassandane-Test: =\?UTF-8\?Q\?prepend1=0A=0A\?=\r\nX-Hello: =\?UTF-8\?Q\?World=E2=88=97\?=\r\nReturn-Path: /, $msg1);
    $self->assert_matches(qr/X-Cassandane-Unique: .*\r\nX-Cassandane-Test: append1\r\nX-Cassandane-Test: append3\r\nX-Cassandane-Test: append5\r\n\r\n/, $msg1);

    $imaptalk->select($target);
    $res = $imaptalk->fetch(1, 'rfc822');

    $msg1 = $res->{1}->{rfc822};

    $self->assert_matches(qr/^X-Hello: =\?UTF-8\?Q\?World=E2=88=97\?=\r\nReturn-Path: /, $msg1);
    $self->assert_matches(qr/X-Cassandane-Unique: .*\r\n\r\n/, $msg1);
}

sub test_editheader_encoded_address_list
    :min_version_3_3
    :needs_component_sieve
{
    my ($self) = @_;

    xlog $self, "Install a sieve script with editheader actions";
    my $script = <<EOF;
require ["editheader", "encoded-character", "variables"];
if header :matches "To" "*bbb\@example.com*" {
  deleteheader "To";
  addheader :last "To" "\${1}\${unicode:0022}BBB\${unicode:0022} <bbb\@example.net>\${2}";
}
addheader :last "X-Foo" "must encode star (\${unicode:2217})";
addheader :last "X-Bar" "don't need to encode this";
addheader :last "X-Blah" "can encode <ddd\@example.com> in non-list \${unicode:2217}";
EOF

    $script =~ s/\r?\n/\r\n/gs;
    $script =~ s/\\/\\\\/gs;

    $self->{instance}->install_sieve_script($script);

    xlog $self, "Deliver a matching message";
    my $msg1 = $self->{gen}->generate(
        subject => "Message 1",
        extra_headers => [['To', '"=?UTF-8?Q?=E2=88=97?=" <aaa@example.com>, bbb@example.com, ccc@example.com']
        ],
    );
    $self->{instance}->deliver($msg1);

    my $imaptalk = $self->{store}->get_client();
    $imaptalk->select("INBOX");
    my $res = $imaptalk->fetch(1, 'rfc822');

    $msg1 = $res->{1}->{rfc822};

    $self->assert_matches(qr/To: =\?UTF-8\?Q\?=22=E2=88=97=22\?= <aaa\@example.com>,\s+"BBB" <bbb\@example.net>,\s+ccc\@example.com\r\n/, $msg1);
    $self->assert_matches(qr/X-Foo: =\?UTF-8\?Q\?must_encode_star_\(=E2=88=97\)\?=\r\n/, $msg1);
    $self->assert_matches(qr/X-Bar: don't need to encode this\r\n/, $msg1);
    $self->assert_matches(qr/X-Blah: =\?UTF-8\?Q\?can_encode_<ddd\@example.com>_in_non-list_=E2=88=97\?=\r\n\r\n/, $msg1);

}

sub test_duplicate
    :min_version_3_1
    :needs_component_sieve
{
    my ($self) = @_;

    xlog $self, "Install a sieve script with a duplicate check";
    $self->{instance}->install_sieve_script(<<EOF
require ["duplicate", "variables"];
if allof (header :matches "subject" "ALERT: *",
          duplicate :seconds 3 :last :uniqueid "${1}") {
    discard;
}
EOF
    );

    xlog $self, "Deliver a message";
    # This message sets the duplicate tracking entry
    my $msg1 = $self->{gen}->generate(subject => "ALERT: server down");
    $self->{instance}->deliver($msg1);

    xlog $self, "Deliver second message";
    # This message should be discarded
    my $msg2 = $self->{gen}->generate(subject => "ALERT: server down");
    $self->{instance}->deliver($msg2);

    xlog $self, "Deliver third message";
    # This message should be discarded
    my $msg3 = $self->{gen}->generate(subject => "ALERT: server down");
    $self->{instance}->deliver($msg3);

    sleep 3;
    xlog $self, "Deliver fourth message";
    # This message should be delivered (after the expire time)
    my $msg4 = $self->{gen}->generate(subject => "ALERT: server down");
    $self->{instance}->deliver($msg4);

    xlog $self, "Deliver fifth message";
    # This message should be discarded
    my $msg5 = $self->{gen}->generate(subject => "ALERT: server down");
    $self->{instance}->deliver($msg5);

    my $imaptalk = $self->{store}->get_client();
    $imaptalk->select("INBOX");

    $self->assert_num_equals(2, $imaptalk->get_response_code('exists'));
}

sub test_ereject
    :min_version_3_1
    :needs_component_sieve
{
    my ($self) = @_;

    xlog $self, "Install a sieve script rejecting all mail";
    $self->{instance}->install_sieve_script(<<EOF
require ["ereject"];
ereject "Go away!";
EOF
    );

    xlog $self, "Attempt to deliver a message";
    my $msg1 = $self->{gen}->generate(subject => "Message 1");
    my $res = $self->{instance}->deliver($msg1);

    # should fail to deliver
    $self->assert_num_not_equals(0, $res);

    # should NOT appear in INBOX
    my $imaptalk = $self->{store}->get_client();
    $imaptalk->select("INBOX");
    $self->assert_num_equals(0, $imaptalk->get_response_code('exists'));
}

sub test_specialuse_exists
    :min_version_3_1
    :needs_component_sieve
    :NoAltNameSpace
{
    my ($self) = @_;

    xlog $self, "Testing the \"specialuse_exists\" test";

    my $talk = $self->{store}->get_client();

    my $hitfolder = "INBOX.newfolder";
    my $testfolder = "INBOX.testfolder";
    my $missfolder = "INBOX";

    xlog $self, "Install the sieve script";
    my $scriptname = 'flatPack';
    $self->{instance}->install_sieve_script(<<EOF
require ["fileinto", "special-use"];
if specialuse_exists "\\\\Junk" {
    fileinto "$hitfolder";
}
EOF
    );

    $talk->create($hitfolder);

    my %uid = ($hitfolder => 1, $missfolder => 1);
    my %exp;
    xlog $self, "Deliver a message";
    {
        my $msg = $self->{gen}->generate(subject => "msg1");
        $msg->set_attribute(uid => $uid{$missfolder});
        $uid{$missfolder}++;
        $self->{instance}->deliver($msg);
        $exp{$missfolder}->{"msg1"} = $msg;
    }

    xlog $self, "Create the test folder";
    $talk->create($testfolder, "(USE (\\Junk))");

    xlog $self, "Deliver a message now that the folder exists";
    {
        my $msg = $self->{gen}->generate(subject => "msg2");
        $msg->set_attribute(uid => $uid{$hitfolder});
        $uid{$hitfolder}++;
        $self->{instance}->deliver($msg);
        $exp{$hitfolder}->{"msg2"} = $msg;
    }

    xlog $self, "Check that the messages made it";
    foreach my $folder (keys %exp)
    {
        $self->{store}->set_folder($folder);
        $self->check_messages($exp{$folder}, check_guid => 0);
    }
}

sub test_specialuse
    :min_version_3_1
    :needs_component_sieve
    :NoAltNameSpace
{
    my ($self) = @_;

    xlog $self, "Testing the \":specialuse\" argument";

    my $hitfolder = "INBOX.newfolder";
    my $missfolder = "INBOX";

    xlog $self, "Install the sieve script";
    my $scriptname = 'flatPack';
    $self->{instance}->install_sieve_script(<<EOF
require ["fileinto", "special-use"];
fileinto :specialuse "\\\\Junk" "$missfolder";
EOF
    );

    xlog $self, "Create the hit folder";
    my $talk = $self->{store}->get_client();
    $talk->create($hitfolder, "(USE (\\Junk))");

    xlog $self, "Deliver a message now that the folder exists";
    my $msg = $self->{gen}->generate(subject => "msg1");
    $self->{instance}->deliver($msg);

    xlog $self, "Check that the message made it";
    $talk->select($hitfolder);
    $self->assert_num_equals(1, $talk->get_response_code('exists'));
}

sub test_specialuse_create
    :min_version_3_1
    :needs_component_sieve
{
    my ($self) = @_;

    xlog $self, "Testing the \":specialuse\" + \":create\" arguments";

    my $hitfolder = "INBOX.newfolder";

    xlog $self, "Install the sieve script";
    my $scriptname = 'flatPack';
    $self->{instance}->install_sieve_script(<<EOF
require ["fileinto", "special-use", "mailbox"];
fileinto :specialuse "\\\\Junk" :create "$hitfolder";
EOF
    );

    xlog $self, "Deliver a message";
    my $msg = $self->{gen}->generate(subject => "msg1");
    $self->{instance}->deliver($msg);

    xlog $self, "Check that the message made it";
    my $talk = $self->{store}->get_client();
    $talk->select($hitfolder);
    $self->assert_num_equals(1, $talk->get_response_code('exists'));
}

sub test_vacation_with_fcc
    :min_version_3_1
    :needs_component_sieve
    :NoAltNameSpace
{
    my ($self) = @_;

    my $target = "INBOX.Sent";

    xlog $self, "Install a sieve script with vacation action that uses :fcc";
    $self->{instance}->install_sieve_script(<<'EOF'
require ["vacation", "fcc"];

vacation :fcc "INBOX.Sent" :days 1 :addresses ["cassandane@example.com"] text:
I am out of the office today. I will answer your email as soon as I can.
.
;
EOF
    );

    xlog $self, "Create the target folder";
    my $talk = $self->{store}->get_client();
    $talk->create($target, "(USE (\\Sent))");

    xlog $self, "Deliver a message";
    my $msg1 = $self->{gen}->generate(subject => "Message 1",
                                      to => Cassandane::Address->new(localpart => 'cassandane', domain => 'example.com'));
    $self->{instance}->deliver($msg1);

    xlog $self, "Check that a copy of the auto-reply message made it";
    $talk->select($target);
    $self->assert_num_equals(1, $talk->get_response_code('exists'));

    xlog $self, "Check that the message is an auto-reply";
    my $res = $talk->fetch(1, 'rfc822');
    my $msg2 = $res->{1}->{rfc822};

    $self->assert_matches(qr/Subject: Auto:(?:\r\n)? Message 1\r\n/ms, $msg2);
    $self->assert_matches(qr/Auto-Submitted: auto-replied \(vacation\)\r\n/, $msg2);
    $self->assert_matches(qr/\r\n\r\nI am out of the office today./, $msg2);
}

sub test_vacation_with_fcc_specialuse
    :min_version_3_1
    :needs_component_sieve
    :NoAltNameSpace
{
    my ($self) = @_;

    my $target = "INBOX.Sent";

    xlog $self, "Install a sieve script with vacation action that uses :fcc";
    $self->{instance}->install_sieve_script(<<'EOF'
require ["vacation", "fcc", "special-use"];

vacation :fcc "INBOX" :specialuse "\\Sent" :days 1 :addresses ["cassandane@example.com"] text:
I am out of the office today. I will answer your email as soon as I can.
.
;
EOF
    );

    xlog $self, "Create the target folder";
    my $talk = $self->{store}->get_client();
    $talk->create($target, "(USE (\\Sent))");

    xlog $self, "Deliver a message";
    my $msg1 = $self->{gen}->generate(subject => "Message 1",
                                      to => Cassandane::Address->new(localpart => 'cassandane', domain => 'example.com'));
    $self->{instance}->deliver($msg1);

    xlog $self, "Check that a copy of the auto-reply message made it";
    $talk->select($target);
    $self->assert_num_equals(1, $talk->get_response_code('exists'));

    xlog $self, "Check that the message is an auto-reply";
    my $res = $talk->fetch(1, 'rfc822');
    my $msg2 = $res->{1}->{rfc822};

    $self->assert_matches(qr/Subject: Auto:(?:\r\n)? Message 1\r\n/ms, $msg2);
    $self->assert_matches(qr/Auto-Submitted: auto-replied \(vacation\)\r\n/, $msg2);
    $self->assert_matches(qr/\r\n\r\nI am out of the office today./, $msg2);
}

sub test_vacation_with_explicit_subject
    :min_version_3_1
    :needs_component_sieve
    :NoAltNameSpace
{
    my ($self) = @_;

    my $target = "INBOX.Sent";

    xlog $self, "Install a sieve script with explicit vacation subject";
    $self->{instance}->install_sieve_script(<<'EOF'
require ["vacation", "fcc"];

vacation :fcc "INBOX.Sent" :days 1 :addresses ["cassandane@example.com"] :subject "Boo" text:
I am out of the office today. I will answer your email as soon as I can.
.
;
EOF
    );

    xlog $self, "Create the target folder";
    my $talk = $self->{store}->get_client();
    $talk->create($target, "(USE (\\Sent))");

    xlog $self, "Deliver a message";
    my $msg1 = $self->{gen}->generate(subject => "Message 1",
                                      to => Cassandane::Address->new(localpart => 'cassandane', domain => 'example.com'));
    $self->{instance}->deliver($msg1);

    xlog $self, "Check that a copy of the auto-reply message made it";
    $talk->select($target);
    $self->assert_num_equals(1, $talk->get_response_code('exists'));

    xlog $self, "Check that the message is an auto-reply";
    my $res = $talk->fetch(1, 'rfc822');
    my $msg2 = $res->{1}->{rfc822};

    $self->assert_matches(qr/Subject: Boo\r\n/ms, $msg2);
    $self->assert_matches(qr/Auto-Submitted: auto-replied \(vacation\)\r\n/, $msg2);
    $self->assert_matches(qr/\r\n\r\nI am out of the office today./, $msg2);

#    use Data::Dumper;
#    warn Dumper($msg2);
}

sub test_vacation_with_long_origsubject
    :min_version_3_1
    :needs_component_sieve
    :NoAltNameSpace
{
    my ($self) = @_;

    my $target = 'INBOX.Sent';

    xlog $self, "Install a sieve script with vacation action that uses :fcc";
    $self->{instance}->install_sieve_script(<<"EOF"
require ["vacation", "fcc"];

vacation :fcc "$target" :days 1 :addresses ["cassandane\@example.com"] text:
I am out of the office today. I will answer your email as soon as I can.
.
;
EOF
    );

    xlog $self, "Create the target folder";
    my $talk = $self->{store}->get_client();
    $talk->create($target, "(USE (\\Sent))");

    xlog $self, "Deliver a message";
    # should end up folding a couple of times
    my $subject = "volutpat diam ut venenatis tellus in metus "
                . "vulputate eu scelerisque felis imperdiet proin "
                . "fermentum leo vel orci portad non pulvinar neque "
                . "laoreet suspendisse interdum consectetur";

    my $msg1 = $self->{gen}->generate(
        subject => $subject,
        to => Cassandane::Address->new(localpart => 'cassandane',
                                       domain => 'example.com'));
    $self->{instance}->deliver($msg1);

    xlog $self, "Check that a copy of the auto-reply message made it";
    $talk->select($target);
    $self->assert_num_equals(1, $talk->get_response_code('exists'));

    xlog $self, "Check that the message is an auto-reply";
    my $res = $talk->fetch(1, 'rfc822');
    my $msg2 = $res->{1}->{rfc822};

    my $subjpat = $subject =~ s/ /(?:\r\n)? /gr;
    my $subjre = qr{Subject:\r\n Auto: $subjpat};

    # subject should be the original subject plus "\r\n Auto: " and folding
    $self->assert_matches($subjre, $msg2);

    # check we folded a reasonable number of times
    my $actual_subject;
    if ($msg2 =~ m/^(Subject:.*?\r\n)(?!\s)/ms) {
        $actual_subject = $1;
    }
    $self->assert_matches(qr/^Subject:/, $actual_subject);
    my $fold_count = () = $actual_subject =~ m/\r\n /g;
    xlog "fold count: $fold_count";
    $self->assert_num_gte(2, $fold_count);
    $self->assert_num_lte(4, $fold_count);

    # check for auto-submitted header
    $self->assert_matches(qr/Auto-Submitted: auto-replied \(vacation\)\r\n/, $msg2);
    $self->assert_matches(qr/\r\n\r\nI am out of the office today./, $msg2);
}

sub test_vacation_with_long_encoded_origsubject
    :min_version_3_1
    :needs_component_sieve
    :NoAltNameSpace
{
    my ($self) = @_;

    my $target = 'INBOX.Sent';

    xlog $self, "Install a sieve script with vacation action that uses :fcc";
    $self->{instance}->install_sieve_script(<<"EOF"
require ["vacation", "fcc"];

vacation :fcc "$target" :days 1 :addresses ["cassandane\@example.com"] text:
I am out of the office today. I will answer your email as soon as I can.
.
;
EOF
    );

    xlog $self, "Create the target folder";
    my $talk = $self->{store}->get_client();
    $talk->create($target, "(USE (\\Sent))");

    xlog $self, "Deliver a message";
    # should end up refolding a couple of times
    my $subject = "=?UTF-8?Q?=E3=83=86=E3=82=B9=E3=83=88=E3=83=A1=E3=83=83=E3=82=BB=E3=83=BC?=\r\n"
        . " =?UTF-8?Q?=E3=82=B8=E3=80=81=E7=84=A1=E8=A6=96=E3=81=97=E3=81=A6=E3=81=8F?=\r\n"
        . " =?UTF-8?Q?=E3=81=A0=E3=81=95=E3=81=84?=";

    my $msg1 = $self->{gen}->generate(
        subject => $subject,
        to => Cassandane::Address->new(localpart => 'cassandane',
                                       domain => 'example.com'));
    $self->{instance}->deliver($msg1);

    xlog $self, "Check that a copy of the auto-reply message made it";
    $talk->select($target);
    $self->assert_num_equals(1, $talk->get_response_code('exists'));

    xlog $self, "Check that the message is an auto-reply";
    my $res = $talk->fetch(1, 'rfc822');
    my $msg2 = $res->{1}->{rfc822};

    # check we folded a reasonable number of times
    my $actual_subject;
    if ($msg2 =~ m/^(Subject:.*?\r\n)(?!\s)/ms) {
        $actual_subject = $1;
    }
    $self->assert_matches(qr/^Subject:/, $actual_subject);
    my $fold_count = () = $actual_subject =~ m/\r\n /g;
    xlog "fold count: $fold_count";
    $self->assert_num_gte(2, $fold_count);
    $self->assert_num_lte(4, $fold_count);

    # subject should be the original subject plus "Auto: " and CRLF
    if (version->parse($Encode::MIME::Header::VERSION)
        < version->parse("2.28")) {
        # XXX Work around a bug in older Encode::MIME::Header
        # XXX (https://rt.cpan.org/Public/Bug/Display.html?id=42902)
        # XXX that loses the space between 'Subject:' and 'Auto:',
        # XXX by allowing it to be optional
        my $subjpat = "Auto: " . decode("MIME-Header", $subject) . "\r\n";
        my $subjre = qr/Subject:\s?$subjpat/;
        $self->assert_matches($subjre, decode("MIME-Header", $actual_subject));
    }
    else {
        my $subjpat = "Subject: Auto: "
                    . decode("MIME-Header", $subject) . "\r\n";
        $self->assert_str_equals($subjpat,
                                 decode("MIME-Header", $actual_subject));
    }

    # check for auto-submitted header
    $self->assert_matches(qr/Auto-Submitted: auto-replied \(vacation\)\r\n/, $msg2);
    $self->assert_matches(qr/\r\n\r\nI am out of the office today./, $msg2);
}

sub test_vacation_with_nonfoldable_origsubject
    :min_version_3_5
    :needs_component_sieve
    :NoAltNameSpace
{
    my ($self) = @_;

    my $target = 'INBOX.Sent';

    xlog $self, "Install a sieve script with vacation action that uses :fcc";
    $self->{instance}->install_sieve_script(<<"EOF"
require ["vacation", "fcc"];

vacation :fcc "$target" :days 1 :addresses ["cassandane\@example.com"] text:
I am out of the office today. I will answer your email as soon as I can.
.
;
EOF
    );

    xlog $self, "Create the target folder";
    my $talk = $self->{store}->get_client();
    $talk->create($target, "(USE (\\Sent))");

    xlog $self, "Deliver a message";
    # runs more than 75c without whitespace!
    my $subject = "volutpatdiamutvenenatistellusinmetus"
                . "vulputateeuscelerisquefelisimperdietproin"
                . "fermentumleovelorciportanonpulvinarneque"
                . "laoreetsuspendisseinterdumconsectetur";

    my $msg1 = $self->{gen}->generate(
        subject => $subject,
        to => Cassandane::Address->new(localpart => 'cassandane',
                                       domain => 'example.com'));
    $self->{instance}->deliver($msg1);

    xlog $self, "Check that a copy of the auto-reply message made it";
    $talk->select($target);
    $self->assert_num_equals(1, $talk->get_response_code('exists'));

    xlog $self, "Check that the message is an auto-reply";
    my $res = $talk->fetch(1, 'rfc822');
    my $msg2 = $res->{1}->{rfc822};

    # check we folded a reasonable number of times
    my $actual_subject;
    if ($msg2 =~ m/^(Subject:.*?\r\n)(?!\s)/ms) {
        $actual_subject = $1;
    }
    $self->assert_matches(qr/^Subject:/, $actual_subject);
    my $fold_count = () = $actual_subject =~ m/\r\n /g;
    xlog "fold count: $fold_count";
    $self->assert_num_gte(2, $fold_count);
    $self->assert_num_lte(4, $fold_count);

    # subject should be the original subject plus "Auto: " and CRLF
    if (version->parse($Encode::MIME::Header::VERSION)
        < version->parse("2.28")) {
        # XXX Work around a bug in older Encode::MIME::Header
        # XXX (https://rt.cpan.org/Public/Bug/Display.html?id=42902)
        # XXX that loses the space between 'Subject:' and 'Auto:',
        # XXX by allowing it to be optional
        my $subjpat = "Auto: " . decode("MIME-Header", $subject) . "\r\n";
        my $subjre = qr/Subject:\s?$subjpat/;
        $self->assert_matches($subjre, decode("MIME-Header", $actual_subject));
    }
    else {
        my $subjpat = "Subject: Auto: "
                    . decode("MIME-Header", $subject) . "\r\n";
        $self->assert_str_equals($subjpat,
                                 decode("MIME-Header", $actual_subject));
    }

    # check for auto-submitted header
    $self->assert_matches(qr/Auto-Submitted: auto-replied \(vacation\)\r\n/, $msg2);
    $self->assert_matches(qr/\r\n\r\nI am out of the office today./, $msg2);
}

sub test_github_issue_complex_variables
    :min_version_3_1
    :needs_component_sieve
{
    my ($self) = @_;

    xlog $self, "Install a sieve script with complex variable work";
    $self->{instance}->install_sieve_script(<<'EOF');
require ["fileinto", "reject", "vacation", "notify", "envelope", "body", "relational", "regex", "subaddress", "copy", "mailbox", "mboxmetadata", "servermetadata", "date", "index", "comparator-i;ascii-numeric", "variables", "imap4flags", "editheader", "duplicate", "vacation-seconds"];

### BEGIN USER SIEVE
### GitHub
if allof (
  address :is :domain "Message-ID" "github.com",
  address :regex :localpart "Message-ID" "^([^/]*)/([^/]*)/(pull|issues|issue|commit)/(.*)"
) {
  # Message-IDs:

  set :lower "org" "${1}";
  set :lower "repo" "${2}";
  set :lower "type" "${3}";
  set "tail" "${4}";
  if anyof(
    string :matches "${org}/${repo}" "foo/bar*",
    string :is "${org}" ["foo", "bar", "baz"]
  ) {
    set "ghflags" "";

    # Mark all issue events as seen.
    if address :regex :localpart "Message-ID" "^[^/]+/[^/]+/(pull|issue)/[^/]+/issue_event/" {
      addflag "ghflags" "\\Seen";
      set "type" "issues";
    }

    # Flag comments on things I authored
    if header :is ["X-GitHub-Reason"] "author" {
      addflag "ghflags" "\\Flagged";
    }

    if string :matches "${org}/${repo}" "foo/bar*" {
      # change the mailbox name for foo emails
      set "org" "foo";
      if string :matches "${repo}" "foo-corelibs-*" {
        set "repo" "${1}";
      } elsif string :matches "${repo}" "foo-*" {
        set "repo" "${1}";
      }
    }
    set "mbprefix" "INBOX.GitHub.${org}.${repo}";

    if string :is "${type}" "pull" {
      # PRs
      set "mbname" "${mbprefix}.pulls";
    } elsif string :is "${type}" "issues" {
      # Issues
      set "mbname" "${mbprefix}.issues";
    } elsif string :is "${type}" "commit" {
      # Commit comments
      set "mbname" "${mbprefix}.comments";
      # Disable replies sorting
      set "tail" "";
    } else {
      set "mbname" "${mbprefix}.unknown";
    }

    if string :matches "${tail}" "*/*" {
      set "oldmbname" "${mbname}";
      set "mbname" "${oldmbname}.replies";
    }

    if header :is ["X-GitHub-Reason"] ["subscribed", "push"] {
      fileinto :create :flags "${ghflags}" "${mbname}";
    } else {
      fileinto :create :copy :flags "${ghflags}" "${mbname}";
    }
  }
}
EOF

    my $raw = << 'EOF';
Date: Wed, 16 May 2018 22:06:18 -0700
From: Some Person <notifications@github.com>
To: foo/bar <bar@noreply.github.com>
Cc: Subscribed <subscribed@noreply.github.com>
Message-ID: <foo/bar/pull/1234/abcdef01234@github.com>
X-GitHub-Reason: subscribed

foo bar
EOF
    xlog $self, "Deliver a message";
    my $msg1 = Cassandane::Message->new(raw => $raw);
    $self->{instance}->deliver($msg1);

    # if there's a delivery failure, it will be in the Inbox
    xlog $self, "Check there there are no messages in the Inbox";
    my $talk = $self->{store}->get_client();
    $talk->select("INBOX");
    $self->assert_num_equals(0, $talk->get_response_code('exists'));

    # if there's no delivery failure, this folder will be created!
    $talk->select("INBOX.GitHub.foo.bar.pulls.replies");
    $self->assert_num_equals(1, $talk->get_response_code('exists'));
}

sub test_discard_match_on_body_raw
    :needs_component_sieve
{
    my ($self) = @_;

    xlog $self, "Install the sieve script";
    $self->{instance}->install_sieve_script(<<EOF
require ["body"];

if body :raw :contains "One-Click Additions" {
  discard;
  stop;
}
EOF
    );

    my $raw = << 'EOF';
Date: Wed, 16 May 2018 22:06:18 -0700
From: Some Person <some@person.com>
To: foo/bar <foo@bar.com>
Message-ID: <fake.1528862927.58376@person.com>
Subject: Confirmation of your order
MIME-Version: 1.0
Content-Type: multipart/mixed;
  boundary="----=_Part_91374_1856076643.1527870431792"

------=_Part_91374_1856076643.1527870431792
Content-Type: multipart/alternative;
  boundary="----=_Part_91373_1043761677.1527870431791"

------=_Part_91373_1043761677.1527870431791
Content-Type: text/plain; charset=utf-8
Content-Transfer-Encoding: quoted-printable

Dear Mr Foo Bar,

Thank you for using Blah to do your shopping.


ORDER DETAILS=20
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D

One-Click Additions
-------------------
1 Oven Pride Oven Cleaning System

Total (estimated):             777.70 GBP
Note: The total cost is estimated because some of the items you might have =
ordered, such as meat and cheese, are sold by weight. The exact cost will b=
e shown on your receipt when your order is delivered. This cost includes th=
e delivery charge if any.


CHANGING YOUR ORDER
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
If you want to change any items on your order or change the delivery, simpl=
y go to www.blah.com and the Orders page; from here, click on the order re=
ference number and make the appropriate changes.

The last time you can change this order is: 17:40 on 1st June 2018.


ICALENDAR EMAIL ATTACHMENTS
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D
Order confirmation emails have an ICalendar event file attached to help you.

YOUR COMPLETE SATISFACTION
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D
We want to make sure that you are completely satisfied with your Blah deli=
very; if for any reason you are not, then please advise the Customer Servic=
es Team Member at the door and they will ensure that any issues are resolve=
d for you.

Thank you for shopping with BLAH.
Yours sincerely,

BLAH Customer Service Team

------=_Part_91373_1043761677.1527870431791
Content-Type: text/html; charset=utf-8
Content-Transfer-Encoding: quoted-printable

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
<html>
</html>

------=_Part_91373_1043761677.1527870431791--

------=_Part_91374_1856076643.1527870431792
Content-Type: text/calendar; charset=us-ascii; name=BlahDelivery.ics
Content-Transfer-Encoding: 7bit
Content-Disposition: attachment; filename=BlahDelivery.ics

BEGIN:VCALENDAR
VERSION:2.0
CALSCALE:GREGORIAN
METHOD:PUBLISH
BEGIN:VTIMEZONE
TZID:Europe/London
LAST-MODIFIED:20180601T172711
BEGIN:STANDARD
DTSTART:20071028T010000
RRULE:FREQ=YEARLY;BYDAY=-1SU;BYMONTH=10
TZOFFSETTO:+0000
TZOFFSETFROM:+0100
TZNAME:GMT
END:STANDARD
BEGIN:DAYLIGHT
DTSTART:20070325T010000
RRULE:FREQ=YEARLY;BYDAY=-1SU;BYMONTH=3
TZOFFSETTO:+0100
TZOFFSETFROM:+0000
TZNAME:BST
END:DAYLIGHT
END:VTIMEZONE
BEGIN:VEVENT
LOCATION:Home
DTSTAMP:20180601T172711
UID:36496743@foo.com
LAST-MODIFIED:20180601T172711
SEQUENCE:1
DTSTART;TZID=Europe/London:20180602T080000
SUMMARY:Blah delivery
DTEND;TZID=Europe/London:20180602T090000
DESCRIPTION:
END:VEVENT
END:VCALENDAR
------=_Part_91374_1856076643.1527870431792--
EOF
    xlog $self, "Deliver a message";
    my $msg1 = Cassandane::Message->new(raw => $raw);
    $self->{instance}->deliver($msg1);

    # should fail to deliver and NOT appear in INBOX
    my $imaptalk = $self->{store}->get_client();
    $imaptalk->select("INBOX");
    $self->assert_num_equals(0, $imaptalk->get_response_code('exists'));
}

sub test_discard_match_on_body_text
    :needs_component_sieve
{
    my ($self) = @_;

    xlog $self, "Install the sieve script";
    $self->{instance}->install_sieve_script(<<EOF
require ["body"];

if body :text :contains "One-Click Additions" {
  discard;
  stop;
}
EOF
    );

    my $raw = << 'EOF';
Date: Wed, 16 May 2018 22:06:18 -0700
From: Some Person <some@person.com>
To: foo/bar <foo@bar.com>
Message-ID: <fake.1528862927.58376@person.com>
Subject: Confirmation of your order
MIME-Version: 1.0
Content-Type: multipart/mixed;
  boundary="----=_Part_91374_1856076643.1527870431792"

------=_Part_91374_1856076643.1527870431792
Content-Type: multipart/alternative;
  boundary="----=_Part_91373_1043761677.1527870431791"

------=_Part_91373_1043761677.1527870431791
Content-Type: text/plain; charset=utf-8
Content-Transfer-Encoding: quoted-printable

Dear Mr Foo Bar,

Thank you for using Blah to do your shopping.


ORDER DETAILS=20
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D

One-Click Additions
-------------------
1 Oven Pride Oven Cleaning System

Total (estimated):             777.70 GBP
Note: The total cost is estimated because some of the items you might have =
ordered, such as meat and cheese, are sold by weight. The exact cost will b=
e shown on your receipt when your order is delivered. This cost includes th=
e delivery charge if any.


CHANGING YOUR ORDER
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
If you want to change any items on your order or change the delivery, simpl=
y go to www.blah.com and the Orders page; from here, click on the order re=
ference number and make the appropriate changes.

The last time you can change this order is: 17:40 on 1st June 2018.


ICALENDAR EMAIL ATTACHMENTS
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D
Order confirmation emails have an ICalendar event file attached to help you.

YOUR COMPLETE SATISFACTION
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D
We want to make sure that you are completely satisfied with your Blah deli=
very; if for any reason you are not, then please advise the Customer Servic=
es Team Member at the door and they will ensure that any issues are resolve=
d for you.

Thank you for shopping with BLAH.
Yours sincerely,

BLAH Customer Service Team

------=_Part_91373_1043761677.1527870431791
Content-Type: text/html; charset=utf-8
Content-Transfer-Encoding: quoted-printable

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
<html>
</html>

------=_Part_91373_1043761677.1527870431791--

------=_Part_91374_1856076643.1527870431792
Content-Type: text/calendar; charset=us-ascii; name=BlahDelivery.ics
Content-Transfer-Encoding: 7bit
Content-Disposition: attachment; filename=BlahDelivery.ics

BEGIN:VCALENDAR
VERSION:2.0
CALSCALE:GREGORIAN
METHOD:PUBLISH
BEGIN:VTIMEZONE
TZID:Europe/London
LAST-MODIFIED:20180601T172711
BEGIN:STANDARD
DTSTART:20071028T010000
RRULE:FREQ=YEARLY;BYDAY=-1SU;BYMONTH=10
TZOFFSETTO:+0000
TZOFFSETFROM:+0100
TZNAME:GMT
END:STANDARD
BEGIN:DAYLIGHT
DTSTART:20070325T010000
RRULE:FREQ=YEARLY;BYDAY=-1SU;BYMONTH=3
TZOFFSETTO:+0100
TZOFFSETFROM:+0000
TZNAME:BST
END:DAYLIGHT
END:VTIMEZONE
BEGIN:VEVENT
LOCATION:Home
DTSTAMP:20180601T172711
UID:36496743@foo.com
LAST-MODIFIED:20180601T172711
SEQUENCE:1
DTSTART;TZID=Europe/London:20180602T080000
SUMMARY:Blah delivery
DTEND;TZID=Europe/London:20180602T090000
DESCRIPTION:
END:VEVENT
END:VCALENDAR
------=_Part_91374_1856076643.1527870431792--
EOF
    xlog $self, "Deliver a message";
    my $msg1 = Cassandane::Message->new(raw => $raw);
    $self->{instance}->deliver($msg1);

    # should fail to deliver and NOT appear in INBOX
    my $imaptalk = $self->{store}->get_client();
    $imaptalk->select("INBOX");
    $self->assert_num_equals(0, $imaptalk->get_response_code('exists'));
}

sub test_fileinto_mailboxidexists
    :min_version_3_1
    :needs_component_sieve
{
    my ($self) = @_;

    xlog $self, "Testing the \"mailboxidexists\" test";

    my $talk = $self->{store}->get_client();

    my $hitfolder = "INBOX.newfolder";
    my $missfolder = "INBOX";

    my $testfolder = "INBOX.testfolder";

    xlog $self, "Install the sieve script";
    my $scriptname = 'flatPack';
    $self->{instance}->install_sieve_script(<<EOF
require ["fileinto", "mailboxid"];
if mailboxidexists "not-a-real-mailboxid"  {
    fileinto "$hitfolder";
}
EOF
    );

    $talk->create($hitfolder);

    my %uid = ($hitfolder => 1, $missfolder => 1);
    my %exp;
    xlog $self, "Deliver a message";
    {
        my $msg = $self->{gen}->generate(subject => "msg1");
        $msg->set_attribute(uid => $uid{$missfolder});
        $uid{$missfolder}++;
        $self->{instance}->deliver($msg);
        $exp{$missfolder}->{"msg1"} = $msg;
    }

    xlog $self, "Create the test folder";
    $talk->create($testfolder);
    my $res = $talk->status($testfolder, ['mailboxid']);
    my $id = $res->{mailboxid}[0];

    $self->{instance}->install_sieve_script(<<EOF
require ["fileinto", "mailboxid"];
if mailboxidexists "$id"  {
    fileinto "$hitfolder";
}
EOF
    );

    xlog $self, "Deliver a message now that the folder exists";
    {
        my $msg = $self->{gen}->generate(subject => "msg2");
        $msg->set_attribute(uid => $uid{$hitfolder});
        $uid{$hitfolder}++;
        $self->{instance}->deliver($msg);
        $exp{$hitfolder}->{"msg2"} = $msg;
    }

    xlog $self, "Delete the test folder";
    $talk->delete($testfolder);

    xlog $self, "Deliver a message now that the folder doesn't exist";
    {
        my $msg = $self->{gen}->generate(subject => "msg3");
        $msg->set_attribute(uid => $uid{$missfolder});
        $uid{$missfolder}++;
        $self->{instance}->deliver($msg);
        $exp{$missfolder}->{"msg3"} = $msg;
    }

    xlog $self, "Check that the messages made it";
    foreach my $folder (keys %exp)
    {
        $self->{store}->set_folder($folder);
        $self->check_messages($exp{$folder}, check_guid => 0);
    }
}

sub test_fileinto_mailboxid
    :min_version_3_1
    :needs_component_sieve
{
    my ($self) = @_;

    xlog $self, "Testing the \"mailboxid\" action";

    my $talk = $self->{store}->get_client();

    my $hitfolder = "INBOX.newfolder";
    my $missfolder = "INBOX.testfolder";

    xlog $self, "Install the sieve script";
    my $scriptname = 'flatPack';
    $self->{instance}->install_sieve_script(<<EOF
require ["fileinto", "mailboxid"];
fileinto :mailboxid "does-not-exist" "$missfolder";

EOF
    );

    $talk->create($hitfolder);
    $talk->create($missfolder);

    my %uid = ($hitfolder => 1, $missfolder => 1);
    my %exp;
    xlog $self, "Deliver a message";
    {
        my $msg = $self->{gen}->generate(subject => "msg1");
        $msg->set_attribute(uid => $uid{$missfolder});
        $uid{$missfolder}++;
        $self->{instance}->deliver($msg);
        $exp{$missfolder}->{"msg1"} = $msg;
    }

    my $res = $talk->status($hitfolder, ['mailboxid']);
    my $id = $res->{mailboxid}[0];

    $self->{instance}->install_sieve_script(<<EOF
require ["fileinto", "mailboxid"];
fileinto :mailboxid "$id" "$missfolder";
EOF
    );

    xlog $self, "Deliver a message now that the folder exists";
    {
        my $msg = $self->{gen}->generate(subject => "msg2");
        $msg->set_attribute(uid => $uid{$hitfolder});
        $uid{$hitfolder}++;
        $self->{instance}->deliver($msg);
        $exp{$hitfolder}->{"msg2"} = $msg;
    }

    xlog $self, "Check that the messages made it";
    foreach my $folder (keys %exp)
    {
        $self->{store}->set_folder($folder);
        $self->check_messages($exp{$folder}, check_guid => 0);
    }

    xlog $self, "Delete the target folder";
    $talk->delete($hitfolder);

    xlog $self, "Deliver a message now that the folder doesn't exist";
    {
        my $msg = $self->{gen}->generate(subject => "msg3");
        $msg->set_attribute(uid => $uid{$missfolder});
        $uid{$missfolder}++;
        $self->{instance}->deliver($msg);
        $exp{$missfolder}->{"msg3"} = $msg;
    }

    xlog $self, "Check that the message made it to miss folder";
    $self->{store}->set_folder($missfolder);
    $self->check_messages($exp{$missfolder}, check_guid => 0);
}

sub test_fileinto_mailboxid_variable
    :min_version_3_5
    :needs_component_sieve
{
    my ($self) = @_;

    xlog $self, "Testing the \"mailboxid\" action";

    my $talk = $self->{store}->get_client();

    my $hitfolder = "INBOX.newfolder";
    my $missfolder = "INBOX.testfolder";

    xlog $self, "Install the sieve script";
    my $scriptname = 'flatPack';
    $self->{instance}->install_sieve_script(<<EOF
require ["fileinto", "mailboxid"];
fileinto :mailboxid "does-not-exist" "$missfolder";

EOF
    );

    $talk->create($hitfolder);
    $talk->create($missfolder);

    my %uid = ($hitfolder => 1, $missfolder => 1);
    my %exp;
    xlog $self, "Deliver a message";
    {
        my $msg = $self->{gen}->generate(subject => "msg1");
        $msg->set_attribute(uid => $uid{$missfolder});
        $uid{$missfolder}++;
        $self->{instance}->deliver($msg);
        $exp{$missfolder}->{"msg1"} = $msg;
    }

    my $res = $talk->status($hitfolder, ['mailboxid']);
    my $id = $res->{mailboxid}[0];

    $self->{instance}->install_sieve_script(<<EOF
require ["fileinto", "mailboxid", "variables"];
set "id" "$id";
fileinto :mailboxid "\${id}" "$missfolder";
EOF
    );

    xlog $self, "Deliver a message now that the folder exists";
    {
        my $msg = $self->{gen}->generate(subject => "msg2");
        $msg->set_attribute(uid => $uid{$hitfolder});
        $uid{$hitfolder}++;
        $self->{instance}->deliver($msg);
        $exp{$hitfolder}->{"msg2"} = $msg;
    }

    xlog $self, "Check that the messages made it";
    foreach my $folder (keys %exp)
    {
        $self->{store}->set_folder($folder);
        $self->check_messages($exp{$folder}, check_guid => 0);
    }

    xlog $self, "Delete the target folder";
    $talk->delete($hitfolder);

    xlog $self, "Deliver a message now that the folder doesn't exist";
    {
        my $msg = $self->{gen}->generate(subject => "msg3");
        $msg->set_attribute(uid => $uid{$missfolder});
        $uid{$missfolder}++;
        $self->{instance}->deliver($msg);
        $exp{$missfolder}->{"msg3"} = $msg;
    }

    xlog $self, "Check that the message made it to miss folder";
    $self->{store}->set_folder($missfolder);
    $self->check_messages($exp{$missfolder}, check_guid => 0);
}

sub test_encoded_char_variable_in_mboxname
    :needs_component_sieve :min_version_3_1 :SieveUTF8Fileinto
{
    my ($self) = @_;

    my $target = "INBOX.\N{U+2217}";

    xlog $self, "Testing encoded-character in a mailbox name";

    xlog $self, "Actually create the target folder";
    my $imaptalk = $self->{store}->get_client();

    $imaptalk->create($target)
         or die "Cannot create $target: $@";
    $self->{store}->set_fetch_attributes('uid');

    xlog $self, "Install script";
    $self->{instance}->install_sieve_script(<<EOF
require ["fileinto", "encoded-character", "variables"];
set "star" "\${unicode:2217}";
fileinto "INBOX.\${star}";
EOF
    );

    xlog $self, "Deliver a message";
    my $msg1 = $self->{gen}->generate(subject => "Message 1");
    $self->{instance}->deliver($msg1);

    xlog $self, "Check that the message made it to the target";
    $self->{store}->set_folder($target);
    $self->check_messages({ 1 => $msg1 }, check_guid => 0);
}

sub test_utf8_mboxname
    :needs_component_sieve :min_version_3_1 :SieveUTF8Fileinto
{
    my ($self) = @_;

    my $target = "INBOX.A & B";

    xlog $self, "Testing '&' in a mailbox name";

    xlog $self, "Actually create the target folder";
    my $imaptalk = $self->{store}->get_client();

    $imaptalk->create($target)
         or die "Cannot create $target: $@";
    $self->{store}->set_fetch_attributes('uid');

    xlog $self, "Install script";
    $self->{instance}->install_sieve_script(<<EOF
require ["fileinto", "encoded-character"];
fileinto "INBOX.A & B";
EOF
    );

    xlog $self, "Deliver a message";
    my $msg1 = $self->{gen}->generate(subject => "Message 1");
    $self->{instance}->deliver($msg1);

    xlog $self, "Check that the message made it to the target";
    $self->{store}->set_folder($target);
    $self->check_messages({ 1 => $msg1 }, check_guid => 0);
}

sub test_snooze
    :needs_component_sieve :needs_component_calalarmd
    :needs_component_jmap
    :min_version_3_1
    :NoAltNameSpace
{
    my ($self) = @_;

    my $snoozed = "INBOX.snoozed";
    my $awakened = "INBOX.awakened";

    my $localtz = DateTime::TimeZone->new( name => 'local' );
    my $maildate = DateTime->now(time_zone => $localtz);
    $maildate->add(DateTime::Duration->new(minutes => 1));
    my $timestr = $maildate->strftime('%T');

    xlog $self, "Install script";
    $self->{instance}->install_sieve_script(<<EOF
require ["x-cyrus-snooze", "imap4flags"];
snooze :mailbox "$awakened" :addflags [ "\\\\Flagged", "\$awakened" ] "$timestr";
EOF
    );

    xlog $self, "Create the awakened folder";
    my $imaptalk = $self->{store}->get_client();

    $imaptalk->create($awakened)
         or die "Cannot create $awakened: $@";
    $self->{store}->set_fetch_attributes(qw(uid flags));

    xlog $self, "Deliver a message without having a snoozed folder";
    my $msg1 = $self->{gen}->generate(subject => "Message 1");
    $self->{instance}->deliver($msg1);

    xlog $self, "Check that the message was delivered to INBOX";
    $self->{store}->set_folder("INBOX");
    $self->check_messages({ 1 => $msg1 }, check_guid => 0);

    xlog $self, "Create the snoozed folder";
    $imaptalk->create($snoozed, "(USE (\\Snoozed))");
    $self->assert_equals('ok', $imaptalk->get_last_completion_response());

    xlog $self, "Deliver a message";
    $self->{instance}->deliver($msg1);

    xlog $self, "Check that the message made it to the snoozed folder";
    $self->{store}->set_folder($snoozed);
    $self->check_messages({ 1 => $msg1 }, check_guid => 0);

    xlog $self, "Trigger re-delivery of snoozed email";
    $self->{instance}->run_command({ cyrus => 1 },
                                   'calalarmd', '-t' => $maildate->epoch() + 90 );

    xlog $self, "Check that the message made it to the awakened folder";
    $self->{store}->set_folder($awakened);
    $msg1->set_attribute(flags => [ '\\Recent', '\\Flagged', '$awakened' ]);
    $self->check_messages({ 1 => $msg1 }, check_guid => 0);
}

sub test_snooze_mailboxid
    :needs_component_sieve :needs_component_calalarmd
    :needs_component_jmap
    :min_version_3_1
    :NoAltNameSpace
{
    my ($self) = @_;

    my $snoozed = "INBOX.snoozed";
    my $awakened = "INBOX.awakened";

    xlog $self, "Create the awakened folder";
    my $imaptalk = $self->{store}->get_client();

    $imaptalk->create($awakened)
         or die "Cannot create $awakened: $@";
    my $res = $imaptalk->status($awakened, ['mailboxid']);
    my $awakenedid = $res->{mailboxid}[0];

    my $localtz = DateTime::TimeZone->new( name => 'local' );
    my $maildate = DateTime->now(time_zone => $localtz);
    $maildate->add(DateTime::Duration->new(minutes => 1));
    my $timestr = $maildate->strftime('%T');

    xlog $self, "Install script";
    $self->{instance}->install_sieve_script(<<EOF
require ["x-cyrus-snooze", "imap4flags", "mailboxid"];
snooze :mailboxid "$awakenedid" :addflags [ "\\\\Flagged", "\$awakened" ] "$timestr";
EOF
    );

    $self->{store}->set_fetch_attributes(qw(uid flags));

    xlog $self, "Deliver a message without having a snoozed folder";
    my $msg1 = $self->{gen}->generate(subject => "Message 1");
    $self->{instance}->deliver($msg1);

    xlog $self, "Check that the message was delivered to INBOX";
    $self->{store}->set_folder("INBOX");
    $self->check_messages({ 1 => $msg1 }, check_guid => 0);

    xlog $self, "Create the snoozed folder";
    $imaptalk->create($snoozed, "(USE (\\Snoozed))");
    $self->assert_equals('ok', $imaptalk->get_last_completion_response());

    xlog $self, "Deliver a message";
    $self->{instance}->deliver($msg1);

    xlog $self, "Check that the message made it to the snoozed folder";
    $self->{store}->set_folder($snoozed);
    $self->check_messages({ 1 => $msg1 }, check_guid => 0);

    xlog $self, "Trigger re-delivery of snoozed email";
    $self->{instance}->run_command({ cyrus => 1 },
                                   'calalarmd', '-t' => $maildate->epoch() + 90 );

    xlog $self, "Check that the message made it to the awakened folder";
    $self->{store}->set_folder($awakened);
    $msg1->set_attribute(flags => [ '\\Recent', '\\Flagged', '$awakened' ]);
    $self->check_messages({ 1 => $msg1 }, check_guid => 0);
}

sub test_snooze_specialuse
    :needs_component_sieve :needs_component_calalarmd
    :needs_component_jmap
    :min_version_3_3
    :NoAltNameSpace
{
    my ($self) = @_;

    my $snoozed = "INBOX.snoozed";
    my $awakened = "INBOX.awakened";

    xlog $self, "Create the awakened folder";
    my $imaptalk = $self->{store}->get_client();

    $imaptalk->create($awakened, "(USE (\\Important))")
         or die "Cannot create $awakened: $@";

    my $localtz = DateTime::TimeZone->new( name => 'local' );
    my $maildate = DateTime->now(time_zone => $localtz);
    $maildate->add(DateTime::Duration->new(minutes => 1));
    my $timestr = $maildate->strftime('%T');

    xlog $self, "Install script";
    $self->{instance}->install_sieve_script(<<EOF
require ["snooze", "imap4flags", "special-use"];
snooze :specialuse "\\\\Important" :addflags [ "\\\\Flagged", "\$awakened" ] "$timestr";
EOF
    );

    $self->{store}->set_fetch_attributes(qw(uid flags));

    xlog $self, "Deliver a message without having a snoozed folder";
    my $msg1 = $self->{gen}->generate(subject => "Message 1");
    $self->{instance}->deliver($msg1);

    xlog $self, "Check that the message was delivered to INBOX";
    $self->{store}->set_folder("INBOX");
    $self->check_messages({ 1 => $msg1 }, check_guid => 0);

    xlog $self, "Create the snoozed folder";
    $imaptalk->create($snoozed, "(USE (\\Snoozed))");
    $self->assert_equals('ok', $imaptalk->get_last_completion_response());

    xlog $self, "Deliver a message";
    $self->{instance}->deliver($msg1);

    xlog $self, "Check that the message made it to the snoozed folder";
    $self->{store}->set_folder($snoozed);
    $self->check_messages({ 1 => $msg1 }, check_guid => 0);

    xlog $self, "Trigger re-delivery of snoozed email";
    $self->{instance}->run_command({ cyrus => 1 },
                                   'calalarmd', '-t' => $maildate->epoch() + 90 );

    xlog $self, "Check that the message made it to the awakened folder";
    $self->{store}->set_folder($awakened);
    $msg1->set_attribute(flags => [ '\\Recent', '\\Flagged', '$awakened' ]);
    $self->check_messages({ 1 => $msg1 }, check_guid => 0);
}

sub test_snooze_specialuse_create
    :needs_component_sieve :needs_component_calalarmd
    :needs_component_jmap
    :min_version_3_3
    :NoAltNameSpace
{
    my ($self) = @_;

    my $snoozed = "INBOX.snoozed";
    my $awakened = "INBOX.awakened";

    my $imaptalk = $self->{store}->get_client();

    my $localtz = DateTime::TimeZone->new( name => 'local' );
    my $maildate = DateTime->now(time_zone => $localtz);
    $maildate->add(DateTime::Duration->new(minutes => 1));
    my $timestr = $maildate->strftime('%T');

    xlog $self, "Install script";
    $self->{instance}->install_sieve_script(<<EOF
require ["snooze", "imap4flags", "special-use", "mailbox", "mailboxid"];
snooze:specialuse "\\\\Important" :mailbox "$awakened" :create :addflags [ "\\\\Flagged", "\$awakened" ] "$timestr";
EOF
    );

    $self->{store}->set_fetch_attributes(qw(uid flags));

    xlog $self, "Deliver a message without having a snoozed folder";
    my $msg1 = $self->{gen}->generate(subject => "Message 1");
    $self->{instance}->deliver($msg1);

    xlog $self, "Check that the message was delivered to INBOX";
    $self->{store}->set_folder("INBOX");
    $self->check_messages({ 1 => $msg1 }, check_guid => 0);

    xlog $self, "Create the snoozed folder";
    $imaptalk->create($snoozed, "(USE (\\Snoozed))");
    $self->assert_equals('ok', $imaptalk->get_last_completion_response());

    xlog $self, "Deliver a message";
    $self->{instance}->deliver($msg1);

    xlog $self, "Check that the message made it to the snoozed folder";
    $self->{store}->set_folder($snoozed);
    $self->check_messages({ 1 => $msg1 }, check_guid => 0);

    xlog $self, "Trigger re-delivery of snoozed email";
    $self->{instance}->run_command({ cyrus => 1 },
                                   'calalarmd', '-t' => $maildate->epoch() + 90 );

    xlog $self, "Check that the message made it to the awakened folder";
    $self->{store}->set_folder($awakened);
    $msg1->set_attribute(flags => [ '\\Recent', '\\Flagged', '$awakened' ]);
    $self->check_messages({ 1 => $msg1 }, check_guid => 0);
}

sub test_snooze_tzid
    :needs_component_sieve :needs_component_calalarmd
    :needs_component_jmap
    :min_version_3_3
    :NoAltNamespace
{
    my ($self) = @_;

    my $snoozed = "INBOX.snoozed";
    my $awakened = "INBOX.awakened";

    my $localtz = DateTime::TimeZone->new( name => 'Australia/Melbourne' );
    xlog $self, "using local timezone: " . $localtz->name();
    my $maildate = DateTime->now(time_zone => $localtz);
    $maildate->add(DateTime::Duration->new(minutes => 1));
    my $timestr = $maildate->strftime('%T');

    xlog $self, "Install script with tzid";
    $self->{instance}->install_sieve_script(<<EOF
require ["vnd.cyrus.snooze", "imap4flags"];
snooze :tzid "Australia/Melbourne" :mailbox "$awakened" :addflags "\$awakened" "$timestr";
EOF
    );

    xlog $self, "Create the awakened folder";
    my $imaptalk = $self->{store}->get_client();

    $imaptalk->create($awakened)
         or die "Cannot create $awakened: $@";
    $self->{store}->set_fetch_attributes(qw(uid flags));

    xlog $self, "Create the snoozed folder";
    $imaptalk->create($snoozed, "(USE (\\Snoozed))");
    $self->assert_equals('ok', $imaptalk->get_last_completion_response());

    xlog $self, "Deliver a message";
    my $msg1 = $self->{gen}->generate(subject => "Message 1");
    $self->{instance}->deliver($msg1);

    xlog $self, "Check that the message made it to the snoozed folder";
    $self->{store}->set_folder($snoozed);
    $self->check_messages({ 1 => $msg1 }, check_guid => 0);

    xlog $self, "Trigger re-delivery of snoozed email";
    $self->{instance}->run_command({ cyrus => 1 },
                                   'calalarmd', '-t' => $maildate->epoch() + 39600 + 90 ); # 11h + 90s to account for NY/Mel time diff

    xlog $self, "Check that the message made it to the awakened folder";
    $self->{store}->set_folder($awakened);
    $msg1->set_attribute(flags => [ '\\Recent', '$awakened' ]);
    $self->check_messages({ 1 => $msg1 }, check_guid => 0);
}

sub test_utf8_subject_encoded
    :min_version_3_0
    :needs_component_sieve
{
    my ($self) = @_;

    my $imaptalk = $self->{store}->get_client();

    xlog $self, "Install a sieve script flagging messages that match utf8 snowman";
    $self->{instance}->install_sieve_script(<<EOF
require ["fileinto", "imap4flags"];
if header :matches "Subject" "☃" {
    setflag "\\\\Flagged";
}
EOF
    );

    xlog $self, "Deliver a message";

    # should NOT get flagged
    my $msg1 = $self->{gen}->generate(subject => "Message 1");
    $self->{instance}->deliver($msg1);

    # SHOULD get flagged
    my $msg2 = $self->{gen}->generate(subject => "=?UTF-8?B?4piD?=");
    $self->{instance}->deliver($msg2);

    # should NOT get flagged
    my $msg3 = $self->{gen}->generate(subject => "Message 3");
    $self->{instance}->deliver($msg3);

    $imaptalk->unselect();
    $imaptalk->select("INBOX");
    $self->assert_num_equals(3, $imaptalk->get_response_code('exists'));

    my @uids = $imaptalk->search('1:*', 'NOT', 'FLAGGED');

    $self->assert_num_equals(2, scalar(@uids));
}

sub test_utf8_subject_raw
    :min_version_3_0
    :needs_component_sieve :NoMunge8bit
{
    my ($self) = @_;

    my $imaptalk = $self->{store}->get_client();

    xlog $self, "Install a sieve script flagging messages that match utf8 snowman";
    $self->{instance}->install_sieve_script(<<EOF
require ["fileinto", "imap4flags"];
if header :matches "Subject" "☃" {
    setflag "\\\\Flagged";
}
EOF
    );

    xlog $self, "Deliver a message";

    # should NOT get flagged
    my $msg1 = $self->{gen}->generate(subject => "Message 1");
    $self->{instance}->deliver($msg1);

    # SHOULD get flagged
    my $msg2 = $self->{gen}->generate(subject => "☃");
    $self->{instance}->deliver($msg2);

    # should NOT get flagged
    my $msg3 = $self->{gen}->generate(subject => "Message 3");
    $self->{instance}->deliver($msg3);

    $imaptalk->unselect();
    $imaptalk->select("INBOX");
    $self->assert_num_equals(3, $imaptalk->get_response_code('exists'));

    my @uids = $imaptalk->search('1:*', 'NOT', 'FLAGGED');

    $self->assert_num_equals(2, scalar(@uids));
}

sub test_error_flag
    :needs_component_sieve :min_version_3_3
{
    my ($self) = @_;

    xlog $self, "Install a sieve script filing all mail into a nonexistant folder";
    $self->{instance}->install_sieve_script(<<EOF);
require ["ihave", "fileinto"];

if header :contains "Subject" "fail" {
    error "this test fails";
}
elsif header :contains "Subject" "file" {
    fileinto :copy "INBOX.not_exists";
}
EOF
    xlog $self, "Deliver four messages";

    # should NOT get flagged
    my $msg1 = $self->{gen}->generate(subject => "Message 1");
    $self->{instance}->deliver($msg1);

    # SHOULD get flagged
    my $msg2 = $self->{gen}->generate(subject => "this will fail with an error");
    $self->{instance}->deliver($msg2);

    # should NOT get flagged
    my $msg3 = $self->{gen}->generate(subject => "Message 3");
    $self->{instance}->deliver($msg3);

    # SHOULD get flagged
    my $msg4 = $self->{gen}->generate(subject => "this fileinto won't succeed");
    $self->{instance}->deliver($msg4);

    my $imaptalk = $self->{store}->get_client();

    $imaptalk->select("INBOX");
    $self->assert_num_equals(4, $imaptalk->get_response_code('exists'));

    my $res = $imaptalk->fetch('1:*', 'flags');

    $self->assert_null(grep { $_ eq '$SieveFailed' } @{$res->{1}{flags}});
    $self->assert_not_null(grep { $_ eq '$SieveFailed' } @{$res->{2}{flags}});
    $self->assert_null(grep { $_ eq '$SieveFailed' } @{$res->{3}{flags}});
    $self->assert_not_null(grep { $_ eq '$SieveFailed' } @{$res->{4}{flags}});
}

sub test_double_require
    :needs_component_sieve
{
    my ($self) = @_;

    my $target = "INBOX.target";

    xlog $self, "Install a sieve script filing all mail into a nonexistant folder";
    $self->{instance}->install_sieve_script(<<EOF
require ["fileinto"];
require ["imap4flags"];
addflag "\\\\Flagged";
fileinto "$target";
EOF
    );

    xlog $self, "Deliver a message";
    my $msg1 = $self->{gen}->generate(subject => "Message 1");
    $self->{instance}->deliver($msg1);

    xlog $self, "Actually create the target folder";
    my $imaptalk = $self->{store}->get_client();

    $imaptalk->create($target)
         or die "Cannot create $target: $@";
    $self->{store}->set_fetch_attributes('uid');

    xlog $self, "Deliver another message";
    my $msg2 = $self->{gen}->generate(subject => "Message 2");
    $self->{instance}->deliver($msg2);
    $msg2->set_attribute(uid => 1);

    xlog $self, "Check that only the 1st message made it to INBOX";
    $self->{store}->set_folder('INBOX');
    $self->check_messages({ 1 => $msg1 }, check_guid => 0);

    xlog $self, "Check that only the 2nd message made it to the target";
    $self->{store}->set_folder($target);
    $self->check_messages({ 1 => $msg2 }, check_guid => 0);
}

sub test_jmapquery
    :min_version_3_3 :needs_component_sieve :needs_component_jmap
{
    my ($self) = @_;

    my $imap = $self->{store}->get_client();
    $imap->create("INBOX.matches") or die;

    $self->{instance}->install_sieve_script(<<'EOF'
require ["x-cyrus-jmapquery", "x-cyrus-log", "variables", "fileinto"];
if
  allof( not string :is "${stop}" "Y",
    jmapquery text:
  {
    "operator" : "OR",
    "conditions" : [
        {
           "deliveredTo" : "xxx@yyy.zzz",
           "attachmentType" : "image"
        }
    ]
  }
.
  )
{
  fileinto "INBOX.matches";
}
EOF
    );

    my $body = << 'EOF';
--047d7b33dd729737fe04d3bde348
Content-Type: text/plain; charset=UTF-8

plain

--047d7b33dd729737fe04d3bde348
Content-Type: image/tiff
Content-Transfer-Encoding: base64

abc=

--047d7b33dd729737fe04d3bde348--
EOF
    $body =~ s/\r?\n/\r\n/gs;

    xlog $self, "Deliver a matching message";
    my $msg1 = $self->{gen}->generate(
        subject => "Message 1",
        extra_headers => [['X-Delivered-To', 'xxx@yyy.zzz']],
        mime_type => "multipart/mixed",
        mime_boundary => "047d7b33dd729737fe04d3bde348",
        body => $body,
    );
    $self->{instance}->deliver($msg1);

    $self->{store}->set_fetch_attributes('uid');

    xlog "Assert that message got moved into INBOX.matches";
    $self->{store}->set_folder('INBOX.matches');
    $self->check_messages({ 1 => $msg1 }, check_guid => 0);

    xlog $self, "Deliver a non-matching message";
    my $msg2 = $self->{gen}->generate(subject => "Message 2");
    $self->{instance}->deliver($msg2);
    $msg2->set_attribute(uid => 1);

    xlog "Assert that message got moved into INBOX";
    $self->{store}->set_folder('INBOX');
    $self->check_messages({ 1 => $msg2 }, check_guid => 0);
}

sub test_jmapquery_multiple_to_cross_domain
    :min_version_3_3 :needs_component_sieve :needs_component_jmap
{
    my ($self) = @_;

    my $imap = $self->{store}->get_client();
    $imap->create("INBOX.matches") or die;

    $self->{instance}->install_sieve_script(<<'EOF'
require ["x-cyrus-jmapquery", "x-cyrus-log", "variables", "fileinto"];
if
  allof( not string :is "${stop}" "Y",
    jmapquery text:
  {
    "to" : "foo@example.net",
    "header" : ["X-Foo"]
  }
.
  )
{
  fileinto "INBOX.matches";
}
EOF
    );

    xlog $self, "Deliver a matching message";
    my $msg1 = $self->{gen}->generate(
        subject => "Message 1",
        extra_headers => [['To', 'foo@example.net'],
                          ['X-Foo', 'bar']
        ],
    );
    $self->{instance}->deliver($msg1);

    $self->{store}->set_fetch_attributes('uid');

    xlog "Assert that message got moved into INBOX.matches";
    $self->{store}->set_folder('INBOX.matches');
    $self->check_messages({ 1 => $msg1 }, check_guid => 0);

    xlog $self, "Deliver a non-matching message";
    my $msg2 = $self->{gen}->generate(
        subject => "Message 2",
        extra_headers => [['To', 'foo@example.com, bar@example.net'],
                          ['X-Foo', 'bar']
        ],
    );
    $self->{instance}->deliver($msg2);
    $msg2->set_attribute(uid => 1);

    xlog "Assert that message got moved into INBOX";
    $self->{store}->set_folder('INBOX');
    $self->check_messages({ 1 => $msg2 }, check_guid => 0);
}

sub test_jmapquery_attachmentindexing
    :min_version_3_3 :needs_component_sieve :needs_component_jmap
    :needs_search_xapian :SearchAttachmentExtractor :JMAPExtensions
{
    my ($self) = @_;

    my $imap = $self->{store}->get_client();
    my $instance = $self->{instance};

    my $uri = URI->new($instance->{config}->get('search_attachment_extractor_url'));
    my (undef, $filename) = tempfile('tmpXXXXXX', OPEN => 0,
        DIR => $instance->{basedir} . "/tmp");

    xlog "Start a dummy extractor server";
    my $handler = sub {
        my ($conn, $req) = @_;
        open HANDLE, ">$filename" || die;
        close HANDLE;
        if ($req->method eq 'HEAD') {
            my $res = HTTP::Response->new(204);
            $res->content("");
            $conn->send_response($res);
        } else {
            my $res = HTTP::Response->new(200);
            $res->content("data");
            $conn->send_response($res);
        }
    };
    $instance->start_httpd($handler, $uri->port());

    xlog "Install JMAP sieve script";
    $imap->create("INBOX.matches") or die;
    $instance->install_sieve_script(<<'EOF'
require ["x-cyrus-jmapquery", "x-cyrus-log", "variables", "fileinto"];
if
  allof( not string :is "${stop}" "Y",
    jmapquery text:
  {
    "body": "plaintext"
  }
.
  )
{
  fileinto "INBOX.matches";
}
EOF
    );

    xlog "Deliver a message with attachment";
    my $body = << 'EOF';
--047d7b33dd729737fe04d3bde348
Content-Type: text/plain; charset=UTF-8

plaintext

--047d7b33dd729737fe04d3bde348
Content-Type: application/pdf

data

--047d7b33dd729737fe04d3bde348--
EOF
    $body =~ s/\r?\n/\r\n/gs;
    my $msg1 = $self->{gen}->generate(
        subject => "Message 1",
        mime_type => "multipart/mixed",
        mime_boundary => "047d7b33dd729737fe04d3bde348",
        body => $body,
    );
    $instance->deliver($msg1);

    xlog "Assert that extractor did NOT get called";
    $self->assert(not -e $filename);

    xlog "Assert that message got moved into INBOX.matches";
    $self->{store}->set_folder('INBOX.matches');
    $self->check_messages({ 1 => $msg1 }, check_guid => 0);
}

sub test_notify
    :needs_component_sieve
{
    my ($self) = @_;

    $self->{instance}->install_sieve_script(<<'EOF'
require ["notify", "enotify"];

notify :method "addcal" :options ["calendarId","6ae6a9e0-53f5-4559-8c5a-520208f86cfd"];
notify "https://cyrusimap.org/notifiers/updatecal";
EOF
        );

    xlog $self, "Deliver a message";
    my $msg1 = $self->{gen}->generate(subject => "Message 1");
    $self->{instance}->deliver($msg1);

    my $data = $self->{instance}->getnotify();
    my ($addcal) = grep { $_->{METHOD} eq 'addcal' } @$data;
    my ($updatecal) = grep { $_->{METHOD} eq 'https://cyrusimap.org/notifiers/updatecal' } @$data;

    $self->assert_not_null($addcal);
    $self->assert_not_null($updatecal);
}

sub test_variable_modifiers
    :needs_component_sieve
{
    my ($self) = @_;

    $self->{instance}->install_sieve_script(<<'EOF'
require ["variables", "editheader", "regex", "enotify"];

set                        "a" "juMBlEd?lETteRS=.*";
set :length                "b" "${a}";  #  => "18"
set :lower                 "c" "${a}";  #  => "jumbled?letters=.*"
set :upper                 "d" "${a}";  #  => "JUMBLED?LETTERS=.*"
set :lowerfirst            "e" "${a}";  #  => "juMBlEd?lETteRS=.*"
set :lowerfirst :upper     "f" "${a}";  #  => "jUMBLED?LETTERS.*"
set :upperfirst            "g" "${a}";  #  => "JuMBlEd?lETteRS=.*"
set :upperfirst :lower     "h" "${a}";  #  => "Jumbled?letters=.*"
set :quotewildcard         "i" "${a}";  #  => "juMBlEd\?lETteRS=.\*"
set :quoteregex            "j" "${a}";  #  => "juMBlEd\?lETteRS=\.\*"
set :encodeurl             "k" "${a}";  #  => "juMBlEd%3FlETteRS%3D.%2A"
set :encodeurl :upper      "l" "${a}";  #  => "JUMBLED%3FLETTERS%3D.%2A"
set :quotewildcard :upper  "m" "${a}";  #  => "JUMBLED\?LETTERS=.\*"
set :quoteregex :upper     "n" "${a}";  #  => "JUMBLED\?LETTERS=\.\*"
set :quoteregex :encodeurl
    :upperfirst :lower     "o" "${a}";  #  => "Jumbled%5C%3fletters%3D%5C.%5C%2A"
set :quoteregex :encodeurl
    :upper :length         "p" "${a}";  #  => "33"

addheader "X-Cassandane-Test" "len = \"${b}\"";
addheader "X-Cassandane-Test" "lower = \"${c}\"";
addheader "X-Cassandane-Test" "upper = \"${d}\"";
addheader "X-Cassandane-Test" "lowerfirst = \"${e}\"";
addheader "X-Cassandane-Test" "lowerfirst+upper = \"${f}\"";
addheader "X-Cassandane-Test" "upperfirst = \"${g}\"";
addheader "X-Cassandane-Test" "upperfirst+lower = \"${h}\"";
addheader "X-Cassandane-Test" "wild = \"${i}\"";
addheader "X-Cassandane-Test" "regex = \"${j}\"";
addheader "X-Cassandane-Test" "url = \"${k}\"";
addheader "X-Cassandane-Test" "url+upper = \"${l}\"";
addheader "X-Cassandane-Test" "wild+upper = \"${m}\"";
addheader "X-Cassandane-Test" "regex+upper = \"${n}\"";
addheader "X-Cassandane-Test" "regex+url+upperfirst+lower = \"${o}\"";
addheader "X-Cassandane-Test" "regex+url+upper+len = \"${p}\"";
EOF
        );

    xlog $self, "Deliver a message";
    my $msg1 = $self->{gen}->generate(subject => "Message 1");
    $self->{instance}->deliver($msg1);

    my $imaptalk = $self->{store}->get_client();
    $imaptalk->select("INBOX");
    my $res = $imaptalk->fetch(1, 'rfc822');

    $msg1 = $res->{1}->{rfc822};

    $self->assert_matches(qr/X-Cassandane-Test: len = "18"\r\n/, $msg1);
    $self->assert_matches(qr/X-Cassandane-Test: lower = "jumbled\?letters=\.\*"\r\n/, $msg1);
    $self->assert_matches(qr/X-Cassandane-Test: upper = "JUMBLED\?LETTERS=\.\*"\r\n/, $msg1);
    $self->assert_matches(qr/X-Cassandane-Test: lowerfirst = "juMBlEd\?lETteRS=\.\*"\r\n/, $msg1);
    $self->assert_matches(qr/X-Cassandane-Test: lowerfirst\+upper = "jUMBLED\?LETTERS=\.\*"\r\n/, $msg1);
    $self->assert_matches(qr/X-Cassandane-Test: upperfirst = "JuMBlEd\?lETteRS=\.\*"\r\n/, $msg1);
    $self->assert_matches(qr/X-Cassandane-Test: upperfirst\+lower = "Jumbled\?letters=\.\*"\r\n/, $msg1);
    $self->assert_matches(qr/X-Cassandane-Test: wild = "juMBlEd\\\?lETteRS=\.\\\*"\r\n/, $msg1);
    $self->assert_matches(qr/X-Cassandane-Test: regex = "juMBlEd\\\?lETteRS=\\\.\\\*"\r\n/, $msg1);
    $self->assert_matches(qr/X-Cassandane-Test: url = "juMBlEd%3FlETteRS%3D\.%2A"\r\n/, $msg1);
    $self->assert_matches(qr/X-Cassandane-Test: wild\+upper = "JUMBLED\\\?LETTERS=\.\\\*"\r\n/, $msg1);
    $self->assert_matches(qr/X-Cassandane-Test: regex\+upper = "JUMBLED\\\?LETTERS=\\\.\\\*"\r\n/, $msg1);
    $self->assert_matches(qr/X-Cassandane-Test: url\+upper = "JUMBLED%3FLETTERS%3D\.%2A"\r\n/, $msg1);
    $self->assert_matches(qr/X-Cassandane-Test: regex\+url\+upperfirst\+lower = "Jumbled%5C%3Fletters%3D%5C.%5C%2A"\r\n/, $msg1);
    $self->assert_matches(qr/X-Cassandane-Test: regex\+url\+upper\+len = "33"\r\n/, $msg1);
}

sub test_date
    :needs_component_sieve
{
    my ($self) = @_;

    $self->{instance}->install_sieve_script(<<'EOF'
require ["date", "variables", "imap4flags", "regex", "relational"];

if date :originalzone "date" "date" "2018-05-16" {
  addflag "Test1";
}

set "time" "22:06:18";
if date :originalzone "date" "time" ["foo", "${time}"] {
  addflag "Test2";
}

if date :regex "date" "std11" "^[a-z]{3}, [0-9]{1,2} [a-z]{3} [0-9]{4}" {
  addflag "Test3";
}

if date :value "ge" :originalzone "date" "hour" "12" {
  addflag "Test4";
}
EOF
        );

    my $raw = << 'EOF';
Date: Wed, 16 May 2018 22:06:18 -0700
From: Some Person <notifications@github.com>
To: foo/bar <bar@noreply.github.com>
Cc: Subscribed <subscribed@noreply.github.com>
Message-ID: <foo/bar/pull/1234/abcdef01234@github.com>
X-Cassandane-Unique: foo

foo bar
EOF
    xlog $self, "Deliver a message";
    my $msg1 = Cassandane::Message->new(raw => $raw);
    $self->{instance}->deliver($msg1);

    my $imaptalk = $self->{store}->get_client();
    $self->{store}->set_fetch_attributes(qw(uid flags));
    $self->{store}->set_folder('INBOX');
    $msg1->set_attribute(uid => 1);
    $msg1->set_attribute(flags => [ '\\Recent', 'Test1', 'Test2', 'Test3', 'Test4' ]);
    $self->check_messages({ 1 => $msg1 }, keyed_on => 'uid', check_guid => 0);
}

sub test_imip_invite
    :needs_component_sieve :needs_component_httpd :min_version_3_5
{
    my ($self) = @_;

    my $IMAP = $self->{store}->get_client();
    $self->{store}->_select();
    $self->assert_num_equals(1, $IMAP->uid());
    $self->{store}->set_fetch_attributes(qw(uid flags));

    xlog $self, "Create calendar user";
    my $CalDAV = $self->{caldav};
    my $CalendarId = 'Default';
    my $uuid = "6de280c9-edff-4019-8ebd-cfebc73f8201";

    xlog $self, "Install a sieve script to process iMIP";
    $self->{instance}->install_sieve_script(<<EOF
require ["body", "variables", "imap4flags", "vnd.cyrus.imip"];
if body :content "text/calendar" :contains "\nMETHOD:" {
    processimip :outcome "outcome";
    if string "\${outcome}" "added" {
        setflag "\\\\Flagged";
    }
}
EOF
    );

    my $imip = <<EOF;
Date: Thu, 23 Sep 2021 09:06:18 -0400
From: Foo <foo\@example.net>
To: Cassandane <cassandane\@example.com>
Message-ID: <$uuid\@example.net>
Content-Type: text/calendar; method=REQUEST; component=VEVENT
X-Cassandane-Unique: $uuid

BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.10.4//EN
METHOD:REQUEST
BEGIN:VEVENT
CREATED:20210923T034327Z
UID:$uuid
DTEND;TZID=America/New_York:20210923T183000
TRANSP:OPAQUE
SUMMARY:An Event
DTSTART;TZID=America/New_York:20210923T153000
DTSTAMP:20210923T034327Z
SEQUENCE:0
ORGANIZER;CN=Test User:MAILTO:foo\@example.net
ATTENDEE;CN=Test User;PARTSTAT=ACCEPTED;RSVP=TRUE:MAILTO:foo\@example.net
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:MAILTO:cassandane\@example.com
END:VEVENT
END:VCALENDAR
EOF

    xlog $self, "Deliver iMIP invite";
    my $msg = Cassandane::Message->new(raw => $imip);
    $msg->set_attribute(uid => 1,
                        flags => [ '\\Recent', '\\Flagged' ]);
    $self->{instance}->deliver($msg);

    xlog $self, "Check that the message made it to INBOX";
    $self->check_messages({ 1 => $msg }, check_guid => 0);

    xlog $self, "Check that the event made it to calendar";
    my $events = $CalDAV->GetEvents($CalendarId);
    $self->assert_equals(1, scalar @$events);
    $self->assert_str_equals($uuid, $events->[0]{uid});
}

sub test_imip_invite_base64
    :needs_component_sieve :needs_component_httpd :min_version_3_5
{
    my ($self) = @_;

    my $IMAP = $self->{store}->get_client();
    $self->{store}->_select();
    $self->assert_num_equals(1, $IMAP->uid());
    $self->{store}->set_fetch_attributes(qw(uid flags));

    xlog $self, "Create calendar user";
    my $CalDAV = $self->{caldav};
    my $CalendarId = 'Default';
    my $uuid = "6de280c9-edff-4019-8ebd-cfebc73f8201";

    xlog $self, "Install a sieve script to process iMIP";
    $self->{instance}->install_sieve_script(<<EOF
require ["body", "variables", "imap4flags", "vnd.cyrus.imip"];
if body :content "text/calendar" :contains "\nMETHOD:" {
    processimip :outcome "outcome";
    if string "\${outcome}" "added" {
        setflag "\\\\Flagged";
    }
}
EOF
    );

    my $itip = <<EOF;
BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.10.4//EN
METHOD:REQUEST
BEGIN:VEVENT
CREATED:20210923T034327Z
UID:$uuid
DTEND;TZID=America/New_York:20210923T183000
TRANSP:OPAQUE
SUMMARY:An Event
DTSTART;TZID=America/New_York:20210923T153000
DTSTAMP:20210923T034327Z
SEQUENCE:0
ORGANIZER;CN=Test User:MAILTO:foo\@example.net
ATTENDEE;CN=Test User;PARTSTAT=ACCEPTED;RSVP=TRUE:MAILTO:foo\@example.net
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:MAILTO:cassandane\@example.com
END:VEVENT
END:VCALENDAR
EOF

    my $itip_b64 = encode_base64($itip);

    my $imip = <<EOF;
Date: Thu, 23 Sep 2021 09:06:18 -0400
From: Foo <foo\@example.net>
To: Cassandane <cassandane\@example.com>
Message-ID: <$uuid\@example.net>
Content-Type: text/calendar; method=REQUEST; component=VEVENT
Content-Transfer-Encoding: base64
X-Cassandane-Unique: $uuid

$itip_b64
EOF

    xlog $self, "Deliver iMIP invite";
    my $msg = Cassandane::Message->new(raw => $imip);
    $msg->set_attribute(uid => 1,
                        flags => [ '\\Recent', '\\Flagged' ]);
    $self->{instance}->deliver($msg);

    xlog $self, "Check that the message made it to INBOX";
    $self->check_messages({ 1 => $msg }, check_guid => 0);

    xlog $self, "Check that the event made it to calendar";
    my $events = $CalDAV->GetEvents($CalendarId);
    $self->assert_equals(1, scalar @$events);
    $self->assert_str_equals($uuid, $events->[0]{uid});
}

sub test_imip_invite_multipart
    :needs_component_sieve :needs_component_httpd :min_version_3_5
{
    my ($self) = @_;

    my $IMAP = $self->{store}->get_client();
    $self->{store}->_select();
    $self->assert_num_equals(1, $IMAP->uid());
    $self->{store}->set_fetch_attributes(qw(uid flags));

    xlog $self, "Create calendar user";
    my $CalDAV = $self->{caldav};
    my $CalendarId = 'Default';
    my $uuid = "6de280c9-edff-4019-8ebd-cfebc73f8201";

    xlog $self, "Install a sieve script to process iMIP";
    $self->{instance}->install_sieve_script(<<EOF
require ["body", "variables", "imap4flags", "vnd.cyrus.imip"];
if body :content "text/calendar" :contains "\nMETHOD:" {
    processimip :outcome "outcome";
    if string "\${outcome}" "added" {
        setflag "\\\\Flagged";
    }
}
EOF
    );

    my $imip = <<EOF;
Date: Thu, 23 Sep 2021 09:06:18 -0400
From: Foo <foo\@example.net>
To: Cassandane <cassandane\@example.com>
Message-ID: <$uuid\@example.net>
Content-Type: multipart/mixed; boundary=$uuid
Mime-Version: 1.0
X-Cassandane-Unique: $uuid

--$uuid
Content-Type: text/plain
Mime-Version: 1.0

Invite for cassandane\@example.com

--$uuid
Content-Type: text/calendar; method=REQUEST; component=VEVENT
Content-Disposition: attachment; filename=event.ics
Mime-Version: 1.0

BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.10.4//EN
METHOD:REQUEST
BEGIN:VEVENT
CREATED:20210923T034327Z
UID:$uuid
DTEND;TZID=America/New_York:20210923T183000
TRANSP:OPAQUE
SUMMARY:An Event
DTSTART;TZID=America/New_York:20210923T153000
DTSTAMP:20210923T034327Z
SEQUENCE:0
ORGANIZER;CN=Test User:MAILTO:foo\@example.net
ATTENDEE;CN=Test User;PARTSTAT=ACCEPTED;RSVP=TRUE:MAILTO:foo\@example.net
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:MAILTO:cassandane\@example.com
END:VEVENT
END:VCALENDAR
--$uuid--
EOF

    xlog $self, "Deliver iMIP invite";
    my $msg = Cassandane::Message->new(raw => $imip);
    $msg->set_attribute(uid => 1,
                        flags => [ '\\Recent', '\\Flagged' ]);
    $self->{instance}->deliver($msg);

    xlog $self, "Check that the message made it to INBOX";
    $self->check_messages({ 1 => $msg }, check_guid => 0);

    xlog $self, "Check that the event made it to calendar";
    my $events = $CalDAV->GetEvents($CalendarId);
    $self->assert_equals(1, scalar @$events);
    $self->assert_str_equals($uuid, $events->[0]{uid});
}

sub test_imip_invite_calendarid
    :needs_component_sieve :needs_component_httpd :min_version_3_5
{
    my ($self) = @_;

    my $IMAP = $self->{store}->get_client();
    $self->{store}->_select();
    $self->assert_num_equals(1, $IMAP->uid());
    $self->{store}->set_fetch_attributes(qw(uid flags));

    xlog $self, "Create calendar user and second calendar";
    my $CalDAV = $self->{caldav};
    my $CalendarId = $CalDAV->NewCalendar({name => 'foo'});
    $self->assert_not_null($CalendarId);

    my $uuid = "6de280c9-edff-4019-8ebd-cfebc73f8201";

    xlog $self, "Install a sieve script to process iMIP";
    $self->{instance}->install_sieve_script(<<EOF
require ["body", "variables", "imap4flags", "vnd.cyrus.imip"];
if body :content "text/calendar" :contains "\nMETHOD:" {
    processimip :calendarid "$CalendarId" :outcome "outcome";
    if string "\${outcome}" "added" {
        setflag "\\\\Flagged";
    }
}
EOF
    );

    my $imip = <<EOF;
Date: Thu, 23 Sep 2021 09:06:18 -0400
From: Foo <foo\@example.net>
To: Cassandane <cassandane\@example.com>
Message-ID: <$uuid\@example.net>
Content-Type: text/calendar; method=REQUEST; component=VEVENT
X-Cassandane-Unique: $uuid

BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.10.4//EN
METHOD:REQUEST
BEGIN:VEVENT
CREATED:20210923T034327Z
UID:$uuid
DTEND;TZID=America/New_York:20210923T183000
TRANSP:OPAQUE
SUMMARY:An Event
DTSTART;TZID=America/New_York:20210923T153000
DTSTAMP:20210923T034327Z
SEQUENCE:0
ORGANIZER;CN=Test User:MAILTO:foo\@example.net
ATTENDEE;CN=Test User;PARTSTAT=ACCEPTED;RSVP=TRUE:MAILTO:foo\@example.net
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:MAILTO:cassandane\@example.com
END:VEVENT
END:VCALENDAR
EOF

    xlog $self, "Deliver iMIP invite";
    my $msg = Cassandane::Message->new(raw => $imip);
    $msg->set_attribute(uid => 1,
                        flags => [ '\\Recent', '\\Flagged' ]);
    $self->{instance}->deliver($msg);

    xlog $self, "Check that the message made it to INBOX";
    $self->check_messages({ 1 => $msg }, check_guid => 0);

    xlog $self, "Check that the event made it to calendar";
    my $events = $CalDAV->GetEvents($CalendarId);
    $self->assert_equals(1, scalar @$events);
    $self->assert_str_equals($uuid, $events->[0]{uid});
}

sub test_imip_invite_updatesonly
    :needs_component_sieve :needs_component_httpd :min_version_3_5
{
    my ($self) = @_;

    my $IMAP = $self->{store}->get_client();
    $self->{store}->_select();
    $self->assert_num_equals(1, $IMAP->uid());
    $self->{store}->set_fetch_attributes(qw(uid flags));

    xlog $self, "Create calendar user";
    my $CalDAV = $self->{caldav};
    my $CalendarId = 'Default';
    my $uuid = "6de280c9-edff-4019-8ebd-cfebc73f8201";

    xlog $self, "Install a sieve script to process iMIP";
    $self->{instance}->install_sieve_script(<<EOF
require ["body", "variables", "imap4flags", "vnd.cyrus.imip"];
if body :content "text/calendar" :contains "\nMETHOD:" {
    processimip :updatesonly :outcome "outcome";
    if string "\${outcome}" "added" {
        setflag "\\\\Flagged";
    }
}
EOF
    );

    my $imip = <<EOF;
Date: Thu, 23 Sep 2021 09:06:18 -0400
From: Foo <foo\@example.net>
To: Cassandane <cassandane\@example.com>
Message-ID: <$uuid\@example.net>
Content-Type: text/calendar; method=REQUEST; component=VEVENT
X-Cassandane-Unique: $uuid

BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.10.4//EN
METHOD:REQUEST
BEGIN:VEVENT
CREATED:20210923T034327Z
UID:$uuid
DTEND;TZID=America/New_York:20210923T183000
TRANSP:OPAQUE
SUMMARY:An Event
DTSTART;TZID=America/New_York:20210923T153000
DTSTAMP:20210923T034327Z
SEQUENCE:0
ORGANIZER;CN=Test User:MAILTO:foo\@example.net
ATTENDEE;CN=Test User;PARTSTAT=ACCEPTED;RSVP=TRUE:MAILTO:foo\@example.net
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:MAILTO:cassandane\@example.com
END:VEVENT
END:VCALENDAR
EOF

    xlog $self, "Deliver iMIP invite";
    my $msg = Cassandane::Message->new(raw => $imip);
    $msg->set_attribute(uid => 1,
                        flags => [ '\\Recent' ]);
    $self->{instance}->deliver($msg);

    xlog $self, "Check that the message made it to INBOX";
    $self->check_messages({ 1 => $msg }, check_guid => 0);

    xlog $self, "Check that the event did NOT make it to calendar";
    my $events = $CalDAV->GetEvents($CalendarId);
    $self->assert_deep_equals([], $events);
}

sub test_imip_update
    :needs_component_sieve :needs_component_httpd :min_version_3_5
{
    my ($self) = @_;

    my $IMAP = $self->{store}->get_client();
    $self->{store}->_select();
    $self->assert_num_equals(1, $IMAP->uid());
    $self->{store}->set_fetch_attributes(qw(uid flags));

    xlog $self, "Create calendar user";
    my $CalDAV = $self->{caldav};
    my $CalendarId = 'Default';
    my $uuid = "6de280c9-edff-4019-8ebd-cfebc73f8201";

    xlog $self, "Install a sieve script to process iMIP";
    $self->{instance}->install_sieve_script(<<EOF
require ["body", "variables", "imap4flags", "vnd.cyrus.imip"];
if body :content "text/calendar" :contains "\nMETHOD:" {
    processimip :outcome "outcome";
    if string "\${outcome}" "updated" {
        setflag "\\\\Flagged";
    }
}
EOF
    );

    my $imip = <<EOF;
Date: Thu, 23 Sep 2021 09:06:18 -0400
From: Foo <foo\@example.net>
To: Cassandane <cassandane\@example.com>
Message-ID: <$uuid-0\@example.net>
Content-Type: text/calendar; method=REQUEST; component=VEVENT
X-Cassandane-Unique: $uuid-0

BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.10.4//EN
METHOD:REQUEST
BEGIN:VEVENT
CREATED:20210923T034327Z
UID:$uuid
DTEND;TZID=America/New_York:20210923T183000
TRANSP:OPAQUE
SUMMARY:An Event
DTSTART;TZID=America/New_York:20210923T153000
DTSTAMP:20210923T034327Z
SEQUENCE:0
ORGANIZER;CN=Test User:MAILTO:foo\@example.net
ATTENDEE;CN=Test User;PARTSTAT=ACCEPTED;RSVP=TRUE:MAILTO:foo\@example.net
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:MAILTO:cassandane\@example.com
END:VEVENT
END:VCALENDAR
EOF

    xlog $self, "Deliver iMIP invite";
    my $msg = Cassandane::Message->new(raw => $imip);
    $msg->set_attribute(uid => 1,
                        flags => [ '\\Recent', '\\Flagged' ]);
    $self->{instance}->deliver($msg);

    xlog $self, "Check that the message made it to INBOX";
    $self->check_messages({ 1 => $msg }, check_guid => 0);

    xlog $self, "Expunge the message";
    $IMAP->store('1', '+flags', '(\\Deleted)');
    $IMAP->expunge();

    xlog $self, "Check that the event made it to calendar";
    my $events = $CalDAV->GetEvents($CalendarId);
    $self->assert_equals(1, scalar @$events);
    $self->assert_str_equals($uuid, $events->[0]{uid});
    $self->assert_str_equals('An Event', $events->[0]{title});
    $self->assert_str_equals('2021-09-23T15:30:00', $events->[0]{start});


    $imip = <<EOF;
Date: Thu, 24 Sep 2021 09:06:18 -0400
From: Foo <foo\@example.net>
To: Cassandane <cassandane\@example.com>
Message-ID: <$uuid-1\@example.net>
Content-Type: text/calendar; method=CANCEL; component=VEVENT
X-Cassandane-Unique: $uuid-1

BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.10.4//EN
METHOD:REQUEST
BEGIN:VEVENT
CREATED:20210923T034327Z
UID:$uuid
DTEND;TZID=America/New_York:20210924T170000
TRANSP:OPAQUE
SUMMARY:An Updated Event
DTSTART;TZID=America/New_York:20210924T140000
DTSTAMP:20210923T034327Z
SEQUENCE:1
ORGANIZER;CN=Test User:MAILTO:foo\@example.net
ATTENDEE;CN=Test User;PARTSTAT=ACCEPTED;RSVP=TRUE:MAILTO:foo\@example.net
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:MAILTO:cassandane\@example.com
END:VEVENT
END:VCALENDAR
EOF

    xlog $self, "Deliver iMIP update";
    $msg = Cassandane::Message->new(raw => $imip);
    $msg->set_attribute(uid => 2,
                        flags => [ '\\Recent', '\\Flagged' ]);
    $self->{instance}->deliver($msg);

    xlog $self, "Check that the message made it to INBOX";
    $self->check_messages({ 1 => $msg }, check_guid => 0);

    xlog $self, "Check that the event was updated on calendar";
    $events = $CalDAV->GetEvents($CalendarId);
    $self->assert_equals(1, scalar @$events);
    $self->assert_str_equals($uuid, $events->[0]{uid});
    $self->assert_str_equals('An Updated Event', $events->[0]{title});
    $self->assert_str_equals('2021-09-24T14:00:00', $events->[0]{start});
}

sub test_imip_override
    :needs_component_sieve :needs_component_httpd :min_version_3_5
{
    my ($self) = @_;

    my $IMAP = $self->{store}->get_client();
    $self->{store}->_select();
    $self->assert_num_equals(1, $IMAP->uid());
    $self->{store}->set_fetch_attributes(qw(uid flags));

    xlog $self, "Create calendar user";
    my $CalDAV = $self->{caldav};
    my $CalendarId = 'Default';
    my $uuid = "6de280c9-edff-4019-8ebd-cfebc73f8201";

    xlog $self, "Install a sieve script to process iMIP";
    $self->{instance}->install_sieve_script(<<EOF
require ["body", "variables", "imap4flags", "vnd.cyrus.imip"];
if body :content "text/calendar" :contains "\nMETHOD:" {
    processimip :outcome "outcome";
    if string "\${outcome}" "updated" {
        setflag "\\\\Flagged";
    }
}
EOF
    );

    my $imip = <<EOF;
Date: Thu, 23 Sep 2021 09:06:18 -0400
From: Foo <foo\@example.net>
To: Cassandane <cassandane\@example.com>
Message-ID: <$uuid-0\@example.net>
Content-Type: text/calendar; method=REQUEST; component=VEVENT
X-Cassandane-Unique: $uuid-0

BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.10.4//EN
METHOD:REQUEST
BEGIN:VEVENT
CREATED:20210923T034327Z
UID:$uuid
DTEND;TZID=America/New_York:20210923T183000
TRANSP:OPAQUE
SUMMARY:An Event
DTSTART;TZID=America/New_York:20210923T153000
DTSTAMP:20210923T034327Z
SEQUENCE:0
RRULE:FREQ=WEEKLY
ORGANIZER;CN=Test User:MAILTO:foo\@example.net
ATTENDEE;CN=Test User;PARTSTAT=ACCEPTED;RSVP=TRUE:MAILTO:foo\@example.net
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:MAILTO:cassandane\@example.com
END:VEVENT
END:VCALENDAR
EOF

    xlog $self, "Deliver iMIP invite";
    my $msg = Cassandane::Message->new(raw => $imip);
    $msg->set_attribute(uid => 1,
                        flags => [ '\\Recent', '\\Flagged' ]);
    $self->{instance}->deliver($msg);

    xlog $self, "Check that the message made it to INBOX";
    $self->check_messages({ 1 => $msg }, check_guid => 0);

    xlog $self, "Expunge the message";
    $IMAP->store('1', '+flags', '(\\Deleted)');
    $IMAP->expunge();

    xlog $self, "Check that the event made it to calendar";
    my $events = $CalDAV->GetEvents($CalendarId);
    $self->assert_equals(1, scalar @$events);
    $self->assert_str_equals($uuid, $events->[0]{uid});
    $self->assert_str_equals('An Event', $events->[0]{title});
    $self->assert_str_equals('2021-09-23T15:30:00', $events->[0]{start});

    xlog $self, "Get the event, set per-user data, and add an alarm";
    my $alarm = <<EOF;
BEGIN:VALARM
UID:myalarm
TRIGGER;RELATED=START:PT0S
ACTION:DISPLAY
DESCRIPTION:CYR-140
END:VALARM
EOF
    my $href = $events->[0]{href};
    my $response = $CalDAV->Request('GET', $href);
    my $ical = $response->{content};
    $ical =~ s/PARTSTAT=NEEDS-ACTION/PARTSTAT=ACCEPTED/;
    $ical =~ s/END:VEVENT/TRANSP:TRANSPARENT\n${alarm}END:VEVENT/;

    $CalDAV->Request('PUT', $href, $ical, 'Content-Type' => 'text/calendar');

    $imip = <<EOF;
Date: Thu, 24 Sep 2021 09:06:18 -0400
From: Foo <foo\@example.net>
To: Cassandane <cassandane\@example.com>
Message-ID: <$uuid-1\@example.net>
Content-Type: text/calendar; method=CANCEL; component=VEVENT
X-Cassandane-Unique: $uuid-1

BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.10.4//EN
METHOD:REQUEST
BEGIN:VEVENT
CREATED:20210923T034327Z
UID:$uuid
DTEND;TZID=America/New_York:20210923T183000
TRANSP:OPAQUE
SUMMARY:An Overridden Event
DTSTART;TZID=America/New_York:20210923T153000
DTSTAMP:20210924T034327Z
SEQUENCE:0
RECURRENCE-ID;TZID=America/New_York:20210923T153000
LOCATION:location2
ORGANIZER;CN=Test User:MAILTO:foo\@example.net
ATTENDEE;CN=Test User;PARTSTAT=ACCEPTED;RSVP=TRUE:MAILTO:foo\@example.net
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:MAILTO:cassandane\@example.com
END:VEVENT
END:VCALENDAR
EOF

    xlog $self, "Deliver iMIP update";
    $msg = Cassandane::Message->new(raw => $imip);
    $msg->set_attribute(uid => 2,
                        flags => [ '\\Recent', '\\Flagged' ]);
    $self->{instance}->deliver($msg);

    xlog $self, "Check that the message made it to INBOX";
    $self->check_messages({ 1 => $msg }, check_guid => 0);

    xlog $self, "Check that the updated event made it to calendar";
    $events = $CalDAV->GetEvents($CalendarId);

    $self->assert_equals(1, scalar @$events);
    $self->assert_str_equals($uuid, $events->[0]{uid});
    $self->assert_str_equals('An Overridden Event', $events->[0]{recurrenceOverrides}{'2021-09-23T15:30:00'}{title});
    $self->assert_str_equals('location2', $events->[0]{recurrenceOverrides}{'2021-09-23T15:30:00'}{locations}{location}{name});

    xlog $self, "Make sure that per-user data remains";
    $self->assert_equals(JSON::true, $events->[0]{showAsFree});
    $self->assert_not_null($events->[0]{alerts}{myalarm});
    $self->assert_str_equals('accepted', $events->[0]{participants}{'cassandane@example.com'}{scheduleStatus});    

    $response = $CalDAV->Request('GET', $href);
    $ical = Data::ICal->new(data => $response->{content});
    $self->assert_str_equals('TRANSPARENT', $ical->{entries}[0]{properties}{transp}[0]{value});
    $self->assert_str_equals('DISPLAY', $ical->{entries}[0]{entries}[0]{properties}{action}[0]{value});
    $self->assert_str_equals('TRANSPARENT', $ical->{entries}[1]{properties}{transp}[0]{value});
    $self->assert_str_equals('DISPLAY', $ical->{entries}[1]{entries}[0]{properties}{action}[0]{value});
}

sub test_imip_invite_single_then_master
    :needs_component_sieve :needs_component_httpd :min_version_3_7
{
    my ($self) = @_;

    my $IMAP = $self->{store}->get_client();
    $self->{store}->_select();
    $self->assert_num_equals(1, $IMAP->uid());
    $self->{store}->set_fetch_attributes(qw(uid flags));

    xlog $self, "Create calendar user";
    my $CalDAV = $self->{caldav};
    my $CalendarId = 'Default';
    my $uuid = "6de280c9-edff-4019-8ebd-cfebc73f8201";

    xlog $self, "Install a sieve script to process iMIP";
    $self->{instance}->install_sieve_script(<<EOF
require ["body", "variables", "imap4flags", "vnd.cyrus.imip"];
if body :content "text/calendar" :contains "\nMETHOD:" {
    processimip :outcome "outcome";
    if string "\${outcome}" "updated" {
        setflag "\\\\Flagged";
    }
}
EOF
    );

    my $imip = <<EOF;
Date: Thu, 23 Sep 2021 09:06:18 -0400
From: Foo <foo\@example.net>
To: Cassandane <cassandane\@example.com>
Message-ID: <$uuid-0\@example.net>
Content-Type: text/calendar; method=REQUEST; component=VEVENT
X-Cassandane-Unique: $uuid-0

BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.10.4//EN
METHOD:REQUEST
BEGIN:VEVENT
CREATED:20210923T034327Z
UID:$uuid
DTEND;TZID=America/New_York:20210923T183000
TRANSP:OPAQUE
SUMMARY:An Event
DTSTART;TZID=American/New_York:20210923T153000
DTSTAMP:20210923T034327Z
SEQUENCE:0
RECURRENCE-ID;TZID=American/New_York:20210923T153000
ORGANIZER;CN=Test User:MAILTO:foo\@example.net
ATTENDEE;CN=Test User;PARTSTAT=ACCEPTED;RSVP=TRUE:MAILTO:foo\@example.net
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:MAILTO:cassandane\@example.com
END:VEVENT
END:VCALENDAR
EOF

    xlog $self, "Deliver iMIP invite";
    my $msg = Cassandane::Message->new(raw => $imip);
    $self->{instance}->deliver($msg);

    xlog $self, "Check that the event made it to calendar";
    my $events = $CalDAV->GetEvents($CalendarId);
    $self->assert_equals(1, scalar @$events);
    $self->assert_str_equals($uuid, $events->[0]{uid});
    $self->assert_null($events->[0]{recurrenceRule});
    $self->assert_not_null($events->[0]{recurrenceOverrides});

    xlog $self, "Get and accept the event";
    my $href = $events->[0]{href};
    my $response = $CalDAV->Request('GET', $href);
    my $ical = $response->{content};
    $ical =~ s/PARTSTAT=NEEDS-ACTION/PARTSTAT=ACCEPTED/;

    $CalDAV->Request('PUT', $href, $ical, 'Content-Type' => 'text/calendar');

    $imip = <<EOF;
Date: Thu, 24 Sep 2021 09:06:18 -0400
From: Foo <foo\@example.net>
To: Cassandane <cassandane\@example.com>
Message-ID: <$uuid-1\@example.net>
Content-Type: text/calendar; method=CANCEL; component=VEVENT
X-Cassandane-Unique: $uuid-1

BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.10.4//EN
METHOD:REQUEST
BEGIN:VEVENT
CREATED:20210923T034327Z
UID:$uuid
DTEND;TZID=America/New_York:20210923T183000
TRANSP:OPAQUE
SUMMARY:An Overridden Event
DTSTART;TZID=American/New_York:20210923T153000
DTSTAMP:20210924T034327Z
SEQUENCE:0
RRULE:FREQ=WEEKLY
ORGANIZER;CN=Test User:MAILTO:foo\@example.net
ATTENDEE;CN=Test User;PARTSTAT=ACCEPTED;RSVP=TRUE:MAILTO:foo\@example.net
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:MAILTO:cassandane\@example.com
END:VEVENT
END:VCALENDAR
EOF

    xlog $self, "Deliver iMIP update";
    $msg = Cassandane::Message->new(raw => $imip);
    $self->{instance}->deliver($msg);

    xlog $self, "Check that the standalone instance was dropped from the calendar";
    $events = $CalDAV->GetEvents($CalendarId);

    $self->assert_equals(1, scalar @$events);
    $self->assert_str_equals($uuid, $events->[0]{uid});
    $self->assert_not_null($events->[0]{recurrenceRule});
    $self->assert_null($events->[0]{recurrenceOverrides});
    $self->assert_str_equals('needs-action', $events->[0]{participants}{'cassandane@example.com'}{scheduleStatus});    
}

sub test_imip_update_master_and_add_override
    :needs_component_sieve :needs_component_httpd :min_version_3_5
{
    # this test is mainly here to test that a crasher caused by Cyrus using
    # a libical component after it was freed
    my ($self) = @_;

    my $IMAP = $self->{store}->get_client();
    $self->{store}->_select();
    $self->assert_num_equals(1, $IMAP->uid());
    $self->{store}->set_fetch_attributes(qw(uid flags));

    xlog $self, "Create calendar user";
    my $CalDAV = $self->{caldav};
    my $CalendarId = 'Default';
    my $uuid = "6de280c9-edff-4019-8ebd-cfebc73f8201";

    xlog $self, "Install a sieve script to process iMIP";
    $self->{instance}->install_sieve_script(<<EOF
require ["body", "variables", "imap4flags", "vnd.cyrus.imip"];
if body :content "text/calendar" :contains "\nMETHOD:" {
    processimip :outcome "outcome";
    if string "\${outcome}" "updated" {
        setflag "\\\\Flagged";
    }
}
EOF
    );

    my $imip = <<EOF;
Date: Thu, 23 Sep 2021 09:06:18 -0400
From: Foo <foo\@example.net>
To: Cassandane <cassandane\@example.com>
Message-ID: <$uuid-0\@example.net>
Content-Type: text/calendar; method=REQUEST; component=VEVENT
X-Cassandane-Unique: $uuid-0

BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.10.4//EN
METHOD:REQUEST
BEGIN:VEVENT
CREATED:20210923T034327Z
UID:$uuid
DTEND;TZID=America/New_York:20210923T183000
TRANSP:OPAQUE
SUMMARY:An Event
DTSTART;TZID=America/New_York:20210923T153000
DTSTAMP:20210923T034327Z
SEQUENCE:0
ORGANIZER;CN=Test User:MAILTO:foo\@example.net
ATTENDEE;CN=Test User;PARTSTAT=ACCEPTED;RSVP=TRUE:MAILTO:foo\@example.net
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:MAILTO:cassandane\@example.com
END:VEVENT
END:VCALENDAR
EOF

    xlog $self, "Deliver iMIP invite";
    my $msg = Cassandane::Message->new(raw => $imip);
    $msg->set_attribute(uid => 1,
                        flags => [ '\\Recent', '\\Flagged' ]);
    $self->{instance}->deliver($msg);

    xlog $self, "Check that the message made it to INBOX";
    $self->check_messages({ 1 => $msg }, check_guid => 0);

    xlog $self, "Expunge the message";
    $IMAP->store('1', '+flags', '(\\Deleted)');
    $IMAP->expunge();

    xlog $self, "Check that the event made it to calendar";
    my $events = $CalDAV->GetEvents($CalendarId);
    $self->assert_equals(1, scalar @$events);
    $self->assert_str_equals($uuid, $events->[0]{uid});
    $self->assert_str_equals('An Event', $events->[0]{title});
    $self->assert_str_equals('2021-09-23T15:30:00', $events->[0]{start});


    xlog $self, "Get the event, set per-user data, and add an alarm";
    my $alarm = <<EOF;
BEGIN:VALARM
UID:myalarm
TRIGGER;RELATED=START:PT0S
ACTION:DISPLAY
DESCRIPTION:CYR-140
END:VALARM
EOF
    my $href = $events->[0]{href};
    my $response = $CalDAV->Request('GET', $href);
    my $ical = $response->{content};
    $ical =~ s/PARTSTAT=NEEDS-ACTION/PARTSTAT=ACCEPTED/;
    $ical =~ s/END:VEVENT/TRANSP:TRANSPARENT\n${alarm}END:VEVENT/;

    $CalDAV->Request('PUT', $href, $ical, 'Content-Type' => 'text/calendar');

    $imip = <<EOF;
Date: Thu, 24 Sep 2021 09:06:18 -0400
From: Foo <foo\@example.net>
To: Cassandane <cassandane\@example.com>
Message-ID: <$uuid-1\@example.net>
Content-Type: text/calendar; method=CANCEL; component=VEVENT
X-Cassandane-Unique: $uuid-1

BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.10.4//EN
METHOD:REQUEST
BEGIN:VEVENT
CREATED:20210923T034327Z
UID:$uuid
DTEND;TZID=America/New_York:20210924T170000
TRANSP:OPAQUE
SUMMARY:An Updated Event
DTSTART;TZID=America/New_York:20210924T140000
DTSTAMP:20210923T034327Z
SEQUENCE:1
ORGANIZER;CN=Test User:MAILTO:foo\@example.net
ATTENDEE;CN=Test User;PARTSTAT=ACCEPTED;RSVP=TRUE:MAILTO:foo\@example.net
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:MAILTO:cassandane\@example.com
END:VEVENT
BEGIN:VEVENT
CREATED:20210923T034327Z
UID:$uuid
DTEND;TZID=America/New_York:20210924T183000
TRANSP:OPAQUE
SUMMARY:An Overridden Event
DTSTART;TZID=America/New_York:20210924T153000
DTSTAMP:20210924T034327Z
SEQUENCE:0
RECURRENCE-ID;TZID=America/New_York:20210924T153000
LOCATION:location2
ORGANIZER;CN=Test User:MAILTO:foo\@example.net
ATTENDEE;CN=Test User;PARTSTAT=ACCEPTED;RSVP=TRUE:MAILTO:foo\@example.net
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:MAILTO:cassandane\@example.com
END:VEVENT
END:VCALENDAR
EOF

    xlog $self, "Deliver iMIP update";
    $msg = Cassandane::Message->new(raw => $imip);
    $msg->set_attribute(uid => 2,
                        flags => [ '\\Recent', '\\Flagged' ]);
    $self->{instance}->deliver($msg);

    xlog $self, "Check that the message made it to INBOX";
    $self->check_messages({ 1 => $msg }, check_guid => 0);

    xlog $self, "Check that the event was updated on calendar";
    $events = $CalDAV->GetEvents($CalendarId);
    $self->assert_equals(1, scalar @$events);
    $self->assert_str_equals($uuid, $events->[0]{uid});
    $self->assert_str_equals('An Updated Event', $events->[0]{title});
    $self->assert_str_equals('2021-09-24T14:00:00', $events->[0]{start});
}

sub test_imip_cancel_instance
    :needs_component_sieve :needs_component_httpd :min_version_3_7
{
    my ($self) = @_;

    my $IMAP = $self->{store}->get_client();
    $self->{store}->_select();
    $self->assert_num_equals(1, $IMAP->uid());
    $self->{store}->set_fetch_attributes(qw(uid flags));

    xlog $self, "Create calendar user";
    my $CalDAV = $self->{caldav};
    my $CalendarId = 'Default';
    my $uuid = "6de280c9-edff-4019-8ebd-cfebc73f8201";

    xlog $self, "Install a sieve script to process iMIP";
    $self->{instance}->install_sieve_script(<<EOF
require ["body", "variables", "imap4flags", "vnd.cyrus.imip"];
if body :content "text/calendar" :contains "\nMETHOD:" {
    processimip :deletecanceled :outcome "outcome";
    if string "\${outcome}" "updated" {
        setflag "\\\\Flagged";
    }
}
EOF
    );

    my $imip = <<EOF;
Date: Thu, 23 Sep 2021 09:06:18 -0400
From: Foo <foo\@example.net>
To: Cassandane <cassandane\@example.com>
Message-ID: <$uuid-0\@example.net>
Content-Type: text/calendar; method=REQUEST; component=VEVENT
X-Cassandane-Unique: $uuid-0

BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.10.4//EN
METHOD:REQUEST
BEGIN:VEVENT
CREATED:20210923T034327Z
UID:$uuid
DTEND;TZID=America/New_York:20210923T183000
TRANSP:OPAQUE
SUMMARY:An Event
DTSTART;TZID=America/New_York:20210923T153000
DTSTAMP:20210923T034327Z
SEQUENCE:0
RRULE:FREQ=WEEKLY
ORGANIZER;CN=Test User:MAILTO:foo\@example.net
ATTENDEE;CN=Test User;PARTSTAT=ACCEPTED;RSVP=TRUE:MAILTO:foo\@example.net
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:MAILTO:cassandane\@example.com
END:VEVENT
END:VCALENDAR
EOF

    xlog $self, "Deliver iMIP invite";
    my $msg = Cassandane::Message->new(raw => $imip);
    $msg->set_attribute(uid => 1,
                        flags => [ '\\Recent', '\\Flagged' ]);
    $self->{instance}->deliver($msg);

    xlog $self, "Check that the message made it to INBOX";
    $self->check_messages({ 1 => $msg }, check_guid => 0);

    xlog $self, "Expunge the message";
    $IMAP->store('1', '+flags', '(\\Deleted)');
    $IMAP->expunge();

    xlog $self, "Check that the event made it to calendar";
    my $events = $CalDAV->GetEvents($CalendarId);
    $self->assert_equals(1, scalar @$events);
    $self->assert_str_equals($uuid, $events->[0]{uid});
    $self->assert_str_equals('An Event', $events->[0]{title});
    $self->assert_str_equals('2021-09-23T15:30:00', $events->[0]{start});
    my $href = $events->[0]{href};

    $imip = <<EOF;
Date: Thu, 24 Sep 2021 09:06:18 -0400
From: Foo <foo\@example.net>
To: Cassandane <cassandane\@example.com>
Message-ID: <$uuid-1\@example.net>
Content-Type: text/calendar; method=CANCEL; component=VEVENT
X-Cassandane-Unique: $uuid-1

BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.10.4//EN
METHOD:CANCEL
BEGIN:VEVENT
UID:$uuid
DTSTAMP:20210924T034327Z
SEQUENCE:1
STATUS:CANCELLED
RECURRENCE-ID;TZID=America/New_York:20210923T153000
ORGANIZER;CN=Test User:MAILTO:foo\@example.net
ATTENDEE;CN=Test User;PARTSTAT=ACCEPTED;RSVP=TRUE:MAILTO:foo\@example.net
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:MAILTO:cassandane\@example.com
END:VEVENT
END:VCALENDAR
EOF

    xlog $self, "Deliver iMIP cancel";
    $msg = Cassandane::Message->new(raw => $imip);
    $msg->set_attribute(uid => 2,
                        flags => [ '\\Recent', '\\Flagged' ]);
    $self->{instance}->deliver($msg);

    xlog $self, "Check that the message made it to INBOX";
    $self->check_messages({ 1 => $msg }, check_guid => 0);

    xlog $self, "Check that the updated event made it to calendar";
    $events = $CalDAV->GetEvents($CalendarId);

    $self->assert_equals(1, scalar @$events);
    $self->assert_str_equals($uuid, $events->[0]{uid});
    $self->assert_equals(JSON::null,
                         $events->[0]{recurrenceOverrides}{'2021-09-23T15:30:00'});
}

sub test_imip_preserve_alerts
    :needs_component_sieve :needs_component_httpd :min_version_3_5
{
    my ($self) = @_;

    my $IMAP = $self->{store}->get_client();
    $self->{store}->_select();
    $self->assert_num_equals(1, $IMAP->uid());
    $self->{store}->set_fetch_attributes(qw(uid flags));

    xlog $self, "Create calendar user";
    my $CalDAV = $self->{caldav};
    my $CalendarId = 'Default';
    my $uuid = "6de280c9-edff-4019-8ebd-cfebc73f8201";

    xlog $self, "Install a sieve script to process iMIP";
    $self->{instance}->install_sieve_script(<<EOF
require ["body", "variables", "imap4flags", "vnd.cyrus.imip"];
if body :content "text/calendar" :contains "\nMETHOD:" {
    processimip :outcome "outcome";
    if string "\${outcome}" "updated" {
        setflag "\\\\Flagged";
    }
}
EOF
    );

    my $imip = <<EOF;
Date: Thu, 23 Sep 2021 09:06:18 -0400
From: Foo <foo\@example.net>
To: Cassandane <cassandane\@example.com>
Message-ID: <$uuid-0\@example.net>
Content-Type: text/calendar; method=REQUEST; component=VEVENT
X-Cassandane-Unique: $uuid-0

BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.10.4//EN
METHOD:REQUEST
BEGIN:VEVENT
CREATED:20210923T034327Z
UID:$uuid
DTEND;TZID=America/New_York:20210923T183000
TRANSP:OPAQUE
SUMMARY:An Event
DTSTART;TZID=America/New_York:20210923T153000
DTSTAMP:20210923T034327Z
SEQUENCE:0
RRULE:FREQ=WEEKLY
ORGANIZER;CN=Test User:MAILTO:foo\@example.net
ATTENDEE;CN=Test User;PARTSTAT=ACCEPTED;RSVP=TRUE:MAILTO:foo\@example.net
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:MAILTO:cassandane\@example.com
END:VEVENT
END:VCALENDAR
EOF

    xlog $self, "Deliver initial iMIP invite";
    my $msg = Cassandane::Message->new(raw => $imip);
    $self->{instance}->deliver($msg);

    $imip = <<EOF;
Date: Thu, 24 Sep 2021 09:06:18 -0400
From: Foo <foo\@example.net>
To: Cassandane <cassandane\@example.com>
Message-ID: <$uuid-1\@example.net>
Content-Type: text/calendar; method=CANCEL; component=VEVENT
X-Cassandane-Unique: $uuid-1

BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.10.4//EN
METHOD:REQUEST
BEGIN:VEVENT
CREATED:20210923T034327Z
UID:$uuid
DTEND;TZID=America/New_York:20210923T183000
TRANSP:OPAQUE
SUMMARY:An Overridden Event
DTSTART;TZID=America/New_York:20210923T153000
DTSTAMP:20210924T034327Z
SEQUENCE:0
RECURRENCE-ID;TZID=America/New_York:20210923T153000
LOCATION:location2
ORGANIZER;CN=Test User:MAILTO:foo\@example.net
ATTENDEE;CN=Test User;PARTSTAT=ACCEPTED;RSVP=TRUE:MAILTO:foo\@example.net
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:MAILTO:cassandane\@example.com
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:MAILTO:bar\@example.net
END:VEVENT
END:VCALENDAR
EOF

    xlog $self, "Add another attendee to a single instance";
    $msg = Cassandane::Message->new(raw => $imip);
    $self->{instance}->deliver($msg);

    xlog $self, "Get the event and add an alarm";
    my $alarm = <<EOF;
BEGIN:VALARM
UID:myalarm
TRIGGER;RELATED=START:PT0S
ACTION:DISPLAY
DESCRIPTION:CYR-140
END:VALARM
EOF

    my $events = $CalDAV->GetEvents($CalendarId);
    my $href = $events->[0]{href};
    my $response = $CalDAV->Request('GET', $href);
    my $ical = $response->{content};
    $ical =~ s/END:VEVENT/${alarm}END:VEVENT/g;

    $CalDAV->Request('PUT', $href, $ical, 'Content-Type' => 'text/calendar');

    $imip = <<EOF;
Date: Thu, 23 Sep 2021 09:06:18 -0400
From: Foo <foo\@example.net>
To: Cassandane <cassandane\@example.com>
Message-ID: <$uuid-0\@example.net>
Content-Type: text/calendar; method=REQUEST; component=VEVENT
X-Cassandane-Unique: $uuid-2

BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.10.4//EN
METHOD:REQUEST
BEGIN:VEVENT
CREATED:20210923T034327Z
UID:$uuid
DTEND;TZID=America/New_York:20210923T183000
TRANSP:OPAQUE
SUMMARY:An Event
DTSTART;TZID=America/New_York:20210923T153000
DTSTAMP:20210925T034327Z
SEQUENCE:0
RRULE:FREQ=WEEKLY
ORGANIZER;CN=Test User:MAILTO:foo\@example.net
ATTENDEE;CN=Test User;PARTSTAT=ACCEPTED;RSVP=TRUE:MAILTO:foo\@example.net
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:MAILTO:cassandane\@example.com
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:MAILTO:bar\@example.net
END:VEVENT
BEGIN:VEVENT
CREATED:20210923T034327Z
UID:$uuid
DTEND;TZID=America/New_York:20210923T183000
TRANSP:OPAQUE
SUMMARY:An Overridden Event
DTSTART;TZID=American/New_York:20210923T153000
DTSTAMP:20210924T034327Z
SEQUENCE:0
RECURRENCE-ID;TZID=American/New_York:20210923T153000
LOCATION:location2
ORGANIZER;CN=Test User:MAILTO:foo\@example.net
ATTENDEE;CN=Test User;PARTSTAT=ACCEPTED;RSVP=TRUE:MAILTO:foo\@example.net
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:MAILTO:cassandane\@example.com
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:MAILTO:bar\@example.net
END:VEVENT
END:VCALENDAR
EOF

    xlog $self, "Update the master to include the other user";
    $msg = Cassandane::Message->new(raw => $imip);
    $self->{instance}->deliver($msg);

    xlog $self, "Make sure that alarms remain";
    $events = $CalDAV->GetEvents($CalendarId);

    $response = $CalDAV->Request('GET', $href);
    $ical = Data::ICal->new(data => $response->{content});
    $self->assert_str_equals('DISPLAY', $ical->{entries}[0]{entries}[0]{properties}{action}[0]{value});
    $self->assert_str_equals('DISPLAY', $ical->{entries}[1]{entries}[0]{properties}{action}[0]{value});
}

sub test_imip_cancel
    :needs_component_sieve :needs_component_httpd :min_version_3_5
{
    my ($self) = @_;

    my $IMAP = $self->{store}->get_client();
    $self->{store}->_select();
    $self->assert_num_equals(1, $IMAP->uid());
    $self->{store}->set_fetch_attributes(qw(uid flags));

    xlog $self, "Create calendar user";
    my $CalDAV = $self->{caldav};
    my $CalendarId = 'Default';
    my $uuid = "6de280c9-edff-4019-8ebd-cfebc73f8201";

    xlog $self, "Install a sieve script to process iMIP";
    $self->{instance}->install_sieve_script(<<EOF
require ["body", "variables", "imap4flags", "vnd.cyrus.imip"];
if body :content "text/calendar" :contains "\nMETHOD:" {
    processimip :outcome "outcome";
    if string "\${outcome}" "updated" {
        setflag "\\\\Flagged";
    }
}
EOF
    );

    my $imip = <<EOF;
Date: Thu, 23 Sep 2021 09:06:18 -0400
From: Foo <foo\@example.net>
To: Cassandane <cassandane\@example.com>
Message-ID: <$uuid-0\@example.net>
Content-Type: text/calendar; method=REQUEST; component=VEVENT
X-Cassandane-Unique: $uuid-0

BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.10.4//EN
METHOD:REQUEST
BEGIN:VEVENT
CREATED:20210923T034327Z
UID:$uuid
DTEND;TZID=America/New_York:20210923T183000
TRANSP:OPAQUE
SUMMARY:An Event
DTSTART;TZID=America/New_York:20210923T153000
DTSTAMP:20210923T034327Z
SEQUENCE:0
STATUS:TENTATIVE
ORGANIZER;CN=Test User:MAILTO:foo\@example.net
ATTENDEE;CN=Test User;PARTSTAT=ACCEPTED;RSVP=TRUE:MAILTO:foo\@example.net
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:MAILTO:cassandane\@example.com
END:VEVENT
END:VCALENDAR
EOF

    xlog $self, "Deliver iMIP invite";
    my $msg = Cassandane::Message->new(raw => $imip);
    $msg->set_attribute(uid => 1,
                        flags => [ '\\Recent', '\\Flagged' ]);
    $self->{instance}->deliver($msg);

    xlog $self, "Check that the message made it to INBOX";
    $self->check_messages({ 1 => $msg }, check_guid => 0);

    xlog $self, "Expunge the message";
    $IMAP->store('1', '+flags', '(\\Deleted)');
    $IMAP->expunge();

    xlog $self, "Check that the event made it to calendar";
    my $events = $CalDAV->GetEvents($CalendarId);
    $self->assert_equals(1, scalar @$events);
    $self->assert_str_equals($uuid, $events->[0]{uid});
    $self->assert_str_equals('tentative', $events->[0]{status});


    $imip = <<EOF;
Date: Thu, 24 Sep 2021 09:06:18 -0400
From: Foo <foo\@example.net>
To: Cassandane <cassandane\@example.com>
Message-ID: <$uuid-1\@example.net>
Content-Type: text/calendar; method=CANCEL; component=VEVENT
X-Cassandane-Unique: $uuid-1

BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.10.4//EN
METHOD:CANCEL
BEGIN:VEVENT
CREATED:20210924T034327Z
UID:$uuid
DTSTAMP:20210924T034327Z
SEQUENCE:1
ORGANIZER;CN=Test User:MAILTO:foo\@example.net
ATTENDEE;CN=Test User:MAILTO:foo\@example.net
ATTENDEE:MAILTO:cassandane\@example.com
END:VEVENT
END:VCALENDAR
EOF

    xlog $self, "Deliver iMIP cancel";
    $msg = Cassandane::Message->new(raw => $imip);
    $msg->set_attribute(uid => 2,
                        flags => [ '\\Recent', '\\Flagged' ]);
    $self->{instance}->deliver($msg);

    xlog $self, "Check that the message made it to INBOX";
    $self->check_messages({ 1 => $msg }, check_guid => 0);

    xlog $self, "Check that the event was removed from calendar";
    $events = $CalDAV->GetEvents($CalendarId);
    $self->assert_equals(1, scalar @$events);
    $self->assert_str_equals($uuid, $events->[0]{uid});
    $self->assert_str_equals('cancelled', $events->[0]{status});
}

sub test_imip_cancel_delete
    :needs_component_sieve :needs_component_httpd :min_version_3_5
{
    my ($self) = @_;

    my $IMAP = $self->{store}->get_client();
    $self->{store}->_select();
    $self->assert_num_equals(1, $IMAP->uid());
    $self->{store}->set_fetch_attributes(qw(uid flags));

    xlog $self, "Create calendar user";
    my $CalDAV = $self->{caldav};
    my $CalendarId = 'Default';
    my $uuid = "6de280c9-edff-4019-8ebd-cfebc73f8201";

    xlog $self, "Install a sieve script to process iMIP";
    $self->{instance}->install_sieve_script(<<EOF
require ["body", "variables", "imap4flags", "vnd.cyrus.imip"];
if body :content "text/calendar" :contains "\nMETHOD:" {
    processimip :deletecanceled :outcome "outcome";
    if string "\${outcome}" "deleted" {
        setflag "\\\\Flagged";
    }
}
EOF
    );

    my $imip = <<EOF;
Date: Thu, 23 Sep 2021 09:06:18 -0400
From: Foo <foo\@example.net>
To: Cassandane <cassandane\@example.com>
Message-ID: <$uuid-0\@example.net>
Content-Type: text/calendar; method=REQUEST; component=VEVENT
X-Cassandane-Unique: $uuid-0

BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.10.4//EN
METHOD:REQUEST
BEGIN:VEVENT
CREATED:20210923T034327Z
UID:$uuid
DTEND;TZID=America/New_York:20210923T183000
TRANSP:OPAQUE
SUMMARY:An Event
DTSTART;TZID=America/New_York:20210923T153000
DTSTAMP:20210923T034327Z
SEQUENCE:0
ORGANIZER;CN=Test User:MAILTO:foo\@example.net
ATTENDEE;CN=Test User;PARTSTAT=ACCEPTED;RSVP=TRUE:MAILTO:foo\@example.net
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:MAILTO:cassandane\@example.com
END:VEVENT
END:VCALENDAR
EOF
    xlog $self, "Deliver iMIP invite";
    my $msg = Cassandane::Message->new(raw => $imip);
    $msg->set_attribute(uid => 1,
                        flags => [ '\\Recent', '\\Flagged' ]);
    $self->{instance}->deliver($msg);

    xlog $self, "Check that the message made it to INBOX";
    $self->check_messages({ 1 => $msg }, check_guid => 0);

    xlog $self, "Expunge the message";
    $IMAP->store('1', '+flags', '(\\Deleted)');
    $IMAP->expunge();

    xlog $self, "Check that the event made it to calendar";
    my $events = $CalDAV->GetEvents($CalendarId);
    $self->assert_equals(1, scalar @$events);
    $self->assert_str_equals($uuid, $events->[0]{uid});


    $imip = <<EOF;
Date: Thu, 24 Sep 2021 09:06:18 -0400
From: Foo <foo\@example.net>
To: Cassandane <cassandane\@example.com>
Message-ID: <$uuid-1\@example.net>
Content-Type: text/calendar; method=CANCEL; component=VEVENT
X-Cassandane-Unique: $uuid-1

BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.10.4//EN
METHOD:CANCEL
BEGIN:VEVENT
CREATED:20210924T034327Z
UID:$uuid
DTSTAMP:20210924T034327Z
SEQUENCE:1
ORGANIZER;CN=Test User:MAILTO:foo\@example.net
ATTENDEE;CN=Test User:MAILTO:foo\@example.net
ATTENDEE:MAILTO:cassandane\@example.com
END:VEVENT
END:VCALENDAR
EOF

    xlog $self, "Deliver iMIP cancel";
    $msg = Cassandane::Message->new(raw => $imip);
    $msg->set_attribute(uid => 2,
                        flags => [ '\\Recent', '\\Flagged' ]);
    $self->{instance}->deliver($msg);

    xlog $self, "Check that the message made it to INBOX";
    $self->check_messages({ 1 => $msg }, check_guid => 0);

    xlog $self, "Check that the event was removed from calendar";
    $events = $CalDAV->GetEvents($CalendarId);
    $self->assert_deep_equals($events, []);
}

sub test_imip_reply
    :needs_component_sieve :needs_component_httpd :min_version_3_5
{
    my ($self) = @_;

    my $IMAP = $self->{store}->get_client();
    $self->{store}->_select();
    $self->assert_num_equals(1, $IMAP->uid());
    $self->{store}->set_fetch_attributes(qw(uid flags));

    xlog $self, "Create calendar user";
    my $CalDAV = $self->{caldav};
    my $CalendarId = 'Default';
    my $uuid = "6de280c9-edff-4019-8ebd-cfebc73f8201";
    my $href = "$CalendarId/$uuid.ics";

    xlog $self, "Install a sieve script to process iMIP";
    $self->{instance}->install_sieve_script(<<EOF
require ["body", "variables", "imap4flags", "vnd.cyrus.imip"];
if body :content "text/calendar" :contains "\nMETHOD:" {
    processimip :outcome "outcome";
    if string "\${outcome}" "updated" {
        setflag "\\\\Flagged";
    }
}
EOF
    );

    my $event = <<EOF;
BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.10.4//EN
BEGIN:VEVENT
CREATED:20210923T034327Z
UID:$uuid
DTEND;TZID=America/New_York:20210923T183000
TRANSP:OPAQUE
SUMMARY:An Event
DTSTART;TZID=America/New_York:20210923T153000
DTSTAMP:20210923T034327Z
SEQUENCE:0
ORGANIZER;CN=Cassandane:MAILTO:cassandane\@example.com
ATTENDEE;CN=Cassandane;PARTSTAT=ACCEPTED:MAILTO:cassandane\@example.com
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:MAILTO:foo\@example.net
END:VEVENT
END:VCALENDAR
EOF

    xlog $self, "Create an event on calendar";
    $CalDAV->Request('PUT', $href, $event, 'Content-Type' => 'text/calendar');

    xlog $self, "Check that the event made it to calendar";
    my $events = $CalDAV->GetEvents($CalendarId);
    $self->assert_equals(1, scalar @$events);
    $self->assert_str_equals($uuid, $events->[0]{uid});
    $self->assert_str_equals('',
                             $events->[0]{participants}{'foo@example.net'}{name});
    $self->assert_str_equals('needs-action',
                             $events->[0]{participants}{'foo@example.net'}{scheduleStatus});


    my $imip = <<EOF;
Date: Thu, 23 Sep 2021 09:06:18 -0400
From: Foo <foo\@example.net>
To: Cassandane <cassandane\@example.com>
Message-ID: <$uuid\@example.net>
Content-Type: text/calendar; method=REPLY; component=VEVENT
X-Cassandane-Unique: $uuid

BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.10.4//EN
METHOD:REPLY
BEGIN:VEVENT
UID:$uuid
DTSTAMP:20210923T034327Z
SEQUENCE:0
ORGANIZER;CN=Cassandane:MAILTO:cassandane\@example.com
ATTENDEE;CN=Test User;PARTSTAT=ACCEPTED;RSVP=TRUE:MAILTO:foo\@example.net
END:VEVENT
END:VCALENDAR
EOF

    xlog $self, "Deliver iMIP reply";
    my $msg = Cassandane::Message->new(raw => $imip);
    $msg->set_attribute(uid => 1,
                        flags => [ '\\Recent', '\\Flagged' ]);
    $self->{instance}->deliver($msg);

    xlog $self, "Check that the message made it to INBOX";
    $self->check_messages({ 1 => $msg }, check_guid => 0);

    xlog $self, "Check that the reply made it to calendar";
    $events = $CalDAV->GetEvents($CalendarId);
    $self->assert_equals(1, scalar @$events);
    $self->assert_str_equals($uuid, $events->[0]{uid});
    $self->assert_str_equals('Test User',
                             $events->[0]{participants}{'foo@example.net'}{name});
    $self->assert_str_equals('accepted',
                             $events->[0]{participants}{'foo@example.net'}{scheduleStatus});
}

sub test_imip_reply_override
    :needs_component_sieve :needs_component_httpd :min_version_3_5
{
    my ($self) = @_;

    my $IMAP = $self->{store}->get_client();
    $self->{store}->_select();
    $self->assert_num_equals(1, $IMAP->uid());
    $self->{store}->set_fetch_attributes(qw(uid flags));

    xlog $self, "Create calendar user";
    my $CalDAV = $self->{caldav};
    my $CalendarId = 'Default';
    my $uuid = "6de280c9-edff-4019-8ebd-cfebc73f8201";
    my $href = "$CalendarId/$uuid.ics";

    xlog $self, "Install a sieve script to process iMIP";
    $self->{instance}->install_sieve_script(<<EOF
require ["body", "variables", "imap4flags", "vnd.cyrus.imip"];
if body :content "text/calendar" :contains "\nMETHOD:" {
    processimip :outcome "outcome";
    if string "\${outcome}" "updated" {
        setflag "\\\\Flagged";
    }
}
EOF
    );

    my $event = <<EOF;
BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.10.4//EN
BEGIN:VEVENT
CREATED:20211014T034327Z
UID:$uuid
TRANSP:OPAQUE
SUMMARY:A Recurring Event
DTSTART;TZID=America/New_York:20211014T153000
DTEND;TZID=America/New_York:20211014T183000
RRULE:FREQ=WEEKLY
DTSTAMP:20211014T034327Z
SEQUENCE:0
ORGANIZER;CN=Cassandane:MAILTO:cassandane\@example.com
ATTENDEE;CN=Cassandane;PARTSTAT=ACCEPTED:MAILTO:cassandane\@example.com
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:MAILTO:foo\@example.net
END:VEVENT
END:VCALENDAR
EOF

    xlog $self, "Create an event on calendar";
    $CalDAV->Request('PUT', $href, $event, 'Content-Type' => 'text/calendar');

    xlog $self, "Check that the event made it to calendar";
    my $events = $CalDAV->GetEvents($CalendarId);
    $self->assert_equals(1, scalar @$events);
    $self->assert_str_equals($uuid, $events->[0]{uid});
    $self->assert_str_equals('',
                             $events->[0]{participants}{'foo@example.net'}{name});
    $self->assert_str_equals('needs-action',
                             $events->[0]{participants}{'foo@example.net'}{scheduleStatus});


    my $imip = <<EOF;
Date: Thu, 23 Sep 2021 09:06:18 -0400
From: Foo <foo\@example.net>
To: Cassandane <cassandane\@example.com>
Message-ID: <$uuid\@example.net>
Content-Type: text/calendar; method=REPLY; component=VEVENT
X-Cassandane-Unique: $uuid

BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.10.4//EN
METHOD:REPLY
BEGIN:VEVENT
UID:$uuid
DTSTAMP:20210923T034327Z
SEQUENCE:0
ORGANIZER;CN=Cassandane:MAILTO:cassandane\@example.com
ATTENDEE;CN=Test User;PARTSTAT=ACCEPTED;RSVP=TRUE:MAILTO:foo\@example.net
END:VEVENT
BEGIN:VEVENT
UID:$uuid
DTSTAMP:20210923T034327Z
SEQUENCE:0
ORGANIZER;CN=Cassandane:MAILTO:cassandane\@example.com
ATTENDEE;CN=Test User;PARTSTAT=DECLINED:MAILTO:foo\@example.net
RECURRENCE-ID;TZID=America/New_York:20211021T153000
END:VEVENT
END:VCALENDAR
EOF

    xlog $self, "Deliver iMIP reply";
    my $msg = Cassandane::Message->new(raw => $imip);
    $msg->set_attribute(uid => 1,
                        flags => [ '\\Recent', '\\Flagged' ]);
    $self->{instance}->deliver($msg);

    xlog $self, "Check that the message made it to INBOX";
    $self->check_messages({ 1 => $msg }, check_guid => 0);

    xlog $self, "Check that the reply made it to calendar";
    $events = $CalDAV->GetEvents($CalendarId);
    $self->assert_equals(1, scalar @$events);
    $self->assert_str_equals($uuid, $events->[0]{uid});
    $self->assert_str_equals('Test User',
                             $events->[0]{participants}{'foo@example.net'}{name});
    $self->assert_str_equals('accepted',
                             $events->[0]{participants}{'foo@example.net'}{scheduleStatus});

    $self->assert_str_equals('accepted',
                             $events->[0]{recurrenceOverrides}{'2021-10-21T15:30:00'}{participants}{'cassandane@example.com'}{scheduleStatus});
    $self->assert_str_equals('declined',
                             $events->[0]{recurrenceOverrides}{'2021-10-21T15:30:00'}{participants}{'foo@example.net'}{scheduleStatus});
}

sub test_imip_reply_override_google
    :needs_component_sieve :needs_component_httpd :min_version_3_7
{
    my ($self) = @_;

    my $IMAP = $self->{store}->get_client();
    $self->{store}->_select();
    $self->assert_num_equals(1, $IMAP->uid());
    $self->{store}->set_fetch_attributes(qw(uid flags));

    xlog $self, "Create calendar user";
    my $CalDAV = $self->{caldav};
    my $CalendarId = 'Default';
    my $uuid = "6de280c9-edff-4019-8ebd-cfebc73f8201";
    my $href = "$CalendarId/$uuid.ics";

    xlog $self, "Install a sieve script to process iMIP";
    $self->{instance}->install_sieve_script(<<EOF
require ["body", "variables", "imap4flags", "vnd.cyrus.imip"];
if body :content "text/calendar" :contains "\nMETHOD:" {
    processimip :outcome "outcome";
    if string "\${outcome}" "updated" {
        setflag "\\\\Flagged";
    }
}
EOF
    );

    my $event = <<EOF;
BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.10.4//EN
BEGIN:VEVENT
CREATED:20210714T034327Z
UID:$uuid
TRANSP:OPAQUE
SUMMARY:A Recurring Event
DTSTART;TZID=America/New_York:20210714T153000
DTEND;TZID=America/New_York:20210714T183000
RRULE:FREQ=WEEKLY
DTSTAMP:20210714T034327Z
SEQUENCE:0
ORGANIZER;CN=Cassandane:MAILTO:cassandane\@example.com
ATTENDEE;CN=Cassandane;PARTSTAT=ACCEPTED:MAILTO:cassandane\@example.com
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:MAILTO:foo\@example.net
END:VEVENT
BEGIN:VEVENT
CREATED:20210714T034327Z
UID:$uuid
TRANSP:OPAQUE
SUMMARY:A Recurring Event
DTSTART;TZID=America/New_York:20210722T153000
DTEND;TZID=America/New_York:20210722T183000
RECURRENCE-ID;TZID=America/New_York:20210721T153000
DTSTAMP:20210714T034327Z
SEQUENCE:0
ORGANIZER;CN=Cassandane:MAILTO:cassandane\@example.com
ATTENDEE;CN=Cassandane;PARTSTAT=ACCEPTED:MAILTO:cassandane\@example.com
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:MAILTO:foo\@example.net
END:VEVENT
END:VCALENDAR
EOF

    xlog $self, "Create an event on calendar";
    $CalDAV->Request('PUT', $href, $event, 'Content-Type' => 'text/calendar');

    xlog $self, "Check that the event made it to calendar";
    my $events = $CalDAV->GetEvents($CalendarId);
    $self->assert_equals(1, scalar @$events);
    $self->assert_str_equals($uuid, $events->[0]{uid});
    $self->assert_str_equals('',
                             $events->[0]{participants}{'foo@example.net'}{name});
    $self->assert_str_equals('needs-action',
                             $events->[0]{participants}{'foo@example.net'}{scheduleStatus});


    my $imip = <<EOF;
Date: Thu, 23 Sep 2021 09:06:18 -0400
From: Foo <foo\@example.net>
To: Cassandane <cassandane\@example.com>
Message-ID: <$uuid\@example.net>
Content-Type: text/calendar; method=REPLY; component=VEVENT
X-Cassandane-Unique: $uuid

BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.10.4//EN
METHOD:REPLY
BEGIN:VEVENT
UID:$uuid
DTSTAMP:20210723T034327Z
SEQUENCE:0
ORGANIZER;CN=Cassandane:MAILTO:cassandane\@example.com
ATTENDEE;CN=Test User;PARTSTAT=ACCEPTED:MAILTO:foo\@example.net
END:VEVENT
BEGIN:VEVENT
UID:$uuid
DTSTAMP:20210714T034327Z
SEQUENCE:0
ORGANIZER;CN=Cassandane:MAILTO:cassandane\@example.com
ATTENDEE;CN=Test User;PARTSTAT=TENTATIVE:MAILTO:foo\@example.net
RECURRENCE-ID:20210721T193000Z
END:VEVENT
BEGIN:VEVENT
UID:$uuid
DTSTAMP:20210723T034327Z
SEQUENCE:0
ORGANIZER;CN=Cassandane:MAILTO:cassandane\@example.com
ATTENDEE;CN=Test User;PARTSTAT=DECLINED:MAILTO:foo\@example.net
RECURRENCE-ID:20210728T193000Z
END:VEVENT
END:VCALENDAR
EOF

    xlog $self, "Deliver iMIP reply";
    my $msg = Cassandane::Message->new(raw => $imip);
    $msg->set_attribute(uid => 1,
                        flags => [ '\\Recent', '\\Flagged' ]);
    $self->{instance}->deliver($msg);

    xlog $self, "Check that the message made it to INBOX";
    $self->check_messages({ 1 => $msg }, check_guid => 0);

    xlog $self, "Check that the reply made it to calendar";
    $events = $CalDAV->GetEvents($CalendarId);
    $self->assert_equals(1, scalar @$events);
    $self->assert_str_equals($uuid, $events->[0]{uid});
    $self->assert_str_equals('Test User',
                             $events->[0]{participants}{'foo@example.net'}{name});
    $self->assert_str_equals('accepted',
                             $events->[0]{participants}{'foo@example.net'}{scheduleStatus});

    $self->assert_str_equals('2021-07-22T15:30:00',
                             $events->[0]{recurrenceOverrides}{'2021-07-21T15:30:00'}{start});
    $self->assert_str_equals('accepted',
                             $events->[0]{recurrenceOverrides}{'2021-07-21T15:30:00'}{participants}{'cassandane@example.com'}{scheduleStatus});
    $self->assert_str_equals('tentative',
                             $events->[0]{recurrenceOverrides}{'2021-07-21T15:30:00'}{participants}{'foo@example.net'}{scheduleStatus});

    $self->assert_str_equals('accepted',
                             $events->[0]{recurrenceOverrides}{'2021-07-28T15:30:00'}{participants}{'cassandane@example.com'}{scheduleStatus});
    $self->assert_str_equals('declined',
                             $events->[0]{recurrenceOverrides}{'2021-07-28T15:30:00'}{participants}{'foo@example.net'}{scheduleStatus});
}

sub test_imip_reply_override_invalid
    :needs_component_sieve :needs_component_httpd :min_version_3_5
{
    my ($self) = @_;

    my $IMAP = $self->{store}->get_client();
    $self->{store}->_select();
    $self->assert_num_equals(1, $IMAP->uid());
    $self->{store}->set_fetch_attributes(qw(uid flags));

    xlog $self, "Create calendar user";
    my $CalDAV = $self->{caldav};
    my $CalendarId = 'Default';
    my $uuid = "6de280c9-edff-4019-8ebd-cfebc73f8201";
    my $href = "$CalendarId/$uuid.ics";

    xlog $self, "Install a sieve script to process iMIP";
    $self->{instance}->install_sieve_script(<<EOF
require ["body", "variables", "imap4flags", "vnd.cyrus.imip"];
if body :content "text/calendar" :contains "\nMETHOD:" {
    processimip :outcome "outcome";
    if string "\${outcome}" "updated" {
        setflag "\\\\Flagged";
    }
}
EOF
    );

    my $event = <<EOF;
BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.10.4//EN
BEGIN:VEVENT
CREATED:20211014T034327Z
UID:$uuid
TRANSP:OPAQUE
SUMMARY:A Recurring Event
DTSTART;TZID=America/New_York:20211014T153000
DTEND;TZID=America/New_York:20211014T183000
DTSTAMP:20211014T034327Z
SEQUENCE:0
ORGANIZER;CN=Cassandane:MAILTO:cassandane\@example.com
ATTENDEE;CN=Cassandane;PARTSTAT=ACCEPTED:MAILTO:cassandane\@example.com
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:MAILTO:foo\@example.net
END:VEVENT
END:VCALENDAR
EOF

    xlog $self, "Create an event on calendar";
    $CalDAV->Request('PUT', $href, $event, 'Content-Type' => 'text/calendar');

    xlog $self, "Check that the event made it to calendar";
    my $events = $CalDAV->GetEvents($CalendarId);
    $self->assert_equals(1, scalar @$events);
    $self->assert_str_equals($uuid, $events->[0]{uid});
    $self->assert_str_equals('',
                             $events->[0]{participants}{'foo@example.net'}{name});
    $self->assert_str_equals('needs-action',
                             $events->[0]{participants}{'foo@example.net'}{scheduleStatus});
    $self->assert_null($events->[0]{recurrenceRule});


    my $imip = <<EOF;
Date: Thu, 23 Sep 2021 09:06:18 -0400
From: Foo <foo\@example.net>
To: Cassandane <cassandane\@example.com>
Message-ID: <$uuid-0\@example.net>
Content-Type: text/calendar; method=REPLY; component=VEVENT
X-Cassandane-Unique: $uuid-0

BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.10.4//EN
METHOD:REPLY
BEGIN:VEVENT
UID:$uuid
DTSTAMP:20210923T034327Z
SEQUENCE:0
ORGANIZER;CN=Cassandane:MAILTO:cassandane\@example.com
ATTENDEE;CN=Test User;PARTSTAT=DECLINED:MAILTO:foo\@example.net
RECURRENCE-ID;TZID=America/New_York:20211021T153000
END:VEVENT
END:VCALENDAR
EOF

    xlog $self, "Deliver iMIP reply";
    my $msg = Cassandane::Message->new(raw => $imip);
    $msg->set_attribute(uid => 1,
                        flags => [ '\\Recent' ]);
    $self->{instance}->deliver($msg);

    xlog $self, "Check that the message made it to INBOX";
    $self->check_messages({ 1 => $msg }, check_guid => 0);

    xlog $self, "Expunge the message";
    $IMAP->store('1', '+flags', '(\\Deleted)');
    $IMAP->expunge();

    xlog $self, "Check that the reply was ignored";
    $events = $CalDAV->GetEvents($CalendarId);
    $self->assert_equals(1, scalar @$events);
    $self->assert_str_equals($uuid, $events->[0]{uid});
    $self->assert_str_equals('needs-action',
                             $events->[0]{participants}{'foo@example.net'}{scheduleStatus});
    $self->assert_null($events->[0]{recurrenceRule});
    $self->assert_null($events->[0]{recurrenceOverrides});


    $event = <<EOF;
BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.10.4//EN
BEGIN:VEVENT
CREATED:20211014T034327Z
UID:$uuid
TRANSP:OPAQUE
SUMMARY:A Recurring Event
DTSTART;TZID=America/New_York:20211014T153000
DTEND;TZID=America/New_York:20211014T183000
RRULE:FREQ=WEEKLY
DTSTAMP:20211014T034327Z
SEQUENCE:0
ORGANIZER;CN=Cassandane:MAILTO:cassandane\@example.com
ATTENDEE;CN=Cassandane;PARTSTAT=ACCEPTED:MAILTO:cassandane\@example.com
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:MAILTO:foo\@example.net
END:VEVENT
END:VCALENDAR
EOF

    xlog $self, "Create a recurring event on calendar";
    $CalDAV->Request('PUT', $href, $event, 'Content-Type' => 'text/calendar');

    xlog $self, "Check that the event made it to calendar";
    $events = $CalDAV->GetEvents($CalendarId);
    $self->assert_equals(1, scalar @$events);
    $self->assert_str_equals($uuid, $events->[0]{uid});
    $self->assert_str_equals('',
                             $events->[0]{participants}{'foo@example.net'}{name});
    $self->assert_str_equals('needs-action',
                             $events->[0]{participants}{'foo@example.net'}{scheduleStatus});
    $self->assert_not_null($events->[0]{recurrenceRule});
    $self->assert_null($events->[0]{recurrenceOverrides});


    $imip = <<EOF;
Date: Thu, 23 Sep 2021 09:06:18 -0400
From: Foo <foo\@example.net>
To: Cassandane <cassandane\@example.com>
Message-ID: <$uuid-1\@example.net>
Content-Type: text/calendar; method=REPLY; component=VEVENT
X-Cassandane-Unique: $uuid-1

BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.10.4//EN
METHOD:REPLY
BEGIN:VEVENT
UID:$uuid
DTSTAMP:20210923T034327Z
SEQUENCE:0
ORGANIZER;CN=Cassandane:MAILTO:cassandane\@example.com
ATTENDEE;CN=Test User;PARTSTAT=ACCEPTED;RSVP=TRUE:MAILTO:foo\@example.net
END:VEVENT
BEGIN:VEVENT
UID:$uuid
DTSTAMP:20210923T034327Z
SEQUENCE:0
ORGANIZER;CN=Cassandane:MAILTO:cassandane\@example.com
ATTENDEE;CN=Test User;PARTSTAT=DECLINED:MAILTO:foo\@example.net
RECURRENCE-ID;TZID=America/New_York:20211022T153000
END:VEVENT
END:VCALENDAR
EOF

    xlog $self, "Deliver iMIP reply";
    $msg = Cassandane::Message->new(raw => $imip);
    $msg->set_attribute(uid => 2,
                        flags => [ '\\Recent', '\\Flagged' ]);
    $self->{instance}->deliver($msg);

    xlog $self, "Check that the message made it to INBOX";
    $self->check_messages({ 1 => $msg }, check_guid => 0);

    xlog $self, "Check that the reply (master only) made it to calendar";
    $events = $CalDAV->GetEvents($CalendarId);
    $self->assert_equals(1, scalar @$events);
    $self->assert_str_equals($uuid, $events->[0]{uid});
    $self->assert_str_equals('Test User',
                             $events->[0]{participants}{'foo@example.net'}{name});
    $self->assert_str_equals('accepted',
                             $events->[0]{participants}{'foo@example.net'}{scheduleStatus});

    $self->assert_not_null($events->[0]{recurrenceRule});
    $self->assert_null($events->[0]{recurrenceOverrides});
}

sub test_imip_move_event
    :min_version_3_7 :needs_component_jmap :needs_component_sieve
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $caldav = $self->{caldav};
    my $admin = $self->{adminstore}->get_client();

    xlog $self, "Install a sieve script to process iMIP";
    $self->{instance}->install_sieve_script(<<EOF
require ["body", "variables", "imap4flags", "vnd.cyrus.imip"];
if body :content "text/calendar" :contains "\nMETHOD:" {
    processimip :deletecanceled :outcome "outcome";
}
EOF
    );

    xlog "Create calendar X and Y, set X as default calendar";
    my $res = $jmap->CallMethods([
        ['Calendar/set', {
            create => {
                calendarX => {
                    name => 'X',
                },
                calendarY => {
                    name => 'Y',
                },
            },
        }, 'R1'],
    ]);
    my $calendarX = $res->[0][1]{created}{calendarX}{id};
    $self->assert_not_null($calendarX);
    my $calendarY = $res->[0][1]{created}{calendarY}{id};
    $self->assert_not_null($calendarY);

    $res = $jmap->CallMethods([
        ['CalendarPreferences/set', {
            update => {
                singleton => {
                    defaultCalendarId => $calendarX,
                },
            },
        }, 'R1'],
    ]);
    $self->assert(exists $res->[0][1]{updated}{singleton});

    xlog "Get CalendarEvent state";
    $res = $jmap->CallMethods([
        ['CalendarEvent/get', {
            ids => [],
        }, 'R1'],
    ]);
    my $state = $res->[0][1]{state};
    $self->assert_not_null($state);

    my $uuid = "6de280c9-edff-4019-8ebd-cfebc73f8201";
    my $imip = <<EOF;
Date: Thu, 23 Sep 2021 09:06:18 -0400
From: Foo <foo\@example.net>
To: Cassandane <cassandane\@example.com>
Message-ID: <$uuid\@example.net>
Content-Type: text/calendar; method=REQUEST; component=VEVENT
X-Cassandane-Unique: $uuid

BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.10.4//EN
METHOD:REQUEST
BEGIN:VEVENT
CREATED:20210923T034327Z
UID:$uuid
RECURRENCE-ID;TZID=America/New_York:20210923T153000
TRANSP:OPAQUE
SUMMARY:instance1
DTSTART;TZID=America/New_York:20210923T153000
DURATION:PT1H
DTSTAMP:20210923T034327Z
SEQUENCE:0
ORGANIZER;CN=Test User:MAILTO:foo\@example.net
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE;X-JMAP-ID=cassandane:MAILTO:cassandane\@example.com
END:VEVENT
END:VCALENDAR
EOF

    xlog "Deliver iMIP invite for instance1";
    $self->{instance}->deliver(Cassandane::Message->new(raw => $imip));

    xlog "Assert instance1 got into calendar X";
    $res = $jmap->CallMethods([
        ['CalendarEvent/changes', {
            sinceState => $state,
        }, 'R1'],
        ['CalendarEvent/get', {
            '#ids' => {
                resultOf => 'R1',
                name => 'CalendarEvent/changes',
                path => '/created'
            },
            properties => [ 'calendarIds' ],
        }, 'R2'],
    ]);
    $self->assert_deep_equals({
        $calendarX => JSON::true,
    }, $res->[1][1]{list}[0]{calendarIds});
    my $instance1 = $res->[1][1]{list}[0]{id};

    xlog "Move instance1 to calendar Y";
    $res = $jmap->CallMethods([
        ['CalendarEvent/set', {
            update => {
                $instance1 => {
                    calendarIds => {
                        $calendarY => JSON::true,
                    },
                },
            },
        }, 'R1'],
    ]);
    $self->assert(exists $res->[0][1]{updated}{$instance1});
    $state = $res->[0][1]{newState};

    $imip = <<EOF;
Date: Thu, 23 Sep 2021 09:06:18 -0400
From: Foo <foo\@example.net>
To: Cassandane <cassandane\@example.com>
Message-ID: <$uuid\@example.net>
Content-Type: text/calendar; method=REQUEST; component=VEVENT
X-Cassandane-Unique: $uuid

BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.10.4//EN
METHOD:REQUEST
BEGIN:VEVENT
CREATED:20210923T034327Z
UID:$uuid
RECURRENCE-ID;TZID=America/New_York:20210930T153000
TRANSP:OPAQUE
SUMMARY:instance2
DTSTART;TZID=America/New_York:20210930T153000
DURATION:PT1H
DTSTAMP:20210923T034327Z
SEQUENCE:0
ORGANIZER;CN=Test User:MAILTO:foo\@example.net
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE;X-JMAP-ID=cassandane:MAILTO:cassandane\@example.com
END:VEVENT
END:VCALENDAR
EOF

    xlog "Deliver iMIP invite for instance2";
    $self->{instance}->deliver(Cassandane::Message->new(raw => $imip));

    $res = $jmap->CallMethods([
        ['CalendarEvent/changes', {
            sinceState => $state,
        }, 'R1'],
    ]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]{created}});
    my $instance2 = $res->[0][1]{created}[0];
    $self->assert_str_not_equals($instance1, $instance2);

    xlog "Assert both instance1 and instance2 are in calendar Y";
    $res = $jmap->CallMethods([
        ['CalendarEvent/get', {
            ids => [ $instance1, $instance2 ],
            properties => [ 'calendarIds' ],
        }, 'R1'],
    ]);
    $self->assert_num_equals(2, scalar @{$res->[0][1]{list}});
    $self->assert_deep_equals({
        $calendarY => JSON::true,
    }, $res->[0][1]{list}[0]{calendarIds});
    $self->assert_deep_equals({
        $calendarY => JSON::true,
    }, $res->[0][1]{list}[1]{calendarIds});
}

sub test_include_cancel_implicit_keep
    :needs_component_sieve
{
    my ($self) = @_;

    xlog $self, "Install a script which includes another";
    $self->{instance}->install_sieve_script(<<EOF
require ["include"];
include "foo";
EOF
    );

    xlog $self, "Install a script to be included";
    $self->{instance}->install_sieve_script(<<EOF
# This should cancel implicit keep
discard;
EOF
    , name=>'foo');

    xlog $self, "Deliver a message";
    my $msg = $self->{gen}->generate(subject => "Message 1");
    $self->{instance}->deliver($msg);

    xlog $self, "Check that no messages are in INBOX";
    $self->{store}->set_folder('INBOX');
    $self->check_messages({}, check_guid => 0);
}

1;
