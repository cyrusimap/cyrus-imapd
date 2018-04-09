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
use strict;
use warnings;
use IO::File;

use lib '.';
use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;

sub new
{
    my $class = shift;
    return $class->SUPER::new({
	    deliver => 1,
	    services => [ 'imap', 'sieve' ],
            adminstore => 1,
    }, @_);
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

    xlog "Checking preconditions for compiling sieve script $name";

    $self->assert(( ! -f "$basedir/$name.script" ));
    $self->assert(( ! -f "$basedir/$name.bc" ));
    $self->assert(( ! -f "$basedir/$name.errors" ));

    open(FH, '>', "$basedir/$name.script")
	or die "Cannot open $basedir/$name.script for writing: $!";
    print FH $script;
    close(FH);

    xlog "Running sievec on script $name";
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

    return ($result, join("\n", @errors));
}

sub compile_timsieved
{
    my ($self, $name, $script) = @_;

    my $basedir = $self->{instance}->{basedir};
    my $bindir = $self->{instance}->{cyrus_destdir} .
		 $self->{instance}->{cyrus_prefix} . '/bin';
    my $srv = $self->{instance}->get_service('sieve');

    xlog "Checking preconditions for compiling sieve script $name";

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

    xlog "Running installsieve on script $name";
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
	xlog "Checking that installsieve didn't write anything to stderr";
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

sub test_vacation_with_following_rules {
    my ($self) = @_;

    my $target = "INBOX.target";

    xlog "Install a sieve script filing all mail into a nonexistant folder";
    $self->{instance}->install_sieve_script(<<'EOF'

require ["fileinto", "reject", "vacation", "imapflags", "notify", "envelope", "relational", "regex", "subaddress", "copy", "mailbox", "mboxmetadata", "servermetadata", "date", "index", "comparator-i;ascii-numeric", "variables"];

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

    xlog "Deliver a message";
    my $msg1 = $self->{gen}->generate(subject => "Message 1");
    $self->{instance}->deliver($msg1);

    # This will crash if we have broken parsing of vacation
}

sub test_deliver
{
    my ($self) = @_;

    my $target = "INBOX.target";

    xlog "Install a sieve script filing all mail into a nonexistant folder";
    $self->{instance}->install_sieve_script(<<EOF
require ["fileinto"];
fileinto "$target";
EOF
    );

    xlog "Deliver a message";
    my $msg1 = $self->{gen}->generate(subject => "Message 1");
    $self->{instance}->deliver($msg1);

    xlog "Actually create the target folder";
    my $imaptalk = $self->{store}->get_client();

    $imaptalk->create($target)
	 or die "Cannot create $target: $@";
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

sub test_deliver_specialuse
    :min_version_3_0
{
    my ($self) = @_;

    my $target = "INBOX.target";

    xlog "create the target folder";
    my $imaptalk = $self->{store}->get_client();

    $imaptalk->create($target, "(use (\\Trash))")
	 or die "Cannot create $target: $@";
    $self->{store}->set_fetch_attributes('uid');

    xlog "Install a sieve script filing all mail into the Trash role";
    $self->{instance}->install_sieve_script(<<EOF
require ["fileinto"];
fileinto "\\\\Trash";
EOF
    );

    xlog "Deliver a message";
    my $msg = $self->{gen}->generate(subject => "Message 1");
    $self->{instance}->deliver($msg);
    $msg->set_attribute(uid => 1);

    xlog "Check that no messages are in INBOX";
    $self->{store}->set_folder('INBOX');
    $self->check_messages({}, check_guid => 0);

    xlog "Check that the message made it into the target folder";
    $self->{store}->set_folder($target);
    $self->check_messages({ 1 => $msg }, check_guid => 0);
}

sub test_deliver_compile
    :min_version_3_0
{
    my ($self) = @_;

    my $target = "INBOX.target";

    xlog "Create the target folder";
    my $imaptalk = $self->{store}->get_client();
    $imaptalk->create($target)
	 or die "Cannot create $target: $@";
    $self->{store}->set_fetch_attributes('uid');

    xlog "Install a sieve script filing all mail into the target folder";
    $self->{instance}->install_sieve_script(<<EOF
require ["fileinto"];
fileinto "$target";
EOF
    );

    xlog "Deliver a message";
    my $msg1 = $self->{gen}->generate(subject => "Message 1");
    $self->{instance}->deliver($msg1);

    xlog "Delete the compiled bytecode";
    my $sieve_dir = $self->{instance}->get_sieve_script_dir('cassandane');
    my $fname = "$sieve_dir/test1.bc";
    unlink $fname or die "Cannot unlink $fname: $!";

    sleep 1; # so the two deliveries get different syslog timestamps

    xlog "Deliver another message - lmtpd should rebuild the missing bytecode";
    my $msg2 = $self->{gen}->generate(subject => "Message 2");
    $self->{instance}->deliver($msg2);

    xlog "Check that both messages made it to the target";
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
    $self->assert_matches(qr/line 1: reject (?:extension )?MUST be enabled/, $errs);

    ($res, $errs) = $self->compile_sieve_script('badreject2',
	"require [\"reject\"];\nreject\n");
    $self->assert_str_equals('failure', $res);
    $self->assert_matches(qr/line 3: syntax error.*expecting STRING/, $errs);

    ($res, $errs) = $self->compile_sieve_script('badreject3',
	"require [\"reject\"];\nreject 42\n");
    $self->assert_str_equals('failure', $res);
    $self->assert_matches(qr/line 2: syntax error.*expecting STRING/, $errs);

    # TODO: test UTF-8 verification of the string parameter

    ($res, $errs) = $self->compile_sieve_script('badfileinto1',
	"fileinto \"foo\"\n");
    $self->assert_str_equals('failure', $res);
    $self->assert_matches(qr/line 1: fileinto (?:extension )?MUST be enabled/, $errs);

    ($res, $errs) = $self->compile_sieve_script('badfileinto2',
	"require [\"fileinto\"];\nfileinto\n");
    $self->assert_str_equals('failure', $res);
    $self->assert_matches(qr/line 3: syntax error.*unexpected.*\$end/, $errs);

    ($res, $errs) = $self->compile_sieve_script('badfileinto3',
	"require [\"fileinto\"];\nfileinto 42\n");
    $self->assert_str_equals('failure', $res);
    $self->assert_matches(qr/line 2: syntax error.*unexpected.*NUMBER/, $errs);

    ($res, $errs) = $self->compile_sieve_script('badfileinto4',
	"require [\"fileinto\"];\nfileinto :copy \"foo\"\n");
    $self->assert_str_equals('failure', $res);
    $self->assert_matches(qr/line 2: copy (?:extension )?MUST be enabled/, $errs);

    ($res, $errs) = $self->compile_sieve_script('badfileinto5',
	"require [\"fileinto\",\"copy\"];\nfileinto \"foo\"\n");
    $self->assert_str_equals('failure', $res);
    $self->assert_matches(qr/line 3: syntax error.*expecting.*;/, $errs);

    ($res, $errs) = $self->compile_sieve_script('badfileinto6',
	"require [\"fileinto\",\"copy\"];\nfileinto :copy \"foo\"\n");
    $self->assert_str_equals('failure', $res);
    $self->assert_matches(qr/line 3: syntax error.*expecting.*;/, $errs);

    ($res, $errs) = $self->compile_sieve_script('goodfileinto7',
	"require [\"fileinto\",\"copy\"];\nfileinto \"foo\";\n");
    $self->assert_str_equals('success', $res);

    ($res, $errs) = $self->compile_sieve_script('goodfileinto8',
	"require [\"fileinto\",\"copy\"];\nfileinto :copy \"foo\";\n");
    $self->assert_str_equals('success', $res);

    # TODO: test UTF-8 verification of the string parameter
}

sub test_badscript_sievec
{
    my ($self) = @_;

    xlog "Testing sieve script compile failures, via sievec";
    $self->{compile_method} = 'sievec';
    $self->badscript_common();
}

sub test_badscript_timsieved
{
    my ($self) = @_;

    xlog "Testing sieve script compile failures, via timsieved";
    $self->{compile_method} = 'timsieved';
    $self->badscript_common();
}

sub test_dup_keep_keep
{
    my ($self) = @_;

    xlog "Testing duplicate suppression between 'keep' & 'keep'";

    $self->{instance}->install_sieve_script(<<EOF
keep;
keep;
EOF
    );

    xlog "Deliver a message";
    my $msg1 = $self->{gen}->generate(subject => "Message 1");
    $self->{instance}->deliver($msg1);

    xlog "Check that only one copy of the message made it to INBOX";
    $self->{store}->set_folder('INBOX');
    $self->check_messages({ 1 => $msg1 }, check_guid => 0);
}

# Note: experiment indicates that duplicate suppression
# with sieve's fileinto does not work if the mailbox has
# the OPT_IMAP_DUPDELIVER option enabled.  This is not
# really broken, although perhaps unexpected, and it not
# tested for here.

sub test_dup_keep_fileinto
{
    my ($self) = @_;

    xlog "Testing duplicate suppression between 'keep' & 'fileinto'";

    $self->{instance}->install_sieve_script(<<EOF
require ["fileinto"];
keep;
fileinto "INBOX";
EOF
    );

    xlog "Deliver a message";
    my $msg1 = $self->{gen}->generate(subject => "Message 1");
    $self->{instance}->deliver($msg1);

    xlog "Check that only one copy of the message made it to INBOX";
    $self->{store}->set_folder('INBOX');
    $self->check_messages({ 1 => $msg1 }, check_guid => 0);
}

sub test_deliver_fileinto_dot
    :UnixHierarchySep
{
    my ($self) = @_;

    xlog "Testing a sieve script which does a 'fileinto' a mailbox";
    xlog "when the user has a dot in their name.  Bug 3664";
    # NOTE: The commit https://github.com/cyrusimap/cyrus-imapd/commit/73af8e19546f235f6286cc9147a3ea74bde19ebb
    # in Cyrus-imapd changes this behaviour where in we don't do a '.' -> '^' anymore.

    xlog "Create the dotted user";
    my $user = 'betty.boop';
    $self->{instance}->create_user($user);

    xlog "Connect as the new user";
    my $svc = $self->{instance}->get_service('imap');
    $self->{store} = $svc->create_store(username => $user, folder => 'INBOX');
    $self->{store}->set_fetch_attributes('uid');
    my $imaptalk = $self->{store}->get_client();

    xlog "Create the target folder";

    my $target = Cassandane::Mboxname->new(config => $self->{instance}->{config},
					   userid => $user,
					   box => 'target')->to_external();
    $imaptalk->create($target)
	 or die "Cannot create $target: $@";

    xlog "Install the sieve script";
    $self->{instance}->install_sieve_script(<<EOF
require ["fileinto"];
fileinto "$target";
EOF
    , username => 'betty.boop');

    xlog "Deliver a message";
    my $msg1 = $self->{gen}->generate(subject => "Message 1");
    $self->{instance}->deliver($msg1, users => [ $user ]);

    xlog "Check that the message made it to target";
    $self->{store}->set_folder($target);
    $self->check_messages({ 1 => $msg1 }, check_guid => 0);
}

# Disabled for now - addflag does not work
# on shared mailboxes in 2.5.
sub XXXtest_shared_delivery_addflag
    :Admin
{
    my ($self) = @_;

    xlog "Testing setting a flag on a sieve script on a";
    xlog "shared folder.  Bug 3617";

    my $imaptalk = $self->{store}->get_client();
    $self->{store}->set_fetch_attributes(qw(uid flags));

    xlog "Create the target folder";
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


    xlog "Install the sieve script";
    my $scriptname = 'cosbySweater';
    $self->{instance}->install_sieve_script(<<EOF
require ["imapflags"];
if header :comparator "i;ascii-casemap" :is "Subject" "quinoa"  {
    addflag "\\\\Flagged";
    keep;
    stop;
}
EOF
    , username => undef,
    name => $scriptname);

    xlog "Tell the folder to run the sieve script";
    $admintalk->setmetadata($target, "/shared/vendor/cmu/cyrus-imapd/sieve", $scriptname)
	or die "Cannot set metadata: $@";

    xlog "Deliver a message";
    my $msg1 = $self->{gen}->generate(subject => "quinoa");
    $self->{instance}->deliver($msg1, users => [], folder => $target);

    xlog "Check that the message made it to target";
    $self->{store}->set_folder($target);
    $msg1->set_attribute(flags => [ '\\Recent', '\\Flagged' ]);
    $self->check_messages({ 1 => $msg1 }, check_guid => 0);
}

sub test_rfc5490_create
    :min_version_3_0
{
    my ($self) = @_;

    xlog "Testing the \"fileinto :create\" syntax";

    my $talk = $self->{store}->get_client();

    my $hitfolder = "INBOX.newfolder";
    my $missfolder = "INBOX";

    xlog "Install the sieve script";
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
	xlog "Deliver a message with subject \"$case->{subject}\"";
	my $msg = $self->{gen}->generate(subject => $case->{subject});
	$msg->set_attribute(uid => $uid{$case->{filedto}});
	$uid{$case->{filedto}}++;
	$self->{instance}->deliver($msg);
        $exp{$case->{filedto}}->{$case->{subject}} = $msg;
    }

    xlog "Check that the messages made it";
    foreach my $folder (keys %exp)
    {
	$self->{store}->set_folder($folder);
	$self->check_messages($exp{$folder}, check_guid => 0);
    }
}

sub test_rfc5490_mailboxexists
    :min_version_3_0
{
    my ($self) = @_;

    xlog "Testing the \"mailboxexists\" test";

    my $talk = $self->{store}->get_client();

    my $hitfolder = "INBOX.newfolder";
    my $testfolder = "INBOX.testfolder";
    my $missfolder = "INBOX";

    xlog "Install the sieve script";
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
    xlog "Deliver a message";
    {
        my $msg = $self->{gen}->generate(subject => "msg1");
        $msg->set_attribute(uid => $uid{$missfolder});
        $uid{$missfolder}++;
        $self->{instance}->deliver($msg);
        $exp{$missfolder}->{"msg1"} = $msg;
    }

    xlog "Create the test folder";
    $talk->create($testfolder);

    xlog "Deliver a message now that the folder exists";
    {
        my $msg = $self->{gen}->generate(subject => "msg2");
        $msg->set_attribute(uid => $uid{$hitfolder});
        $uid{$hitfolder}++;
        $self->{instance}->deliver($msg);
        $exp{$hitfolder}->{"msg2"} = $msg;
    }

    xlog "Check that the messages made it";
    foreach my $folder (keys %exp)
    {
	$self->{store}->set_folder($folder);
	$self->check_messages($exp{$folder}, check_guid => 0);
    }
}

sub test_rfc5490_mailboxexists_variables
    :min_version_3_0
{
    my ($self) = @_;

    xlog "Testing the \"mailboxexists\" test with variables";

    my $talk = $self->{store}->get_client();

    my $hitfolder = "INBOX.newfolder";
    my $testfolder = "INBOX.testfolder";
    my $missfolder = "INBOX";

    xlog "Install the sieve script";
    my $scriptname = 'flatPack';
    $self->{instance}->install_sieve_script(<<EOF
require ["fileinto", "mailbox", "variables"];
set "testfolder" "$testfolder";
if mailboxexists "\${testfolder}"  {
    fileinto "$hitfolder";
}
EOF
    );

    $talk->create($hitfolder);

    my %uid = ($hitfolder => 1, $missfolder => 1);
    my %exp;
    xlog "Deliver a message";
    {
        my $msg = $self->{gen}->generate(subject => "msg1");
        $msg->set_attribute(uid => $uid{$missfolder});
        $uid{$missfolder}++;
        $self->{instance}->deliver($msg);
        $exp{$missfolder}->{"msg1"} = $msg;
    }

    xlog "Create the test folder";
    $talk->create($testfolder);

    xlog "Deliver a message now that the folder exists";
    {
        my $msg = $self->{gen}->generate(subject => "msg2");
        $msg->set_attribute(uid => $uid{$hitfolder});
        $uid{$hitfolder}++;
        $self->{instance}->deliver($msg);
        $exp{$hitfolder}->{"msg2"} = $msg;
    }

    xlog "Check that the messages made it";
    foreach my $folder (keys %exp)
    {
	$self->{store}->set_folder($folder);
	$self->check_messages($exp{$folder}, check_guid => 0);
    }
}

sub test_rfc5490_metadata
    :min_version_3_0
{
    my ($self) = @_;

    xlog "Testing the \"metadata\" test";

    my $talk = $self->{store}->get_client();

    my $hitfolder = "INBOX.newfolder";
    my $missfolder = "INBOX";

    xlog "Install the sieve script";
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
    xlog "Deliver a message";
    {
        my $msg = $self->{gen}->generate(subject => "msg1");
        $msg->set_attribute(uid => $uid{$missfolder});
        $uid{$missfolder}++;
        $self->{instance}->deliver($msg);
        $exp{$missfolder}->{"msg1"} = $msg;
    }

    xlog "Create the annotation";
    $talk->setmetadata("INBOX", "/private/comment", "awesome");

    xlog "Deliver a message now that the folder exists";
    {
        my $msg = $self->{gen}->generate(subject => "msg2");
        $msg->set_attribute(uid => $uid{$hitfolder});
        $uid{$hitfolder}++;
        $self->{instance}->deliver($msg);
        $exp{$hitfolder}->{"msg2"} = $msg;
    }

    xlog "Check that the messages made it";
    foreach my $folder (keys %exp)
    {
	$self->{store}->set_folder($folder);
	$self->check_messages($exp{$folder}, check_guid => 0);
    }
}

sub test_rfc5490_metadata_matches
    :min_version_3_0
{
    my ($self) = @_;

    xlog "Testing the \"metadata\" test";

    my $talk = $self->{store}->get_client();

    my $hitfolder = "INBOX.newfolder";
    my $missfolder = "INBOX";

    xlog "Install the sieve script";
    $self->{instance}->install_sieve_script(<<EOF
require ["fileinto", "mboxmetadata"];
if metadata :contains "INBOX" "/private/comment" "awesome" {
    fileinto "$hitfolder";
}
EOF
    );

    xlog "Set the initial annotation";
    $talk->setmetadata("INBOX", "/private/comment", "awesomesauce");

    $talk->create($hitfolder);

    my %uid = ($hitfolder => 1, $missfolder => 1);
    my %exp;
    xlog "Deliver a message";
    {
        my $msg = $self->{gen}->generate(subject => "msg1");
        $msg->set_attribute(uid => $uid{$hitfolder});
        $uid{$hitfolder}++;
        $self->{instance}->deliver($msg);
        $exp{$hitfolder}->{"msg1"} = $msg;
    }

    xlog "Create the annotation";
    $talk->setmetadata("INBOX", "/private/comment", "awesome");

    xlog "Deliver a message now that the folder exists";
    {
        my $msg = $self->{gen}->generate(subject => "msg2");
        $msg->set_attribute(uid => $uid{$hitfolder});
        $uid{$hitfolder}++;
        $self->{instance}->deliver($msg);
        $exp{$hitfolder}->{"msg2"} = $msg;
    }

    xlog "Check that the messages made it";
    foreach my $folder (keys %exp)
    {
	$self->{store}->set_folder($folder);
	$self->check_messages($exp{$folder}, check_guid => 0);
    }
}

sub test_rfc5490_metadataexists
    :min_version_3_0 :AnnotationAllowUndefined
{
    my ($self) = @_;

    xlog "Testing the \"metadataexists\" test";

    my $talk = $self->{store}->get_client();

    my $hitfolder = "INBOX.newfolder";
    my $missfolder = "INBOX";

    xlog "Install the sieve script";
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
    xlog "Deliver a message";
    {
        my $msg = $self->{gen}->generate(subject => "msg1");
        $msg->set_attribute(uid => $uid{$missfolder});
        $uid{$missfolder}++;
        $self->{instance}->deliver($msg);
        $exp{$missfolder}->{"msg1"} = $msg;
    }

    xlog "Create the annotation";
    $talk->setmetadata("INBOX", "/private/magic", "hello");

    xlog "Deliver a message now that the folder exists";
    {
        my $msg = $self->{gen}->generate(subject => "msg2");
        $msg->set_attribute(uid => $uid{$hitfolder});
        $uid{$hitfolder}++;
        $self->{instance}->deliver($msg);
        $exp{$hitfolder}->{"msg2"} = $msg;
    }

    xlog "Check that the messages made it";
    foreach my $folder (keys %exp)
    {
	$self->{store}->set_folder($folder);
	$self->check_messages($exp{$folder}, check_guid => 0);
    }
}

sub test_rfc5490_servermetadata
    :min_version_3_0 :AnnotationAllowUndefined
{
    my ($self) = @_;

    xlog "Testing the \"metadata\" test";

    my $talk = $self->{store}->get_client();
    my $admintalk = $self->{adminstore}->get_client();

    my $hitfolder = "INBOX.newfolder";
    my $missfolder = "INBOX";

    xlog "Install the sieve script";
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
    xlog "Deliver a message";
    {
        my $msg = $self->{gen}->generate(subject => "msg1");
        $msg->set_attribute(uid => $uid{$missfolder});
        $uid{$missfolder}++;
        $self->{instance}->deliver($msg);
        $exp{$missfolder}->{"msg1"} = $msg;
    }

    xlog "Create the annotation";
    $admintalk->setmetadata("", "/shared/magic", "awesome");

    xlog "Deliver a message now that the folder exists";
    {
        my $msg = $self->{gen}->generate(subject => "msg2");
        $msg->set_attribute(uid => $uid{$hitfolder});
        $uid{$hitfolder}++;
        $self->{instance}->deliver($msg);
        $exp{$hitfolder}->{"msg2"} = $msg;
    }

    xlog "Check that the messages made it";
    foreach my $folder (keys %exp)
    {
	$self->{store}->set_folder($folder);
	$self->check_messages($exp{$folder}, check_guid => 0);
    }
}

sub test_rfc5490_servermetadataexists
    :min_version_3_0 :AnnotationAllowUndefined
{
    my ($self) = @_;

    xlog "Testing the \"servermetadataexists\" test";

    my $talk = $self->{store}->get_client();
    my $admintalk = $self->{adminstore}->get_client();

    my $hitfolder = "INBOX.newfolder";
    my $missfolder = "INBOX";

    xlog "Install the sieve script";
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
    xlog "Deliver a message";
    {
        my $msg = $self->{gen}->generate(subject => "msg1");
        $msg->set_attribute(uid => $uid{$missfolder});
        $uid{$missfolder}++;
        $self->{instance}->deliver($msg);
        $exp{$missfolder}->{"msg1"} = $msg;
    }

    xlog "Create the annotation";
    $admintalk->setmetadata("", "/shared/moo", "hello");

    xlog "Deliver a message now that the folder exists";
    {
        my $msg = $self->{gen}->generate(subject => "msg2");
        $msg->set_attribute(uid => $uid{$hitfolder});
        $uid{$hitfolder}++;
        $self->{instance}->deliver($msg);
        $exp{$hitfolder}->{"msg2"} = $msg;
    }

    xlog "Check that the messages made it";
    foreach my $folder (keys %exp)
    {
	$self->{store}->set_folder($folder);
	$self->check_messages($exp{$folder}, check_guid => 0);
    }
}

sub test_variables_basic
    :min_version_3_0
{
    my ($self) = @_;

    xlog "Actually create the target folder";
    my $imaptalk = $self->{store}->get_client();

    $imaptalk->create("INBOX.target");
    $imaptalk->create("INBOX.target.Folder1");
    $imaptalk->create("INBOX.target.Folder2");

    xlog "Install a sieve script filing all mail into a nonexistant folder";
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

    xlog "Deliver a message";

    # should go in Folder1
    my $msg1 = $self->{gen}->generate(subject => "Message 1");
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
{
    my ($self) = @_;

    xlog "Actually create the target folder";
    my $imaptalk = $self->{store}->get_client();

    xlog "Install a sieve script filing all mail into a nonexistant folder";
    $self->{instance}->install_sieve_script(<<EOF
require ["fileinto", "imapflags"];
if header :matches "Subject" "Message 2" {
    setflag "\\\\Flagged";
}
EOF
    );

    xlog "Deliver a message";

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
{
    my ($self) = @_;

    xlog "Actually create the target folder";
    my $imaptalk = $self->{store}->get_client();

    $imaptalk->create("INBOX.target");
    $imaptalk->create("INBOX.target.Folder1");
    $imaptalk->create("INBOX.target.Folder2");

    xlog "Install a sieve script filing all mail into a nonexistant folder";
    $self->{instance}->install_sieve_script(<<EOF
require ["fileinto", "variables", "regex"];
set "folder" "target";
if header :regex "Subject" "Message (.*)" {
    fileinto "INBOX.\${folder}.Folder\${1}";
    stop;
}
fileinto "INBOX.\${folder}";
EOF
    );

    xlog "Deliver a message";

    # should go in Folder1
    my $msg1 = $self->{gen}->generate(subject => "Message 1");
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

sub test_nested_tests_and_discard
{
    my ($self) = @_;

    xlog "Install a sieve script discarding all mail";
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

    xlog "Attempt to deliver a message";
    my $msg1 = $self->{gen}->generate(subject => "Message 1");
    $self->{instance}->deliver($msg1);

    # should fail to deliver and NOT appear in INBOX
    my $imaptalk = $self->{store}->get_client();
    $imaptalk->select("INBOX");
    $self->assert_num_equals(0, $imaptalk->get_response_code('exists'));
}

sub test_editheader
{
    my ($self) = @_;

    xlog "Install a sieve script with editheader actions";
    $self->{instance}->install_sieve_script(<<EOF
require ["editheader", "index"];
addheader "X-Cassandane-Test" "prepend1";
addheader "X-Cassandane-Test2" "prepend2";
addheader "X-Cassandane-Test2" "prepend3";
addheader :last "X-Cassandane-Test" "append1";
addheader :last "X-Cassandane-Test" "append2";
addheader :last "X-Cassandane-Test" "append3";
addheader :last "X-Cassandane-Test" "append4";
deleteheader :index 3 :contains "X-Cassandane-Test" "append";
deleteheader :index 1 :last "X-Cassandane-Test";
deleteheader "X-Cassandane-Test2";
EOF
    );

    xlog "Deliver a message";
    my $msg1 = $self->{gen}->generate(subject => "Message 1");
    $self->{instance}->deliver($msg1);

    my $imaptalk = $self->{store}->get_client();
    $imaptalk->select("INBOX");
    my $res = $imaptalk->fetch(1, 'rfc822');

    $msg1 = $res->{1}->{rfc822};

    $self->assert_matches(qr/^X-Cassandane-Test: prepend1/, $msg1);
    $self->assert_matches(qr/X-Cassandane-Test: append3\r\n\r\n/, $msg1);
}

sub test_duplicate
{
    my ($self) = @_;

    xlog "Install a sieve script with a duplicate check";
    $self->{instance}->install_sieve_script(<<EOF
require ["duplicate", "variables"];
if allof (header :matches "subject" "ALERT: *",
          duplicate :seconds 3 :last :uniqueid "${1}") {
    discard;
}
EOF
    );

    xlog "Deliver a message";
    # This message sets the duplicate tracking entry
    my $msg1 = $self->{gen}->generate(subject => "ALERT: server down");
    $self->{instance}->deliver($msg1);

    xlog "Deliver second message";
    # This message should be discarded
    my $msg2 = $self->{gen}->generate(subject => "ALERT: server down");
    $self->{instance}->deliver($msg2);

    xlog "Deliver third message";
    # This message should be discarded
    my $msg3 = $self->{gen}->generate(subject => "ALERT: server down");
    $self->{instance}->deliver($msg3);

    sleep 3;
    xlog "Deliver fourth message";
    # This message should be delivered (after the expire time)
    my $msg4 = $self->{gen}->generate(subject => "ALERT: server down");
    $self->{instance}->deliver($msg4);

    xlog "Deliver fifth message";
    # This message should be discarded
    my $msg5 = $self->{gen}->generate(subject => "ALERT: server down");
    $self->{instance}->deliver($msg5);

    my $imaptalk = $self->{store}->get_client();
    $imaptalk->select("INBOX");

    $self->assert_num_equals(2, $imaptalk->get_response_code('exists'));
}

sub test_ereject
{
    my ($self) = @_;

    xlog "Install a sieve script rejecting all mail";
    $self->{instance}->install_sieve_script(<<EOF
require ["ereject"];
ereject "Go away!";
EOF
    );

    xlog "Attempt to deliver a message";
    my $msg1 = $self->{gen}->generate(subject => "Message 1");
    my $res = $self->{instance}->deliver($msg1);

    # should fail to deliver
    $self->assert_num_not_equals(0, $res);

    # should NOT appear in INBOX
    my $imaptalk = $self->{store}->get_client();
    $imaptalk->select("INBOX");
    $self->assert_num_equals(0, $imaptalk->get_response_code('exists'));
}

1;
