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

package Cassandane::Cyrus::SearchFuzzy;
use strict;
use warnings;
use Cwd qw(abs_path);
use DateTime;
use Data::Dumper;
use File::Temp qw(tempdir);
use File::stat;
use MIME::Base64 qw(encode_base64);
use Encode qw(decode encode);

use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;

sub new
{

    my ($class, @args) = @_;
    my $config = Cassandane::Config->default()->clone();
    $config->set(
        conversations => 'on',
        httpallowcompress => 'no',
        httpmodules => 'jmap',
    );
    my $self = $class->SUPER::new({
        config => $config,
        jmap => 1,
        services => [ 'imap', 'http' ]
    }, @args);

    $self->needs('search', 'xapian');
    return $self;
}

sub set_up
{
    my ($self) = @_;
    $self->SUPER::set_up();

    # This will be "words" if Xapian has a CJK word-tokeniser, "ngrams"
    # if it doesn't, or "none" if it cannot tokenise CJK at all.
    $self->{xapian_cjk_tokens} =
        $self->{instance}->{buildinfo}->get('search', 'xapian_cjk_tokens')
        || "none";

    xlog $self, "Xapian CJK tokeniser '$self->{xapian_cjk_tokens}' detected.\n";

    my $config = $self->{instance}->{config};
    $self->{skipdiacrit} = $config->get_bool('search_skipdiacrit', 'on');
    $self->{fuzzyalways} = $config->get_bool('search_fuzzy_always', 'off');
}

sub tear_down
{
    my ($self) = @_;
    $self->SUPER::tear_down();
}

sub create_testmessages
{
    my ($self) = @_;

    xlog $self, "Generate test messages.";
    # Some subjects with the same verb word stem
    $self->make_message("I am running") || die;
    $self->make_message("I run") || die;
    $self->make_message("He runs") || die;

    # Some bodies with the same word stems but different senders. We use
    # the "connect" word stem since it it the first example on Xapian's
    # Stemming documentation (https://xapian.org/docs/stemming.html).
    # Mails from foo@example.com...
    my %params;
    %params = (
        from => Cassandane::Address->new(
            localpart => "foo",
            domain => "example.com"
        ),
    );
    $params{'body'} ="He has connections.",
    $self->make_message("1", %params) || die;
    $params{'body'} = "Gonna get myself connected.";
    $self->make_message("2", %params) || die;
    # ...as well as from bar@example.com.
    %params = (
        from => Cassandane::Address->new(
            localpart => "bar",
            domain => "example.com"
        ),
        body => "Einstein's gravitational theory resulted in beautiful relations connecting gravitational phenomena with the geometry of space; this was an exciting idea."
    );
    $self->make_message("3", %params) || die;

    # Create the search database.
    xlog $self, "Run squatter";
    $self->{instance}->run_command({cyrus => 1}, 'squatter');
}

# Tests that call this function must have :needs_component_jmap
# We could add that to new() but then NO tests would run without jmap,
# and most tests don't need snippets.
sub get_snippets
{
    # Previous versions of this test module used XSNIPPETS to
    # assert snippets but this command got removed from Cyrus.
    # Use JMAP instead.

    my ($self, $folder, $uids, $filter) = @_;

    my $imap = $self->{store}->get_client();
    my $jmap = $self->{jmap};

    $self->assert_not_null($jmap);

    $imap->select($folder);
    my $res = $imap->fetch($uids, ['emailid']);
    my %emailIdToImapUid = map { $res->{$_}{emailid}[0] => $_ } keys %$res;

    $res = $jmap->CallMethods(
        [
            ['SearchSnippet/get', {
                filter => $filter,
                emailIds => [ keys %emailIdToImapUid ],
            }, 'R1'],
        ],
        [ qw( urn:ietf:params:jmap:core urn:ietf:params:jmap:mail ) ],
    );

    my @snippets;
    foreach (@{$res->[0][1]{list}}) {
        if ($_->{subject}) {
            push(@snippets, [
                0,
                $emailIdToImapUid{$_->{emailId}},
                'SUBJECT',
                $_->{subject},
            ]);
        }
        if ($_->{preview}) {
            push(@snippets, [
                0,
                $emailIdToImapUid{$_->{emailId}},
                'BODY',
                $_->{preview},
            ]);
        }
    }

    return {
        snippets => [ sort { $a->[1] <=> $b->[1] } @snippets ],
    };
}

sub run_delve
{
    my ($self, $dir, @args) = @_;
    my $basedir = $self->{instance}->{basedir};
    my @myargs = ('xapian-delve');
    push(@myargs, @args);
    push(@myargs, $dir);
    $self->{instance}->run_command({redirects => {stdout => "$basedir/delve.out"}}, @myargs);
    open(FH, "<$basedir/delve.out") || die "can't find delve.out";
    my $data = <FH>;
    return $data;
}

sub delve_docs
{
    my ($self, $dir) = @_;
    return ([], []) unless -e "$dir/iamglass";
    my $delveout = $self->run_delve($dir, '-V0');
    $delveout =~ s/^Value 0 for each document: //;
    my @docs = split ' ', $delveout;
    my @parts = map { $_ =~ /^\d+:\*P\*/ ? substr($_, 5) : () } @docs;
    my @gdocs = map { $_ =~ /^\d+:\*G\*/ ? substr($_, 5) : () } @docs;
    return \@gdocs, \@parts;
}

sub start_echo_extractor
{
    my ($self, %params) = @_;
    my $instance = $self->{instance};

    xlog "Start extractor server with tracedir $params{tracedir}";
    my $nrequests = 0;
    my $handler = sub {
        my ($conn, $req) = @_;

        $nrequests++;

        if ($params{trace_delay_seconds}) {
            sleep $params{trace_delay_seconds};
        }

        if ($params{tracedir}) {
            # touch trace file in tracedir
            my @paths = split(q{/}, URI->new($req->uri)->path);
            my $guid = pop(@paths);
            my $fname = join(q{},
                $params{tracedir}, "/req", $nrequests, "_", $req->method, "_$guid");
            open(my $fh, ">", $fname) or die "Can't open > $fname: $!";
            close $fh;
        }

        my $res;

        if ($req->method eq 'HEAD') {
            $res = HTTP::Response->new(204);
            $res->content("");
        } elsif ($req->method eq 'GET') {
            $res = HTTP::Response->new(404);
            $res->content("nope");
        } else {
            $res = HTTP::Response->new(200);
            $res->content($req->content);
        }

        if ($params{response_delay_seconds}) {
            my $secs = $params{response_delay_seconds};
            if (ref($secs) eq 'ARRAY') {
                $secs = ($nrequests <= scalar @$secs) ?
                    $secs->[$nrequests-1] : 0;
            }
            sleep $secs;
        }

        $conn->send_response($res);
    };

    my $uri = URI->new($instance->{config}->get('search_attachment_extractor_url'));
    $instance->start_httpd($handler, $uri->port());
}

sub squatter_attachextract_cache_run
{
    my ($self, $cachedir, @squatterArgs) = @_;
    my $instance = $self->{instance};
    my $imap = $self->{store}->get_client();

    xlog "Append emails with identical attachments";
    $self->make_message("msg1",
        mime_type => "multipart/related",
        mime_boundary => "123456789abcdef",
        body => ""
        ."\r\n--123456789abcdef\r\n"
        ."Content-Type: text/plain\r\n"
        ."\r\n"
        ."bodyterm"
        ."\r\n--123456789abcdef\r\n"
        ."Content-Type: application/pdf\r\n"
        ."\r\n"
        ."attachterm"
        ."\r\n--123456789abcdef--\r\n"
    ) || die;
    $self->make_message("msg2",
        mime_type => "multipart/related",
        mime_boundary => "123456789abcdef",
        body => ""
        ."\r\n--123456789abcdef\r\n"
        ."Content-Type: text/plain\r\n"
        ."\r\n"
        ."bodyterm"
        ."\r\n--123456789abcdef\r\n"
        ."Content-Type: application/pdf\r\n"
        ."\r\n"
        ."attachterm"
        ."\r\n--123456789abcdef--\r\n"
    ) || die;

    xlog "Run squatter with cachedir $cachedir";
    $self->{instance}->run_command({cyrus => 1},
        'squatter', "--attachextract-cache-dir=$cachedir", @squatterArgs);
}

use Cassandane::Tiny::Loader 'tiny-tests/SearchFuzzy';

1;
