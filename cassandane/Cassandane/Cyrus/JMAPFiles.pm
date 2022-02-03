#!/usr/bin/perl
#
#  Copyright (c) 2011-2021 FastMail Pty Ltd. All rights reserved.
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

package Cassandane::Cyrus::JMAPFiles;
use strict;
use warnings;
use DateTime;
use JSON;
use JSON::XS;
use Net::DAVTalk 0.14;
use Net::CalDAVTalk 0.12;
use Mail::JMAPTalk 0.13;
use Data::Dumper;
use Storable 'dclone';
use File::Basename;
use IO::File;

use lib '.';
use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;

use charnames ':full';

sub new
{
    my ($class, @args) = @_;

    my $config = Cassandane::Config->default()->clone();

    $config->set(caldav_realm => 'Cassandane',
                 conversations => 'yes',
                 httpmodules => 'webdav jmap',
                 httpallowcompress => 'no',
                 jmap_nonstandard_extensions => 'yes');

    return $class->SUPER::new({
        config => $config,
        jmap => 1,
        adminstore => 1,
        services => [ 'imap', 'http' ]
    }, @args);
}

sub set_up
{
    my ($self) = @_;
    $self->SUPER::set_up();
    $self->{jmap}->DefaultUsing([
        'urn:ietf:params:jmap:core',
        'https://cyrusimap.org/ns/jmap/files',
        'https://cyrusimap.org/ns/jmap/blob',
    ]);
    my $service = $self->{instance}->get_service("http");
    $ENV{DEBUGDAV} = 1;
    $ENV{JMAP_ALWAYS_FULL} = 1;
    $self->{dav} = Net::DAVTalk->new(
        user => 'cassandane',
        password => 'pass',
        host => $service->host(),
        port => $service->port(),
        scheme => 'http',
        url => '/',
        expandurl => 0,
    );
}

sub tear_down
{
    my ($self) = @_;
    $self->SUPER::tear_down();
}

sub download
{
    my ($self, $accountid, $blobid) = @_;
    my $jmap = $self->{jmap};

    my $uri = $jmap->downloaduri($accountid, $blobid);
    my %Headers;
    $Headers{'Authorization'} = $jmap->auth_header();
    my %getopts = (headers => \%Headers);
    my $res = $jmap->ua->get($uri, \%getopts);
    xlog $self, "JMAP DOWNLOAD @_ " . Dumper($res);
    return $res;
}

sub test_files_query
    :min_version_3_7 :needs_component_jmap :JMAPExtensions
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $dav = $self->{dav};
    my $root = '/dav/drive/user/cassandane';

    # Create folders via WebDAV
    xlog $self, "create folders (via WebDAV)";
    $dav->Request('MKCOL', "$root/folder1");
    $dav->Request('MKCOL', "$root/folder2");
    $dav->Request('MKCOL', "$root/folder2/subfolder");

    # Create files via WebDAV
    xlog $self, "create files (via WebDAV)";
    $dav->Request('PUT', "$root/file1.txt", 'some text',
                  'Content-Type' => 'text/plain');
    $dav->Request('PUT', "$root/folder1/file2.txt", 'more text',
                  'Content-Type' => 'text/plain');
    $dav->Request('PUT', "$root/folder2/subfolder/file3.txt", 'even more text',
                  'Content-Type' => 'text/plain');

    xlog $self, "get unfiltered list";
    my $res = $jmap->CallMethods([ ['StorageNode/query', { }, "R1"] ]);

    $self->assert_num_equals(6, $res->[0][1]{total});
    $self->assert_num_equals(6, scalar @{$res->[0][1]{ids}});

    xlog $self, "filter all children of root";
    $res = $jmap->CallMethods([ ['StorageNode/query', {
                    filter => {
                        parentIds => [ 'root' ],
                    }
                }, "R1"] ]);

    $self->assert_num_equals(3, $res->[0][1]{total});
    $self->assert_num_equals(3, scalar @{$res->[0][1]{ids}});

    xlog $self, "filter children of root - files only";
    $res = $jmap->CallMethods([ ['StorageNode/query', {
                    filter => {
                        parentIds => [ 'root' ],
                        hasBlobId => JSON::true,
                    }
                }, "R1"] ]);

    $self->assert_num_equals(1, $res->[0][1]{total});
    $self->assert_num_equals(1, scalar @{$res->[0][1]{ids}});

    xlog $self, "filter children of root - folders only";
    $res = $jmap->CallMethods([ ['StorageNode/query', {
                    filter => {
                        parentIds => [ 'root' ],
                        hasBlobId => JSON::false,
                    }
                }, "R1"] ]);

    $self->assert_num_equals(2, $res->[0][1]{total});
    $self->assert_num_equals(2, scalar @{$res->[0][1]{ids}});

    xlog $self, "filter all children NOT of root";
    $res = $jmap->CallMethods([ ['StorageNode/query', {
                    filter => {
                        operator => 'NOT',
                        conditions => [{
                            parentIds => [ 'root' ],
                        }]
                    },
                }, "R1"] ]);

    $self->assert_num_equals(3, $res->[0][1]{total});
    $self->assert_num_equals(3, scalar @{$res->[0][1]{ids}});

    xlog $self, "sort by hasblobId and reverse name";
    $res = $jmap->CallMethods([
        ['StorageNode/query', {
            sort => [
                {
                    property => 'hasBlobId',
                },
                {
                    property => 'name',
                    isAscending => JSON::false,
                }
            ]
         }, "R1"],
        ['StorageNode/get', {
            '#ids' => {
                resultOf => 'R1',
                name => 'StorageNode/query',
                path => '/ids'
            },
            properties => ['name']
         }, "R2"],
    ]);

    $self->assert_num_equals(6, scalar @{$res->[1][1]{list}});
    $self->assert_str_equals('subfolder', $res->[1][1]{list}[0]{name});
    $self->assert_str_equals('folder2', $res->[1][1]{list}[1]{name});
    $self->assert_str_equals('folder1', $res->[1][1]{list}[2]{name});
    $self->assert_str_equals('file3.txt', $res->[1][1]{list}[3]{name});
    $self->assert_str_equals('file2.txt', $res->[1][1]{list}[4]{name});
    $self->assert_str_equals('file1.txt', $res->[1][1]{list}[5]{name});
}

sub test_files_set
    :min_version_3_7 :needs_component_jmap :JMAPExtensions
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    my $file1 = <<EOF;
foo
EOF
    my $type1 = 'text/plain';

    my $file2 = <<EOF;
<html>
<head>
<title>bar</title>
</head>
</html>
EOF
    my $type2 = 'text/html';

    xlog $self, "upload file content";
    my $res = $jmap->Upload($file1, $type1);
    my $blobid1 = $res->{blobId};

    $res = $jmap->Upload($file2, $type2);
    my $blobid2 = $res->{blobId};

    xlog $self, "get unfiltered list";
    $res = $jmap->CallMethods([ ['StorageNode/query', { }, "R1"] ]);

    my $state = $res->[0][1]{queryState};

    xlog $self, "create folders";
    $res = $jmap->CallMethods([
        ['StorageNode/set', {
            create => {
                "1" => { name => "foo", parentId => 'root',
                         blobId => $blobid1, type => $type1 },
                "2" => { name => "bar", parentId => '#C',
                         blobId => $blobid2, type => $type2 },
                "C" => { name => "C", parentId => '#B' },
                "B" => { name => "B", parentId => '#A' },
                "A" => { name => "A", parentId => 'root' }
            }
         }, "R1"]
    ]);
    $self->assert_str_equals('StorageNode/set', $res->[0][0]);
    $self->assert_str_equals('R1', $res->[0][2]);
    $self->assert_str_not_equals($state, $res->[0][1]{newState});
    $self->assert_not_null($res->[0][1]{created});
    my $idA = $res->[0][1]{created}{"A"}{id};
    my $idB = $res->[0][1]{created}{"B"}{id};
    my $idC = $res->[0][1]{created}{"C"}{id};

    xlog $self, "get folder $idC";
    $res = $jmap->CallMethods([['StorageNode/get', { ids => [$idC] }, "R1"]]);
    my $mbox = $res->[0][1]{list}[0];
    $self->assert_str_equals($idC, $mbox->{id});
    $self->assert_str_equals("C", $mbox->{name});
    $self->assert_str_equals($idB, $mbox->{parentId});

#    $self->assert_equals(JSON::true, $mbox->{myRights}->{mayReadItems});
#    $self->assert_equals(JSON::true, $mbox->{myRights}->{mayAddItems});
#    $self->assert_equals(JSON::true, $mbox->{myRights}->{mayRemoveItems});
#    $self->assert_equals(JSON::true, $mbox->{myRights}->{mayCreateChild});
#    $self->assert_equals(JSON::true, $mbox->{myRights}->{mayRename});
#    $self->assert_equals(JSON::true, $mbox->{myRights}->{mayDelete});

    xlog $self, "update folders";
    $res = $jmap->CallMethods([
        ['StorageNode/set', {
            update => {
                $idA => { name => "AAA" },
                $idC => { parentId => $idA }
            }
         }, "R1"]
    ]);

    $self->assert_str_equals('StorageNode/set', $res->[0][0]);
    $self->assert_str_equals('R1', $res->[0][2]);
    $self->assert_str_not_equals($state, $res->[0][1]{newState});
    $self->assert(exists $res->[0][1]{updated}{$idA});

    xlog $self, "get folder $idA and $idC";
    $res = $jmap->CallMethods([['StorageNode/get',
                                { ids => [$idA, $idC] }, "R1"]]);
    $mbox = $res->[0][1]{list}[0];
    $self->assert_str_equals($idA, $mbox->{id});
    $self->assert_str_equals("AAA", $mbox->{name});
    $self->assert_str_equals("root", $mbox->{parentId});

    $mbox = $res->[0][1]{list}[1];
    $self->assert_str_equals($idC, $mbox->{id});
    $self->assert_str_equals($idA, $mbox->{parentId});

    xlog $self, "destroy folders";
    $res = $jmap->CallMethods([
            ['StorageNode/set', { destroy => [ $idA, $idB, $idC ] }, "R1"]
    ]);
    $self->assert_str_equals('StorageNode/set', $res->[0][0]);
    $self->assert_str_equals('R1', $res->[0][2]);
    $self->assert_str_not_equals($state, $res->[0][1]{newState});
    $self->assert_str_equals($idA, $res->[0][1]{destroyed}[2]);

    xlog $self, "get folders";
    $res = $jmap->CallMethods([['StorageNode/get',
                                { ids => [$idA, $idB, $idC] }, "R1"]]);
    $self->assert_str_equals($idA, $res->[0][1]{notFound}[0]);
    $self->assert_str_equals($idB, $res->[0][1]{notFound}[1]);
    $self->assert_str_equals($idC, $res->[0][1]{notFound}[2]);
}

1;
