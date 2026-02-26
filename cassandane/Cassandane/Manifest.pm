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

# The Manifest provides a record of which tests were run and whether they
# passed.  You'll find manifest.sqlite in Cassandane's "rundir".  Each test
# run has its own rundir, and each test run has its own manifest.
#
# Instance directories are now derived from the test structure directly:
# $rootdir/$rundir/$suite/$test/$role

package Cassandane::Manifest;
use v5.28.0;
use warnings;
use experimental 'signatures';

use DBI;

sub _new ($class, $dbpath)
{
    my $dbh = DBI->connect(
        "dbi:SQLite:dbname=$dbpath",
        undef,
        undef,
        {
            RaiseError => 1,
            AutoCommit => 1,
            sqlite_use_immediate_transaction => 1,
        },
      );

    $dbh->do("PRAGMA journal_mode=WAL");
    $dbh->do(qq{
        CREATE TABLE IF NOT EXISTS tests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            suite TEXT NOT NULL,
            test TEXT NOT NULL,
            started_at TEXT,
            finished_at TEXT,
            result TEXT,
            UNIQUE(suite, test)
        )
    });

    return bless { dbh => $dbh }, $class;
}

sub record_start ($self, $suite_name, $test_name)
{
    $suite_name =~ s/^Cassandane:://;
    $test_name  =~ s/^test_//;

    $self->{dbh}->do(
        q{
            INSERT OR REPLACE INTO tests
            (suite, test, started_at)
            VALUES (?, ?, datetime('now'))
        },
        undef,
        $suite_name, $test_name,
    );

    return;
}

sub record_completion ($self, $suite_name, $test_name, $result)
{
    $suite_name =~ s/^Cassandane:://;
    $test_name  =~ s/^test_//;

    $self->{dbh}->do(
        q{
            UPDATE tests
            SET finished_at = datetime('now'), result = ?
            WHERE suite = ? AND test = ?
        },
        undef,
        $result, $suite_name, $test_name,
    );

    return;
}

1;
