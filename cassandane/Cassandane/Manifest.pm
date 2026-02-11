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

# The Manifest provides a mapping between test names and the instance
# directories used to run them.  Cassandane will run all its tests with
# instance dirs in Cassandane's "rundir".  That's where you'll find
# manifest.sqlite
#
# With the manifest database, you can map failed tests back to their instance
# directories for debugging.

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
        CREATE TABLE IF NOT EXISTS test_instances (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            suite TEXT NOT NULL,
            test TEXT NOT NULL,
            instance_role TEXT NOT NULL,
            instance_name TEXT NOT NULL,
            instance_basedir TEXT NOT NULL,
            started_at TEXT,
            finished_at TEXT,
            result TEXT,
            UNIQUE(suite, test, instance_role)
        )
    });

    return bless { dbh => $dbh }, $class;
}

sub record_start ($self, $suite_name, $test_name, $instance_role, $instance)
{
    $suite_name =~ s/^Cassandane:://;
    $test_name  =~ s/^test_//;

    $self->{dbh}->do(
        q{
            INSERT OR REPLACE INTO test_instances
            (suite, test, instance_role, instance_name, instance_basedir, started_at)
            VALUES (?, ?, ?, ?, ?, datetime('now'))
        },
        undef,
        $suite_name, $test_name, $instance_role, $instance->name, $instance->basedir,
    );

    return;
}

sub record_completion ($self, $suite_name, $test_name, $result)
{
    $suite_name =~ s/^Cassandane:://;
    $test_name  =~ s/^test_//;

    $self->{dbh}->do(
        q{
            UPDATE test_instances
            SET finished_at = datetime('now'), result = ?
            WHERE suite = ? AND test = ?
        },
        undef,
        $result, $suite_name, $test_name,
    );

    return;
}

1;
