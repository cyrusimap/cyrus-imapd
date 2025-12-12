package Cassandane::JMAPTester;
use Moo;
extends 'JMAP::Tester';

use experimental 'signatures';
use MIME::Base64 ();

with 'Cassandane::Role::JMAPTester';

no Moo;
1;
