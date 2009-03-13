#! /usr/bin/env perl
##**************************************************************
##
## Copyright (C) 1990-2007, Condor Team, Computer Sciences Department,
## University of Wisconsin-Madison, WI.
## 
## Licensed under the Apache License, Version 2.0 (the "License"); you
## may not use this file except in compliance with the License.  You may
## obtain a copy of the License at
## 
##    http://www.apache.org/licenses/LICENSE-2.0
## 
## Unless required by applicable law or agreed to in writing, software
## distributed under the License is distributed on an "AS IS" BASIS,
## WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
## See the License for the specific language governing permissions and
## limitations under the License.
##
##**************************************************************

use CondorTest;

#$cmd = 'job_amazon_basic.cmd';
$cmd = $ARGV[0];

CondorTest::debug( "Submit file for this test is $cmd\n",1);
CondorTest::debug( "looking at env for condor config\n",1);

$condor_config = $ENV{CONDOR_CONFIG};

print "CONDOR_CONFIG = $condor_config\n";

$testdesc =  'Amazon EC2 basic test';
$testname = "job_amazon_basic";

$aborted = sub {
	my %info = @_;
	my $done;
	CondorTest::debug( "Abort event not expected \n",1);
	die "Abort event not expected!\n";
};

$held = sub {
	my %info = @_;
	my $cluster = $info{"cluster"};
	my $holdreason = $info{"holdreason"};

	CondorTest::debug( "Held event not expected: $holdreason \n",1);
	system("condor_status -any -l");
	die "Amazon EC2 job being held not expected\n";
};

$executed = sub
{
	my %args = @_;
	my $cluster = $args{"cluster"};
};

$success = sub
{
	my %info = @_;

	# Verify that output file contains expected "Done" line
};

CondorTest::RegisterExitedSuccess( $testname, $success);
CondorTest::RegisterExecute($testname, $executed);
CondorTest::RegisterHold( $testname, $held );

if( CondorTest::RunTest($testname, $cmd, 0) ) {
	CondorTest::debug( "$testname: SUCCESS\n",1);
	exit(0);
} else {
	CondorTest::debug( "$testname: FAILED\n",1);
	die "$testname: CondorTest::RunTest() failed\n";
}

