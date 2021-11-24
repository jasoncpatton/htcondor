#!/usr/bin/env pytest

import htcondor
import logging
import os
from pathlib import Path
import subprocess
import time

from ornithology import *


logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


@action
def jobset_list_empty(default_condor):
    p = default_condor.run_command(["htcondor", "jobset", "list"])
    return p


@action
def jobset_submit_failure(default_condor, test_dir):
    p = default_condor.run_command(["htcondor", "jobset", "submit", test_dir / "does_not_exist.set"])
    return p


@action
def jobset_submit_success(default_condor, test_dir):
    jobset_file = open(test_dir / "test_submit.set", "w")
    jobset_file.write("""name = TestSubmit
iterator = table A,B {
    wisconsin,iowa
    iowa,illinois
    illinois,wisconsin
}
job {
  executable = /bin/echo
  arguments = $(A).data $(B).data
  output = cluster1.txt
}
job C=A D=B {
  executable = /bin/echo
  arguments = $(C).data $(D).data
  output = cluster2.txt
}
""")
    jobset_file.close()
    p = default_condor.run_command(["htcondor", "jobset", "submit", test_dir / "test_submit.set"])
    return p


@action
def jobset_completed_success(default_condor, test_dir):
    # Currently we have no event logging for jobsets, so we have to poll the list
    timeout = time.time() + 120
    while True:
        if time.time() > timeout:
            assert False
        p = default_condor.run_command(["htcondor", "jobset", "list"])
        if "TestSubmit" not in p.stdout:
            break
        time.sleep(1)
    # Return a list of jobs in this set
    schedd = htcondor.Schedd()
    job_ads = schedd.history(
        constraint=f"JobSetName == \"TestSubmit\"",
        projection=["JobStatus"],
    )
    return job_ads


# Runs a "broken" jobset, which submits correctly but some jobs go on hold due to a missing executable
@action
def broken_jobset_failure(default_condor, test_dir):
    jobset_file = open(test_dir / "broken_jobset.set", "w")
    jobset_file.write("""name = BrokenJobset
iterator = table A,B {
    wisconsin,iowa
    iowa,illinois
    illinois,wisconsin
}
job {
  executable = missing-executable.sh
  arguments = $(A).data $(B).data
  output = cluster1.txt
}
job C=A D=B {
  executable = /bin/echo
  arguments = $(C).data $(D).data
  output = cluster2.txt
}
""")
    jobset_file.close()
    p = default_condor.run_command(["htcondor", "jobset", "submit", test_dir / "broken_jobset.set"])

    # Wait for the jobset to timeout.
    timeout = time.time() + 120
    while time.time() < timeout:
        p = default_condor.run_command(["htcondor", "jobset", "list"])
        # This jobset should not complete successfully! If it does, fail the test.
        if "BrokenJobset" not in p.stdout:
            assert False
        time.sleep(1)
    # Return a list of all jobs in this set
    schedd = htcondor.Schedd()
    job_ads = schedd.query(
        constraint=f"JobSetName == \"BrokenJobset\"",
        projection=["JobStatus"],
    )
    return job_ads


class TestJobsets:

    def test_jobset_list_empty(self, jobset_list_empty):
        assert jobset_list_empty.stderr == "No active job sets found."

    def test_jobset_submit_failure(self, test_dir, jobset_submit_failure):
        assert jobset_submit_failure.stderr == f"Error while trying to run jobset submit:\n[Errno 2] No such file or directory: '{test_dir}/does_not_exist.set'"

    def test_jobset_submit_success(self, jobset_submit_success):
        assert jobset_submit_success.stderr == "Submitted job set TestSubmit containing 2 job clusters."

    def test_jobset_completed_success(self, default_condor, jobset_completed_success):
        # Make sure all the job ads have status 4 (COMPLETED)
        for ad in jobset_completed_success:
            if ad["JobStatus"] != 4:
                assert False
        assert True

    def test_broken_jobset_failure(self, default_condor, broken_jobset_failure):
        num_held_jobs = 0
        for ad in broken_jobset_failure:
            if ad["JobStatus"] == 5:
                num_held_jobs = num_held_jobs + 1
        assert num_held_jobs == 3
