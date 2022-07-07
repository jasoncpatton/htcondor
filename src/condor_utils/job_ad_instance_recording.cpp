/***************************************************************
 *
 * Copyright (C) 1990-2007, Condor Team, Computer Sciences Department,
 * University of Wisconsin-Madison, WI.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you
 * may not use this file except in compliance with the License.  You may
 * obtain a copy of the License at
 * 
 *    http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ***************************************************************/

#include "condor_common.h"
#include "condor_config.h"
#include "condor_debug.h"
#include "directory.h" // for StatInfo
#include "job_ad_instance_recording.h"

//--------------------------------------------------------------
//                       Data members
//--------------------------------------------------------------
//TODO: Make a structor to hold all this data
static bool file_per_epoch = false;
static bool	isInitialized = false;
static char *JobEpochInstDir = NULL;

//--------------------------------------------------------------
//                     Helper Functions
//--------------------------------------------------------------

/*
*	Function to set the job epoch directory from configuration variable
*	JOB_EPOCH_INSTANCE_DIR if it is set and a valid directory.
*/
static void
setEpochDir(){
	if (JobEpochInstDir != NULL) free(JobEpochInstDir);
	// Attempt to grab job epoch instance directory
	if ((JobEpochInstDir = param("JOB_EPOCH_INSTANCE_DIR")) != NULL) {
		// If param was found and not null check if it is a valid directory
		StatInfo si(JobEpochInstDir);
        if (!si.IsDirectory()) {
			// Not a valid directory. Log message and set data member to NULL
            dprintf(D_ALWAYS | D_ERROR,
                    "Invalid JOB_EPOCH_INSTANCE_DIR (%s): must point to a "
                    "valid directory; disabling per-epoch job recording.\n",
                    JobEpochInstDir);
            free(JobEpochInstDir);
            JobEpochInstDir = NULL;
        } else {
            dprintf(D_ALWAYS,
                    "Logging per-epoch job recording files to: %s\n",
                    JobEpochInstDir);
        }
	}
	isInitialized = true;
}

//--------------------------------------------------------------
//                      Write Functions
//--------------------------------------------------------------
/*
*	Write/Append job ad to one file per job with banner seperation
*
*	TODO:Do we want file size limits and file rotation for appending?
*/
static void
appendJobEpochFile(const classad::ClassAd *job_ad){
	// If not initialized then set up job epoch directory
	if (!isInitialized) { setEpochDir(); }
	// Verify that a directory is set if not return
	if (!JobEpochInstDir) { return; }
	
	//Get various information needed for writing epoch file
	int clusterId, procId, numShadow;
	if (!job_ad->LookupInteger("ClusterId", clusterId)) {
		clusterId = -1;
	}
	if (!job_ad->LookupInteger("ProcId", procId)) {
		procId = -1;
	}
	if (!job_ad->LookupInteger("NumShadowStarts", numShadow)) {
		//TODO: Replace Using NumShadowStarts with a better counter for epoch
		numShadow = -1;
	}
	//Format file name to print at end of Job Ad
	std::string file_name, buffer;
	formatstr(file_name,"%s/job.runs.%d.%d.ads",JobEpochInstDir,clusterId,procId);
	sPrintAd(buffer,*job_ad,nullptr,nullptr);
	//Open file and append Job Ad to it
	int fd = safe_open_wrapper_follow(file_name.c_str(), O_RDWR | O_CREAT | O_APPEND | _O_BINARY | O_LARGEFILE | _O_NOINHERIT, 0644);
	FILE* fp = fdopen(fd, "r+");
	if (fp == NULL) {
		dprintf(D_ALWAYS | D_ERROR,
		        "error %d (%s) opening file stream for epoch file for job %d.%d\n",
		        errno, strerror(errno), clusterId, procId);
		close(fd);
		return;
	}
	//Print Job ad and Banner to file
	fprintf(fp,"%s#=====<Job:%d.%d|Epoch:%d>=====#\n",buffer.c_str(),clusterId,procId,numShadow);
	fclose(fp);
}

/*
*	Write a single/current job ad to a new and unique file
*	labeled <filler>.cluster-id.proc-id.epoch-number (num_shadow_starts)
*/
//static void
//writeJobEpochInstance(const classad::ClassAd *job_ad){
	//TODO: -Make per instance writing
	//	-Handle massive amounts of files with sub dirs (see spooling
	//	-Max file limits?
//}

/*
*	Function for shadow to call that will write the current job ad
*	to a job epoch file. This functionality will either write 1 file
*	per job and append each epoch instance of the job ad to said file.
*	Or will write 1 job ad to 1 file per job epoch instance
*/
void
writeJobEpochFile(const classad::ClassAd *job_ad) {

	//If no Job Ad then log error and return
	if (!job_ad) {
		dprintf(D_ALWAYS | D_ERROR,
			"ERROR: No Job Ad. Not able to write to Job Epoch File");
		return;
	}

	if (file_per_epoch) { // Check If user wants 1 file per job epoch/instance
		;//writeJobEpochInstance(job_ad);
	} else { // Otherwise write to single file per job
		appendJobEpochFile(job_ad);
	}
}

//--------------------------------------------------------------
//                   Read/Scrape Functions
//--------------------------------------------------------------


