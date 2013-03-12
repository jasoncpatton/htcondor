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
#include "condor_attributes.h"
#include "condor_debug.h"
#include "env.h"
#include "condor_string.h"	// for strnewp and friends
#include "condor_daemon_core.h"
#include "basename.h"
#include "spooled_job_files.h"
#include "filename_tools.h"
#include "job_lease.h"

#include "gridmanager.h"
#include "boincjob.h"
#include "condor_config.h"
#include "my_username.h"

// GridManager job states
#define GM_INIT					0
#define GM_START				1
#define GM_UNSUBMITTED			2
#define GM_RECOVER_POLL			3
#define GM_JOIN_BATCH			4
#define GM_SUBMIT_SAVE			5
#define GM_SUBMIT				6
#define GM_SUBMITTED			7
#define GM_STAGE_OUT			8
#define GM_DONE_SAVE			9
#define GM_DONE_COMMIT			10
#define GM_CANCEL				11
#define GM_DELETE				12
#define GM_CLEAR_REQUEST		13
#define GM_HOLD					14

static const char *GMStateNames[] = {
	"GM_INIT",
	"GM_START",
	"GM_UNSUBMITTED",
	"GM_RECOVER_POLL",
	"GM_JOIN_BATCH",
	"GM_SUBMIT_SAVE",
	"GM_SUBMIT",
	"GM_SUBMITTED",
	"GM_STAGE_OUT",
	"GM_DONE_SAVE",
	"GM_DONE_COMMIT",
	"GM_CANCEL",
	"GM_DELETE",
	"GM_CLEAR_REQUEST",
	"GM_HOLD",
};

#define BOINC_JOB_STATUS_UNSET			""
#define BOINC_JOB_STATUS_NOT_STARTED	"NOT_STARTED"
#define BOINC_JOB_STATUS_IN_PROGRESS	"IN_PROGRESS"
#define BOINC_JOB_STATUS_DONE			"DONE"
#define BOINC_JOB_STATUS_ERROR			"ERROR"

#define DEFAULT_LEASE_DURATION	6*60*60 //6 hr

#define CLEANUP_DELAY	5
#define MAX_CLEANUP_ATTEMPTS 3

// TODO: Let the maximum submit attempts be set in the job ad or, better yet,
// evalute PeriodicHold expression in job ad.
#define MAX_SUBMIT_ATTEMPTS	1

#define LOG_BOINC_ERROR(func,error) \
    dprintf(D_ALWAYS, \
		"(%d.%d) gmState %s, remoteState %s: %s %s\n", \
        procID.cluster,procID.proc,GMStateNames[gmState],remoteState.c_str(), \
        func,error==GAHPCLIENT_COMMAND_TIMED_OUT?"timed out":"failed")

void BoincJobInit()
{
}

void BoincJobReconfig()
{
	int tmp_int;

	tmp_int = param_integer( "GRIDMANAGER_RESOURCE_PROBE_INTERVAL", 5 * 60 );
	BoincResource::setProbeInterval( tmp_int );

	tmp_int = param_integer( "GRIDMANAGER_GAHP_CALL_TIMEOUT", 5 * 60 );
	BoincJob::setGahpCallTimeout( tmp_int );
	BoincResource::setGahpCallTimeout( tmp_int );

	tmp_int = param_integer("GRIDMANAGER_CONNECT_FAILURE_RETRY_COUNT",3);
	BoincJob::setConnectFailureRetry( tmp_int );

	// Tell all the resource objects to deal with their new config values
	BoincResource *next_resource;

	BoincResource::ResourcesByName.startIterations();
	
	while ( BoincResource::ResourcesByName.iterate( next_resource ) != 0 ) {
		next_resource->Reconfig();
	}
}

bool BoincJobAdMatch( const ClassAd *job_ad ) {
	int universe;
	std::string resource;
	if ( job_ad->LookupInteger( ATTR_JOB_UNIVERSE, universe ) &&
		 universe == CONDOR_UNIVERSE_GRID &&
		 job_ad->LookupString( ATTR_GRID_RESOURCE, resource ) &&
		 strncasecmp( resource.c_str(), "boinc ", 6 ) == 0 ) {

		return true;
	}
	return false;
}

BaseJob *BoincJobCreate( ClassAd *jobad )
{
	return (BaseJob *)new BoincJob( jobad );
}

int BoincJob::gahpCallTimeout = 300;		// default value
int BoincJob::maxConnectFailures = 3;		// default value

BoincJob::BoincJob( ClassAd *classad )
	: BaseJob( classad )
{

	int bool_value;
	char buff[4096];
	std::string buff2;
	std::string grid_resource;
	bool job_already_submitted = false;
	std::string error_string = "";
	char *gahp_path = NULL;

	remoteBatchName = NULL;
	remoteJobName = NULL;
	remoteState = CREAM_JOB_STATE_UNSET;
	gmState = GM_INIT;
	enteredCurrentGmState = time(NULL);
	enteredCurrentRemoteState = time(NULL);
	resourceManagerString = NULL;
	myResource = NULL;
	gahp = NULL;
	connectFailureCount = 0;

	// In GM_HOLD, we assume HoldReason to be set only if we set it, so make
	// sure it's unset when we start.
	// TODO This is bad. The job may already be on hold with a valid hold
	//   reason, and here we'll clear it out (and propogate to the schedd).
	if ( jobAd->LookupString( ATTR_HOLD_REASON, NULL, 0 ) != 0 ) {
		jobAd->AssignExpr( ATTR_HOLD_REASON, "Undefined" );
	}

	gahp_path = param("BOINC_GAHP");
	if ( gahp_path == NULL ) {
		error_string = "BOINC_GAHP not defined";
		goto error_exit;
	}
	snprintf( buff, sizeof(buff), "BOINC" );

	gahp = new GahpClient( buff, gahp_path );
	free( gahp_path );

	gahp->setNotificationTimerId( evaluateStateTid );
	gahp->setMode( GahpClient::normal );
	gahp->setTimeout( gahpCallTimeout );
	
	jobAd->LookupString( ATTR_GRID_RESOURCE, grid_resource );

	if ( grid_resource.length() ) {
		const char *token;

		Tokenize( grid_resource );

		token = GetNextToken( " ", false );
		if ( !token || strcasecmp( token, "boinc" ) ) {
			formatstr( error_string, "%s not of type boinc", ATTR_GRID_RESOURCE );
			goto error_exit;
		}

			/* TODO Make port and '/ce-cream/services/CREAM' optional */
		token = GetNextToken( " ", false );
		if ( token && *token ) {
			// If the resource url is missing a scheme, insert one
			if ( strncmp( token, "http://", 7 ) == 0 ||
				 strncmp( token, "https://", 8 ) == 0 ) {
				resourceManagerString = strdup( token );
			} else {
				std::string urlbuf;
				formatstr( urlbuf, "https://%s", token );
				resourceManagerString = strdup( urlbuf.c_str() );
			}
		} else {
			formatstr( error_string, "%s missing BOINC Service URL",
								  ATTR_GRID_RESOURCE );
			goto error_exit;
		}

	} else {
		formatstr( error_string, "%s is not set in the job ad",
							  ATTR_GRID_RESOURCE );
		goto error_exit;
	}

	buff[0] = '\0';
	
	jobAd->LookupString( ATTR_GRID_JOB_ID, buff, sizeof(buff) );
	if ( buff[0] != '\0' ) {
		const char *token;

		Tokenize( buff );

			// 'boinc'
		token = GetNextToken( " ", false );
			// BOINC server URL
		token = GetNextToken( " ", false );
			// batch name
		token = GetNextToken( " ", false );
		if ( token ) {
			SetRemoteBatchName( token );
		}
		job_already_submitted = true;
	}
	
		// Find/create an appropriate BoincResource for this job
	myResource = BoincResource::FindOrCreateResource( resourceManagerString );
	if ( myResource == NULL ) {
		error_string = "Failed to initialize BoincResource object";
		goto error_exit;
	}

	// RegisterJob() may call our NotifyResourceUp/Down(), so be careful.
	myResource->RegisterJob( this );
	if ( job_already_submitted ) {
		myResource->AlreadySubmitted( this );
	}

	jobAd->LookupString( ATTR_GRID_JOB_STATUS, remoteState );

	gahpErrorString = "";

	return;

 error_exit:
		// We must ensure that the code-path from GM_HOLD doesn't depend
		// on any initialization that's been skipped.
	gmState = GM_HOLD;
	if ( !error_string.empty() ) {
		jobAd->Assign( ATTR_HOLD_REASON, error_string.c_str() );
	}
	return;
}

BoincJob::~BoincJob()
{
	if ( myResource ) {
		myResource->UnregisterJob( this );
	}
	free( resourceManagerString );
	free( remoteBatchName );
	free( remoteJobNmae );
	delete gahp;
}

void BoincJob::Reconfig()
{
	BaseJob::Reconfig();
	gahp->setTimeout( gahpCallTimeout );
}

void BoincJob::doEvaluateState()
{
	bool connect_failure = false;
	int old_gm_state;
	std::string old_remote_state;
	bool reevaluate_state = true;
	time_t now = time(NULL);

	bool attr_exists;
	bool attr_dirty;
	int rc;

	daemonCore->Reset_Timer( evaluateStateTid, TIMER_NEVER );
	dprintf(D_ALWAYS,
			"(%d.%d) doEvaluateState called: gmState %s, remoteState %s\n",
			procID.cluster,procID.proc,GMStateNames[gmState],
			remoteState.c_str());

	if ( gahp ) {
		if ( !resourceStateKnown || resourcePingPending || resourceDown ) {
			gahp->setMode( GahpClient::results_only );
		} else {
			gahp->setMode( GahpClient::normal );
		}
	}

	do {
		reevaluate_state = false;
		old_gm_state = gmState;
		old_remote_state = remoteState;

		switch ( gmState ) {
		  
		case GM_INIT: {
			// This is the state all jobs start in when the BoincJob object
			// is first created. Here, we do things that we didn't want to
			// do in the constructor because they could block (the
			// constructor is called while we're connected to the schedd).

			if ( gahp->Startup() == false ) {
				dprintf( D_ALWAYS, "(%d.%d) Error initializing GAHP\n",
						 procID.cluster, procID.proc );
				
				jobAd->Assign( ATTR_HOLD_REASON, "Failed to initialize GAHP" );
				gmState = GM_HOLD;
				break;
			}

			GahpClient::mode saved_mode = gahp->getMode();
			gahp->setMode( GahpClient::blocking );

			gahp->setMode( saved_mode );

			gmState = GM_START;
		
			} break;
		case GM_START: {
			// This state is the real start of the state machine, after
			// one-time initialization has been taken care of.
			// If we think there's a running jobmanager
			// out there, we try to register for callbacks (in GM_REGISTER).
			// The one way jobs can end up back in this state is if we
			// attempt a restart of a jobmanager only to be told that the
			// old jobmanager process is still alive.

			errorString = "";
			if ( remoteJobName == NULL ) {
				gmState = GM_CLEAR_REQUEST;
			} else if ( wantResubmit || doResubmit ) {
				gmState = GM_CLEAR_REQUEST;
			} else {
					// TODO we should save the cream job state in the job
					//   ad and use it to set submitLogged and
					//   executeLogged here
				submitLogged = true;
				if ( condorState == RUNNING ) {
					executeLogged = true;
				}
				
				if ( condorState == COMPLETED ) {
					gmState = GM_DONE_COMMIT;
				} else if ( remoteState == BOINC_JOB_STATUS_UNSET ) {
					gmState = GM_RECOVER_POLL;
				} else {
					gmState = GM_SUBMITTED;
				}
			}
			} break;
		case GM_RECOVER_POLL: {
			// TODO find out if the job has been submitted...
		} break;
 		case GM_UNSUBMITTED: {
			// There are no outstanding submissions for this job (if
			// there is one, we've given up on it).
			if ( condorState == REMOVED ) {
				gmState = GM_DELETE;
			} else if ( condorState == HELD ) {
				gmState = GM_DELETE;
				break;
			} else {
				gmState = GM_JOIN_BATCH;
			}
		} break;
		case GM_JOIN_BATCH: {
			// Get grouped with other jobs into a Boinc batch
			std::string batch_name;
			std::string error_str;
			if ( !myResource->JoinBatch( batch_name, error_str ) ) {
				dprintf( D_FULLDEBUG, "(%d.%d) Failed to join batch: %s\n",
						 procID.cluster, procID.proc, error_str.c_str() );
				errorString = error_str;
				gmState = GM_HOLD;
			} else {
				SetRemoteBatchName( batch_name.c_str() );
				gmState = GM_SUBMIT_SAVE;
			}
		} break;
		case GM_SUBMIT_SAVE: {
			// Save the batch and job names before submitting
			// TODO Handle REMOVED and HELD?
			jobAd->GetDirtyFlag( ATTR_GRID_JOB_ID, &attr_exists, &attr_dirty );
			if ( attr_exists && attr_dirty ) {
				requestScheddUpdate( this, true );
				break;
			}
			gmState = GM_SUBMIT;
		} break;
		case GM_SUBMIT: {
			// Ready to submit the job

			rc = myResource->Submit( /* this, ... */ );
			if ( /* submit pending */ ) {
				break;
			}
			if ( /* submit failure */ ) {
				errorString = /* error str from resource */;
				gmState = GM_HOLD;
				break;
			}
			/* Success */
			// TODO Set an initial GridJobStatus?
			// TODO record submit attempts, submit time, or RequestSubmit()?
			gmState = GM_SUBMITTED;
			} break;
		case GM_SUBMITTED: {
			// The job has been submitted to BOINC.
			// Wait for completion or failure.
			if ( remoteState == BOINC_JOB_STATUS_DONE ) {
				gmState = GM_STAGE_OUT;
			} else if ( remoteState == BOINC_JOB_STATUS_ERROR ) {
				// TODO Handle error
			} else if ( condorState == REMOVED || condorState == HELD ) {
				gmState = GM_CANCEL;
			} else {
				// TODO anything to do?
			}
			} break;
		case GM_STAGE_OUT: {
			if ( condorState == REMOVED || condorState == HELD ) {
				gmState = GM_CANCEL;
			} else {
				// TODO: Assemble arguments for gahp command
				rc = gahp->boinc_fetch_output( /* args */ );
				if ( rc == GAHPCLIENT_COMMAND_NOT_SUBMITTED ||
					 rc == GAHPCLIENT_COMMAND_PENDING ) {
					break;
				}
				if ( rc != GLOBUS_SUCCESS ) {
					// unhandled error
					LOG_BOINC_ERROR( "boinc_fetch_output()", rc );
					gahpErrorString = gahp->getErrorString();
					gmState = GM_CLEAR_REQUEST;
					//gmState = GM_CANCEL;
					break;
				}
				// TODO Save run info to job ad
				gmState = GM_DONE_SAVE;
			}
		} break;
		case GM_DONE_SAVE: {
			// Report job completion to the schedd.
			JobTerminated();
			if ( condorState == COMPLETED ) {
				jobAd->GetDirtyFlag( ATTR_JOB_STATUS, &attr_exists, &attr_dirty );
				if ( attr_exists && attr_dirty ) {
					requestScheddUpdate( this, true );
					break;
				}
			}
			gmState = GM_DONE_COMMIT;
			} break;
		case GM_DONE_COMMIT: {
			// Allow Boinc batch to be retired once all jobs finish
			// TODO Signal completion to BoincResource
			// TODO send retire_batch if we're last job
			//   (or wait for BoincResource to do so)
			if ( condorState == COMPLETED || condorState == REMOVED ) {
				SetRemoteBatchName( NULL );
				gmState = GM_DELETE;
			} else {
				// Clear the contact string here because it may not get
				// cleared in GM_CLEAR_REQUEST (it might go to GM_HOLD first).
				if ( remoteJobName != NULL ) {
					SetRemoteBatchName( NULL );
					remoteState = BOINC_JOB_STATE_UNSET;
					SetRemoteJobStatus( NULL );
					requestScheddUpdate( this, false );
				}
				gmState = GM_CLEAR_REQUEST;
			}
			} break;
		case GM_CANCEL: {
			// We need to cancel the job submission.
			rc = gahp->boinc_abort_jobs( /* list of single job */ );
			if ( rc == GAHPCLIENT_COMMAND_NOT_SUBMITTED ||
				 rc == GAHPCLIENT_COMMAND_PENDING ) {
				break;
			}
			if ( rc != GLOBUS_SUCCESS ) {
					// unhandled error
				LOG_BOINC_ERROR( "boinc_abort_jobs()", rc );
				gahpErrorString = gahp->getErrorString();
				gmState = GM_CLEAR_REQUEST;
				break;
			}

			SetRemoteBatchName( NULL );
			remoteState = BOINC_JOB_STATE_UNSET;
			SetRemoteJobStatus( NULL );
			requestScheddUpdate( this, false );

			if ( condorState == REMOVED ) {
				gmState = GM_DELETE;
			} else {
				gmState= GM_HOLD;
			}
		} break;
		case GM_DELETE: {
			// We are done with the job. Propagate any remaining updates
			// to the schedd, then delete this object.
			DoneWithJob();
			// This object will be deleted when the update occurs
			} break;
		case GM_CLEAR_REQUEST: {
			// Remove all knowledge of any previous or present job
			// submission, in both the gridmanager and the schedd.

			// If we are doing a rematch, we are simply waiting around
			// for the schedd to be updated and subsequently this cream job
			// object to be destroyed.  So there is nothing to do.
			if ( wantRematch ) {
				break;
			}
			
			// For now, put problem jobs on hold instead of
			// forgetting about current submission and trying again.
			// TODO: Let our action here be dictated by the user preference
			// expressed in the job ad.
			if ( ( remoteJobName != NULL ||
				   remoteState == BOINC_JOB_STATUS_ERROR ) 
				     && condorState != REMOVED 
					 && wantResubmit == 0 
					 && doResubmit == 0 ) {
				if(remoteJobName == NULL) {
					dprintf(D_FULLDEBUG,
							"(%d.%d) Putting on HOLD: lacks remote job ID\n",
							procID.cluster, procID.proc);
				} else if(remoteState == BOINC_JOB_STATUS_ERROR) {
					dprintf(D_FULLDEBUG,
							"(%d.%d) Putting on HOLD: BOINC_JOB_STATUS_ERROR\n",
							procID.cluster, procID.proc);
				} else {
					dprintf(D_FULLDEBUG,
							"(%d.%d) Putting on HOLD: Unknown reason\n",
							procID.cluster, procID.proc);
				}
				gmState = GM_HOLD;
				break;
			}
			// Only allow a rematch *if* we are also going to perform a resubmit
			if ( wantResubmit || doResubmit ) {
				jobAd->EvalBool(ATTR_REMATCH_CHECK,NULL,wantRematch);
			}
			if ( wantResubmit ) {
				wantResubmit = 0;
				dprintf(D_ALWAYS,
						"(%d.%d) Resubmitting to BOINC because %s==TRUE\n",
						procID.cluster, procID.proc, ATTR_GLOBUS_RESUBMIT_CHECK );
			}
			if ( doResubmit ) {
				doResubmit = 0;
				dprintf(D_ALWAYS,
					"(%d.%d) Resubmitting to BOINC (last submit failed)\n",
						procID.cluster, procID.proc );
			}
			remoteState = BOINC_JOB_STATE_UNSET;
			SetRemoteJobStatus( NULL );
			gahpErrorString = "";
			errorString = "";
			UpdateJobLeaseSent( -1 );
			if ( remoteJobName != NULL ) {
				SetRemoteBatchName( NULL );
			}
			JobIdle();
			if ( submitLogged ) {
				JobEvicted();
				if ( !evictLogged ) {
					WriteEvictEventToUserLog( jobAd );
					evictLogged = true;
				}
			}
			
			if ( wantRematch ) {
				dprintf(D_ALWAYS,
						"(%d.%d) Requesting schedd to rematch job because %s==TRUE\n",
						procID.cluster, procID.proc, ATTR_REMATCH_CHECK );

				// Set ad attributes so the schedd finds a new match.
				int dummy;
				if ( jobAd->LookupBool( ATTR_JOB_MATCHED, dummy ) != 0 ) {
					jobAd->Assign( ATTR_JOB_MATCHED, false );
					jobAd->Assign( ATTR_CURRENT_HOSTS, 0 );
				}

				// If we are rematching, we need to forget about this job
				// cuz we wanna pull a fresh new job ad, with a fresh new match,
				// from the all-singing schedd.
				gmState = GM_DELETE;
				break;
			}
			
			// If there are no updates to be done when we first enter this
			// state, requestScheddUpdate will return done immediately
			// and not waste time with a needless connection to the
			// schedd. If updates need to be made, they won't show up in
			// schedd_actions after the first pass through this state
			// because we modified our local variables the first time
			// through. However, since we registered update events the
			// first time, requestScheddUpdate won't return done until
			// they've been committed to the schedd.
			const char *name;
			ExprTree *expr;
			jobAd->ResetExpr();
			if ( jobAd->NextDirtyExpr(name, expr) ) {
				requestScheddUpdate( this, true );
				break;
			}
			submitLogged = false;
			executeLogged = false;
			submitFailedLogged = false;
			terminateLogged = false;
			abortLogged = false;
			evictLogged = false;
			gmState = GM_UNSUBMITTED;
			} break;
		case GM_HOLD: {
			// Put the job on hold in the schedd.
			// TODO: what happens if we learn here that the job is removed?

			// If the condor state is already HELD, then someone already
			// HELD it, so don't update anything else.
			if ( condorState != HELD ) {

				// Set the hold reason as best we can
				// TODO: set the hold reason in a more robust way.
				char holdReason[1024];
				holdReason[0] = '\0';
				holdReason[sizeof(holdReason)-1] = '\0';
				jobAd->LookupString( ATTR_HOLD_REASON, holdReason,
									 sizeof(holdReason) );
				if ( holdReason[0] == '\0' && errorString != "" ) {
					strncpy( holdReason, errorString.c_str(),
							 sizeof(holdReason) - 1 );
				}
				if ( holdReason[0] == '\0' && !gahpErrorString.empty() ) {
					snprintf( holdReason, 1024, "CREAM error: %s",
							  gahpErrorString.c_str() );
				}
				if ( holdReason[0] == '\0' ) {
					strncpy( holdReason, "Unspecified gridmanager error",
							 sizeof(holdReason) - 1 );
				}

				JobHeld( holdReason );
			}
			gmState = GM_DELETE;
			} break;
		default:
			EXCEPT( "(%d.%d) Unknown gmState %d!", procID.cluster,procID.proc,
					gmState );
		}


		if ( gmState != old_gm_state || remoteState != old_remote_state ) {
			reevaluate_state = true;
		}
		if ( remoteState != old_remote_state ) {
/*
			dprintf(D_FULLDEBUG, "(%d.%d) remote state change: %s -> %s\n",
					procID.cluster, procID.proc,
					old_remote_state.c_str(),
					remoteState.c_str());
*/
			enteredCurrentRemoteState = time(NULL);
		}
		if ( gmState != old_gm_state ) {
			dprintf(D_FULLDEBUG, "(%d.%d) gm state change: %s -> %s\n",
					procID.cluster, procID.proc, GMStateNames[old_gm_state],
					GMStateNames[gmState]);
			enteredCurrentGmState = time(NULL);
			// If we were waiting for a pending gahp call, we're not
			// anymore so purge it.
			if ( gahp ) {
				gahp->purgePendingRequests();
			}
			connectFailureCount = 0;
			resourcePingComplete = false;
		}
	} while ( reevaluate_state );
		//end of evaluateState loop

	if ( connect_failure && !resourceDown ) {
		if ( connectFailureCount < maxConnectFailures ) {
			connectFailureCount++;
			int retry_secs = param_integer(
				"GRIDMANAGER_CONNECT_FAILURE_RETRY_INTERVAL",5);
			dprintf(D_FULLDEBUG,
				"(%d.%d) Connection failure (try #%d), retrying in %d secs\n",
				procID.cluster,procID.proc,connectFailureCount,retry_secs);
			daemonCore->Reset_Timer( evaluateStateTid, retry_secs );
		} else {
			dprintf(D_FULLDEBUG,
				"(%d.%d) Connection failure, requesting a ping of the resource\n",
				procID.cluster,procID.proc);
			RequestPing();
		}
	}
}

BaseResource *BoincJob::GetResource()
{
	return (BaseResource *)myResource;
}

void BoincJob::SetRemoteBatchName( const char *batch_name )
{
	std::string full_name;

	free( remoteBatchName );
	free( remoteJobName );
	if ( batch_name ) {
		remoteBatchName = strdup( batch_name );
		formatstr( full_name, "%s#%d.%d", batch_name, procID.cluster, procID.proc );
		remoteJobName = strdup( full_name.c_str() );
	} else {
		remoteBatchName = NULL;
		remoteJobName = NULL;
	}

	if ( batch_name ) {
		formatstr( full_name, "boinc %s %s %s", resourceManagerString,
				   remoteBatchName, remoteJobName );
	} else {
		full_name = "";
	}
	BaseJob::SetRemoteJobId( full_name.c_str() );
}

void BoincJob::NewBoincState( const char *new_state )
{
	std::string new_state_str = new_state ? new_state : "";

		// TODO verify that the string is a valid state name

	SetRemoteJobStatus( new_state );

	if ( new_state_str != remoteState ) {
		dprintf( D_FULLDEBUG, "(%d.%d) boinc state change: %s -> %s\n",
				 procID.cluster, procID.proc, remoteState.c_str(),
				 new_state_str.c_str() );

		if ( new_state_str == BOINC_JOB_STATUS_IN_PROGRESS &&
			 condorState == IDLE ) {
			JobRunning();
		}

		if ( new_state_str == BOINC_JOB_STATUS_NOT_STARTED &&
			 condorState == RUNNING ) {
			JobIdle();
		}

		// TODO When do we consider the submission successful or not:
		//   when Register works, when Start() works, or when the job
		//   state moves to IDLE?
		if ( remoteState == BOINC_JOB_STATUS_UNSET &&
			 !submitLogged && !submitFailedLogged ) {
			if ( new_state_str != BOINC_JOB_STATUS_ERROR ) {
					// The request was successfuly submitted. Write it to
					// the user-log
				if ( !submitLogged ) {
					WriteGridSubmitEventToUserLog( jobAd );
					submitLogged = true;
				}
			}
		}

		remoteState = new_state_str;
		enteredCurrentRemoteState = time(NULL);
		SetRemoteJobStatus( remoteState.c_str() );

		requestScheddUpdate( this, false );

		SetEvaluateState();
	}
}

