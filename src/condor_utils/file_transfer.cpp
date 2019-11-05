/***************************************************************
 *
 * Copyright (C) 1990-2011, Condor Team, Computer Sciences Department,
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
#include "condor_debug.h"
#include "string_list.h"
#include "condor_classad.h"
#include "condor_io.h"
#include "file_transfer.h"
#include "condor_attributes.h"
#include "condor_commands.h"
#include "basename.h"
#include "directory.h"
#include "condor_config.h"
#include "spooled_job_files.h"
#include "util_lib_proto.h"
#include "daemon.h"
#include "daemon_types.h"
#include "nullfile.h"
#include "condor_ver_info.h"
#include "globus_utils.h"
#include "filename_tools.h"
#include "condor_holdcodes.h"
#include "mk_cache_links.h"
#include "subsystem_info.h"
#include "condor_url.h"
#include "my_popen.h"
#include "file_transfer_stats.h"
#include "utc_time.h"
#include "data_reuse.h"
#include "AWSv4-utils.h"
#include "condor_random_num.h"

#include <fstream>
#include <algorithm>
#include <numeric>
#include <sstream>
#include <string>
#include <unordered_set>
#include <unordered_map>

namespace {

class ReuseInfo
{
public:
	ReuseInfo(const std::string &filename,
		const std::string &checksum,
		const std::string &checksum_type,
		const std::string &tag,
		uint64_t size)
	: m_size(size),
	m_filename(filename),
	m_checksum(checksum),
	m_checksum_type(checksum_type),
	m_tag(tag)
	{}

	const std::string &filename() const {return m_filename;}
	const std::string &checksum() const {return m_checksum;}
	const std::string &checksum_type() const {return m_checksum_type;}
	uint64_t size() const {return m_size;}

private:
	const uint64_t m_size{0};
	const std::string m_filename;
	const std::string m_checksum;
	const std::string m_checksum_type;
	const std::string m_tag;
};

}

const char * const StdoutRemapName = "_condor_stdout";
const char * const StderrRemapName = "_condor_stderr";

// Transfer commands are sent from the upload side to the download side.
// 0 - finished
// 1 - use socket default (on or off) for next file
// 2 - force encryption on for next file.
// 3 - force encryption off for next file.
// 4 - do an x509 credential delegation (using the socket default)
// 5 - send a URL and have the download side fetch it
// 6 - send a request to make a directory
// 999 - send a classad telling what to do.
//
// 999 subcommands (999 is followed by a filename and then a ClassAd):
// 7 - ClassAd contains information about a URL upload performed by
//     the upload side.
// 8 - ClassAd contains information about a list of files which will be
//     sent later that may be eligible for reuse.  This is command requires
//     a response indicating if the download side already has one of the
//     files available.
// 9 - ClassAd contains a list of URLs that need to be signed for the uploader
//     to proceed.
enum class TransferCommand {
	Unknown = -1,
	Finished = 0,
	XferFile = 1,
	EnableEncryption = 2,
	DisableEncryption = 3,
	XferX509 = 4,
	DownloadUrl = 5,
	Mkdir = 6,
	Other = 999
};

enum class TransferSubCommand {
	Unknown = -1,
	UploadUrl = 7,
	ReuseInfo = 8,
	SignUrls = 9
};

#define COMMIT_FILENAME ".ccommit.con"

// Filenames are case insensitive on Win32, but case sensitive on Unix
#ifdef WIN32
#	define file_strcmp _stricmp
#	define file_contains contains_anycase
#	define file_contains_withwildcard contains_anycase_withwildcard
#else
#	define file_strcmp strcmp
#	define file_contains contains
#	define file_contains_withwildcard contains_withwildcard
#endif

TranskeyHashTable* FileTransfer::TranskeyTable = NULL;
TransThreadHashTable *FileTransfer::TransThreadTable = NULL;
int FileTransfer::CommandsRegistered = FALSE;
int FileTransfer::SequenceNum = 0;
int FileTransfer::ReaperId = -1;
bool FileTransfer::ServerShouldBlock = true;

const int FINAL_UPDATE_XFER_PIPE_CMD = 1;
const int IN_PROGRESS_UPDATE_XFER_PIPE_CMD = 0;

/**
 * The `FileTransferItem` represents a single work item for the DoUpload
 * side of the file transfer obejct to perform.
 *
 * All state information about the file transfer should be kept here.
 *
 * Importantly, the FileTransferItem implements the `<` operator, allowing
 * it to be sorted in a list.  This allows, for example, all the CEDAR-based
 * transfers to be performed prior to the non-CEDAR transfers.
 */
class FileTransferItem {
public:
	const std::string &srcName() const { return m_src_name; }
	const std::string &destDir() const { return m_dest_dir; }
	const std::string &destUrl() const { return m_dest_url; }
	const std::string &srcScheme() const { return m_src_scheme; }
	filesize_t fileSize() const { return m_file_size; }
	void setDestDir(const std::string &dest) { m_dest_dir = dest; }
	void setFileSize(filesize_t new_size) { m_file_size = new_size; }
	void setDomainSocket(bool value) { is_domainsocket = value; }
	void setSymlink(bool value) { is_symlink = value; }
	void setDirectory(bool value) { is_directory = value; }
	bool isDomainSocket() const {return is_domainsocket;}
	bool isSymlink() const {return is_symlink;}
	bool isDirectory() const {return is_directory;}
	bool isSrcUrl() const {return !m_src_scheme.empty();}
	bool isDestUrl() const {return !m_dest_scheme.empty();}
	condor_mode_t fileMode() const {return m_file_mode;}
	void setFileMode(condor_mode_t new_mode) {m_file_mode = new_mode;}

	void setSrcName(const std::string &src) {
		m_src_name = src;
		const char *scheme_end = IsUrl(src.c_str());
		if (scheme_end) {
			m_src_scheme = std::string(src.c_str(), scheme_end - src.c_str());
		}
	}

	void setDestUrl(const std::string &dest_url) {
		m_dest_url = dest_url;
		const char *scheme_end = IsUrl(dest_url.c_str());
		if (scheme_end) {
			m_dest_scheme = std::string(dest_url.c_str(), scheme_end - dest_url.c_str());
		}
	}

	bool operator<(const FileTransferItem &other) const {
		// Ordering of transfers:
		// - Destination URLs first (allows these plugins to alter CEDAR transfers on
		//   stageout)
		// - CEDAR-based transfers (move any credentials prior to source URLs; assume
		//   credentials are already present for stageout).
		// - Source URLs last.
		//

		auto is_dest_url = !m_dest_scheme.empty();
		auto other_is_dest_url = !other.m_dest_scheme.empty();
		if (is_dest_url && !other_is_dest_url) {
			return true;
		}
		if (!is_dest_url && other_is_dest_url) {
			return false;
		}
		if (is_dest_url) {
			if (m_dest_scheme == other.m_dest_scheme) {
				return m_dest_url < other.m_dest_url;
			} else {
				return m_dest_scheme < other.m_dest_scheme;
			}
		}

		auto is_src_url = !m_src_scheme.empty();
		auto other_is_src_url = !other.m_src_scheme.empty();
		if (is_src_url && !other_is_src_url) {
			return false;
		}
		if (!is_src_url && other_is_src_url) {
			return true;
		}
		if (is_src_url) { // Both are URLs
			if (m_src_scheme == other.m_src_scheme) {
				return m_src_name < other.m_src_name;
			} else {
				return m_src_scheme < other.m_src_scheme;
			}
		}
		return m_src_name < other.m_src_name;
	}

private:
	std::string m_src_scheme;
	std::string m_dest_scheme;
	std::string m_src_name;
	std::string m_dest_dir;
	std::string m_dest_url;
	bool is_domainsocket{false};
	bool is_directory{false};
	bool is_symlink{false};
	condor_mode_t m_file_mode{NULL_FILE_PERMISSIONS};
	filesize_t m_file_size{0};
};

const int GO_AHEAD_FAILED = -1; // failed to contact transfer queue manager
const int GO_AHEAD_UNDEFINED = 0;
const int GO_AHEAD_ONCE = 1;    // send one file and ask again
				// Currently, there is no usage of GO_AHEAD_ONCE; if we have a
				// token, we assume it lasts forever.

const int GO_AHEAD_ALWAYS = 2;  // send all files without asking again


struct upload_info {
	FileTransfer *myobj;
};

struct download_info {
	FileTransfer *myobj;
};

FileTransfer::FileTransfer()
{
}

FileTransfer::~FileTransfer()
{
	if (daemonCore && ActiveTransferTid >= 0) {
		dprintf(D_ALWAYS, "FileTransfer object destructor called during "
				"active transfer.  Cancelling transfer.\n");
		abortActiveTransfer();
	}
	if (daemonCore && (TransferPipe[0] >= 0)) {
		if( registered_xfer_pipe ) {
			registered_xfer_pipe = false;
			daemonCore->Cancel_Pipe(TransferPipe[0]);
		}
		daemonCore->Close_Pipe(TransferPipe[0]);
	}
	if (daemonCore && (TransferPipe[1] >= 0)) daemonCore->Close_Pipe(TransferPipe[1]);
	if (Iwd) free(Iwd);
	if (ExecFile) free(ExecFile);
	if (UserLogFile) free(UserLogFile);
	if (X509UserProxy) free(X509UserProxy);
	if (SpoolSpace) free(SpoolSpace);
	if (TmpSpoolSpace) free(TmpSpoolSpace);
	if (ExceptionFiles) delete ExceptionFiles;
	if (InputFiles) delete InputFiles;
	if (OutputFiles) delete OutputFiles;
	if (EncryptInputFiles) delete EncryptInputFiles;
	if (EncryptOutputFiles) delete EncryptOutputFiles;
	if (DontEncryptInputFiles) delete DontEncryptInputFiles;
	if (DontEncryptOutputFiles) delete DontEncryptOutputFiles;
	if (OutputDestination) free(OutputDestination);
	if (IntermediateFiles) delete IntermediateFiles;
	if (SpooledIntermediateFiles) free(SpooledIntermediateFiles);
	// Note: do _not_ delete FileToSend!  It points to OutputFile or Intermediate.
	if (last_download_catalog) {
		// iterate through and delete entries
		CatalogEntry *entry_pointer;
		last_download_catalog->startIterations();
		while(last_download_catalog->iterate(entry_pointer)) {
			delete entry_pointer;
		}
		delete last_download_catalog;
	}
	if (TransSock) free(TransSock);
	stopServer();
	// Do not delete the TransThreadTable. There may be other FileTransfer
	// objects out there planning to use it.
	//if( TransThreadTable && TransThreadTable->getNumElements() == 0 ) {
	//	delete TransThreadTable;
	//	TransThreadTable = NULL;
	//}
#ifdef WIN32
	if (perm_obj) delete perm_obj;
#endif
	free(m_sec_session_id);
	delete plugin_table;
}

int
FileTransfer::SimpleInit(ClassAd *Ad, bool want_check_perms, bool is_server,
						 ReliSock *sock_to_use, priv_state priv,
						 bool use_file_catalog, bool is_spool) 
{
	char buf[ATTRLIST_MAX_EXPRESSION];
	char *dynamic_buf = NULL;
	const bool allow_inline_plugins = true; // enable job TransferPlugins attribute

	jobAd = *Ad;	// save job ad

	if( did_init ) {
			// no need to except, just quietly return success
		return 1;
	}

	user_supplied_key = is_server ? FALSE : TRUE;

	dprintf(D_FULLDEBUG,"entering FileTransfer::SimpleInit\n");

	/* in the case of SimpleInit being called inside of Init, this will
		simply assign the same value to itself. */
	m_use_file_catalog = use_file_catalog;

	desired_priv_state = priv;
    if ( priv == PRIV_UNKNOWN ) {
        want_priv_change = false;
    } else {
        want_priv_change = true;
    }

	simple_sock = sock_to_use;

	// user must give us an initial working directory.
	if (Ad->LookupString(ATTR_JOB_IWD, buf, sizeof(buf)) != 1) {
		dprintf(D_FULLDEBUG, 
			"FileTransfer::SimpleInit: Job Ad did not have an iwd!\n");
		return 0;
	}
	Iwd = strdup(buf);

	// if the user want us to check file permissions, pull out the Owner
	// from the classad and instantiate a perm object.
	if ( want_check_perms ) {
		if (Ad->LookupString(ATTR_OWNER, buf, sizeof(buf)) != 1) {
			// no owner specified in ad
			dprintf(D_FULLDEBUG, 
				"FileTransfer::SimpleInit: Job Ad did not have an owner!\n");
			return 0;		
		}
#ifdef WIN32
		// lookup the domain
		char ntdomain[80];
		char *p_ntdomain = ntdomain;
		if (Ad->LookupString(ATTR_NT_DOMAIN, ntdomain, sizeof(ntdomain)) != 1) {
			// no nt domain specified in the ad; assume local account
			p_ntdomain = NULL;
		}
		perm_obj = new perm();
		if ( !perm_obj->init(buf,p_ntdomain) ) {
			// could not find the owner on this system; perm object
			// already did a dprintf so we don't have to.
			delete perm_obj;
			perm_obj = NULL;
			return 0;
		} 
#endif
	}

	// Set InputFiles to be ATTR_TRANSFER_INPUT_FILES plus 
	// ATTR_JOB_INPUT, ATTR_JOB_CMD, and ATTR_ULOG_FILE if simple_init.
	dynamic_buf = NULL;
	if (Ad->LookupString(ATTR_TRANSFER_INPUT_FILES, &dynamic_buf) == 1) {
		InputFiles = new StringList(dynamic_buf,",");
		free(dynamic_buf);
		dynamic_buf = NULL;
	} else {
		InputFiles = new StringList(NULL,",");
	}
	StringList PubInpFiles;
	if (Ad->LookupString(ATTR_PUBLIC_INPUT_FILES, &dynamic_buf) == 1) {
	      // Add PublicInputFiles to InputFiles list.
	      // If these files will be transferred via web server cache,
	      // they will be removed from InputFiles.
	      PubInpFiles.initializeFromString(dynamic_buf);
	      free(dynamic_buf);
	      dynamic_buf = NULL;
	      const char *path;
	      PubInpFiles.rewind();
	      while ((path = PubInpFiles.next()) != NULL) {
		  if (!InputFiles->file_contains(path))
		      InputFiles->append(path);			
	      }
	}
	if (Ad->LookupString(ATTR_JOB_INPUT, buf, sizeof(buf)) == 1) {
		// only add to list if not NULL_FILE (i.e. /dev/null)
		if ( ! nullFile(buf) ) {			
			if ( !InputFiles->file_contains(buf) )
				InputFiles->append(buf);			
		}
	}
	
	// If we are spooling, we want to ignore URLs
	// We want the file transfer plugin to be invoked at the starter, not the schedd.
	// See https://condor-wiki.cs.wisc.edu/index.cgi/tktview?tn=2162
	if (IsClient() && simple_init && is_spool) {
		InputFiles->rewind();
		const char *x;
		while ((x = InputFiles->next())) {
			if (IsUrl(x)) {
				InputFiles->deleteCurrent();
			}
		}
		char *list = InputFiles->print_to_string();
		dprintf(D_FULLDEBUG, "Input files: %s\n", list ? list : "" );
		free(list);
	} 
#ifdef HAVE_HTTP_PUBLIC_FILES    
	else if (IsServer() && !is_spool && param_boolean("ENABLE_HTTP_PUBLIC_FILES", false)) {
		// For files to be cached, change file names to URLs
		ProcessCachedInpFiles(Ad, InputFiles, PubInpFiles);
	}
#endif
	
	if ( Ad->LookupString(ATTR_ULOG_FILE, buf, sizeof(buf)) == 1 ) {
		UserLogFile = strdup(condor_basename(buf));
		// For 7.5.6 and earlier, we want to transfer the user log as
		// an input file if we're in condor_submit. Otherwise, we don't.
		// At this point, we don't know what version our peer is,
		// so we have to delay this decision until UploadFiles().
	}
	if ( Ad->LookupString(ATTR_X509_USER_PROXY, buf, sizeof(buf)) == 1 ) {
		X509UserProxy = strdup(buf);
			// add to input files
		if ( !nullFile(buf) ) {			
			if ( !InputFiles->file_contains(buf) )
				InputFiles->append(buf);			
		}
	}
	if ( Ad->LookupString(ATTR_OUTPUT_DESTINATION, buf, sizeof(buf)) == 1 ) {
		OutputDestination = strdup(buf);
		dprintf(D_FULLDEBUG, "FILETRANSFER: using OutputDestination %s\n", buf);
	}

	// there are a few places below where we need the value of the SPOOL
	// knob if we're the server. we param for it once here, and free it
	// at the end of this function
	//
	char* Spool = NULL;
	if ( IsServer() ) {
		Spool = param("SPOOL");
	}

	// if we're the server, initialize the SpoolSpace and TmpSpoolSpace
	// member variables
	//
	int Cluster = 0;
	int Proc = 0;
	Ad->LookupInteger(ATTR_CLUSTER_ID, Cluster);
	Ad->LookupInteger(ATTR_PROC_ID, Proc);
	m_jobid.formatstr("%d.%d",Cluster,Proc);
	if ( IsServer() && Spool ) {

		std::string buf;
		SpooledJobFiles::getJobSpoolPath(Ad, buf);
		SpoolSpace = strdup(buf.c_str());
		TmpSpoolSpace = (char*)malloc( strlen(SpoolSpace) + 10 );
		sprintf(TmpSpoolSpace,"%s.tmp",SpoolSpace);
	}

	if ( (IsServer() || (IsClient() && simple_init)) && 
		 (Ad->LookupString(ATTR_JOB_CMD, buf, sizeof(buf)) == 1) ) 
	{
		// TODO: If desired_priv_state isn't PRIV_UNKNOWN, shouldn't
		//   we switch priv state for these file checks?

		// stash the executable name for comparison later, so
		// we know that this file should be called condor_exec on the
		// client machine.  if an executable for this cluster exists
		// in the spool dir, use it instead.

		// Only check the spool directory if we're the server.
		// Note: This will break Condor-C jobs if the executable is ever
		//   spooled the old-fashioned way (which doesn't happen currently).
		if ( IsServer() && Spool ) {
			ExecFile = GetSpooledExecutablePath(Cluster, Spool);
			if ( access(ExecFile,F_OK | X_OK) < 0 ) {
				free(ExecFile); ExecFile = NULL;
			}
		}

		if ( !ExecFile ) {
			// apparently the executable is not in the spool dir.
			// so we must make certain the user has permission to read
			// this file; if so, we can record it as the Executable to send.
#ifdef WIN32
			// buf doesn't refer to a real file when this code is executed in the SCHEDD when spooling
			// so instead of failing here, we just don't bother with the access test in that case.
			if ( !simple_init && perm_obj && (perm_obj->read_access(buf) != 1) ) {
				// we do _not_ have permission to read this file!!
				dprintf(D_ALWAYS,
					"FileTrans: permission denied reading %s\n",buf);
				return 0;
			}
#endif
			ExecFile = strdup(buf);
		}

		// If we don't already have this on our list of things to transfer, 
		// and we haven't set TRANSFER_EXECTUABLE to false, send it along.
		// If we didn't set TRANSFER_EXECUTABLE, default to true 

		bool xferExec;
		if(!Ad->LookupBool(ATTR_TRANSFER_EXECUTABLE,xferExec)) {
			xferExec=true;
		}

		if ( xferExec && !InputFiles->file_contains(ExecFile) &&
		  !PubInpFiles.file_contains(ExecFile)) {
			// Don't add exec file if it already is in cached list
			InputFiles->append(ExecFile);	
		}	
	} else if ( IsClient() && !simple_init ) {
		ExecFile = strdup( CONDOR_EXEC );
	}

	// Set OutputFiles to be ATTR_SPOOLED_OUTPUT_FILES if specified, otherwise
	// set OutputFiles to be ATTR_TRANSFER_OUTPUT_FILES if specified.
	// If not specified, set it to send whatever files have changed.
	// Also add in ATTR_JOB_OUPUT plus ATTR_JOB_ERROR, if we're not
	// streaming them, and if we're using a fixed list of output
	// files.
	dynamic_buf = NULL;
	if (Ad->LookupString(ATTR_SPOOLED_OUTPUT_FILES, &dynamic_buf) == 1 ||
		Ad->LookupString(ATTR_TRANSFER_OUTPUT_FILES, &dynamic_buf) == 1)
	{
		OutputFiles = new StringList(dynamic_buf,",");
		free(dynamic_buf);
		dynamic_buf = NULL;
	} else {
		// send back new/changed files after the run
		upload_changed_files = true;
	}
	// and now check stdout/err
	bool streaming = false;
	JobStdoutFile = "";
	if(Ad->LookupString(ATTR_JOB_OUTPUT, buf, sizeof(buf)) == 1 ) {
		JobStdoutFile = buf;
		Ad->LookupBool( ATTR_STREAM_OUTPUT, streaming );
		if( ! streaming && ! upload_changed_files && ! nullFile(buf) ) {
				// not streaming it, add it to our list if we're not
				// just going to transfer anything that was changed.
				// only add to list if not NULL_FILE (i.e. /dev/null)
			if( OutputFiles ) {
				if( !OutputFiles->file_contains(buf) ) {
					OutputFiles->append( buf );
				}
			} else {
				OutputFiles = new StringList(buf,",");
			}
		}
	}
		// re-initialize this flag so we don't use stale info from
		// ATTR_STREAM_OUTPUT if ATTR_STREAM_ERROR isn't defined
	streaming = false;
	JobStderrFile = "";
	if( Ad->LookupString(ATTR_JOB_ERROR, buf, sizeof(buf)) == 1 ) {
		JobStderrFile = buf;
		Ad->LookupBool( ATTR_STREAM_ERROR, streaming );
		if( ! streaming && ! upload_changed_files && ! nullFile(buf) ) {
				// not streaming it, add it to our list if we're not
				// just going to transfer anything that was changed.
				// only add to list if not NULL_FILE (i.e. /dev/null)
			if( OutputFiles ) {
				if( !OutputFiles->file_contains(buf) ) {
					OutputFiles->append( buf );
				}
			} else {
				OutputFiles = new StringList(buf,",");
			}
		}
	}

		// add the spooled user log to the list of files to xfer
		// (i.e. when sending output to condor_transfer_data)
	std::string ulog;
	if( jobAd.LookupString(ATTR_ULOG_FILE,ulog) ) {
		if( outputFileIsSpooled(ulog.c_str()) ) {
			if( OutputFiles ) {
				if( !OutputFiles->file_contains(ulog.c_str()) ) {
					OutputFiles->append(ulog.c_str());
				}
			} else {
				OutputFiles = new StringList(buf,",");
			}
		}
	}

	// Set EncryptInputFiles to be ATTR_ENCRYPT_INPUT_FILES if specified.
	if (Ad->LookupString(ATTR_ENCRYPT_INPUT_FILES, buf, sizeof(buf)) == 1) {
		EncryptInputFiles = new StringList(buf,",");
	} else {
		EncryptInputFiles = new StringList(NULL,",");
	}

	// Set EncryptOutputFiles to be ATTR_ENCRYPT_OUTPUT_FILES if specified.
	if (Ad->LookupString(ATTR_ENCRYPT_OUTPUT_FILES, buf, sizeof(buf)) == 1) {
		EncryptOutputFiles = new StringList(buf,",");
	} else {
		EncryptOutputFiles = new StringList(NULL,",");
	}

	// Set DontEncryptInputFiles to be ATTR_DONT_ENCRYPT_INPUT_FILES if specified.
	if (Ad->LookupString(ATTR_DONT_ENCRYPT_INPUT_FILES, buf, sizeof(buf)) == 1) {
		DontEncryptInputFiles = new StringList(buf,",");
	} else {
		DontEncryptInputFiles = new StringList(NULL,",");
	}

	// Set DontEncryptOutputFiles to be ATTR_DONT_ENCRYPT_OUTPUT_FILES if specified.
	if (Ad->LookupString(ATTR_DONT_ENCRYPT_OUTPUT_FILES, buf, sizeof(buf)) == 1) {
		DontEncryptOutputFiles = new StringList(buf,",");
	} else {
		DontEncryptOutputFiles = new StringList(NULL,",");
	}

	// We need to know whether to apply output file remaps or not.
	// The case where we want to apply them is when we are the shadow
	// or anybody else who is writing the files to their final
	// location.  We do not want to apply them if we are the shadow
	// and this job was submitted with 'condor_submit -s' or something
	// similar, because we are writing to the spool directory, and the
	// filenames in the spool directory should be the same as they are
	// in the execute dir, or we have trouble when we try to write
	// files that get mapped to subdirectories within the spool
	// directory.

	// Unfortunately, we can't tell for sure whether we are a client
	// who should be doing remaps, so clients who do want it (like
	// condor_transfer_data), should explicitly call
	// InitDownloadFilenameRemaps().

	bool spooling_output = false;
	{
		if (Iwd && Spool) {
			if(!strncmp(Iwd,Spool,strlen(Spool))) {
				// We are in the spool directory.
				// Wish there was a better way to find this out!
				spooling_output = true;
			}
		}
	}

	if(!spooling_output) {
		if(IsServer()) {
			if(!InitDownloadFilenameRemaps(Ad)) return 0;
		} 
#ifdef HAVE_HTTP_PUBLIC_FILES
		else if( !simple_init ) {
			// Only add input remaps for starter receiving
			AddInputFilenameRemaps(Ad);
		}
#endif
	}

	CondorError e;
	I_support_filetransfer_plugins = false;
	plugin_table = NULL;
	InitializePlugins(e);
	if (allow_inline_plugins) {
		InitializeJobPlugins(*Ad, e, *InputFiles);
	}

	int spool_completion_time = 0;
	Ad->LookupInteger(ATTR_STAGE_IN_FINISH,spool_completion_time);
	last_download_time = spool_completion_time;
	if(IsServer()) {
		BuildFileCatalog(last_download_time);
	} else {
		BuildFileCatalog();
	}

	if ( Spool ) {
		free(Spool);
	}

	did_init = true;
	return 1;
}

int
FileTransfer::InitDownloadFilenameRemaps(ClassAd *Ad) {
	std::string remap_fname;
	std::string ulog_fname;

	dprintf(D_FULLDEBUG,"Entering FileTransfer::InitDownloadFilenameRemaps\n");

	download_filename_remaps = "";
	if(!Ad) return 1;

	// when downloading files from the job, apply output name remaps
	if (Ad->LookupString(ATTR_TRANSFER_OUTPUT_REMAPS,remap_fname)) {
		AddDownloadFilenameRemaps(remap_fname.c_str());
	}

	// If a client is receiving spooled output files which include a
	// user job log file with a directory component, add a remap.
	// Otherwise, the user log will end up in the iwd, which is wrong.
	if (IsClient() && Ad->LookupString(ATTR_ULOG_FILE, ulog_fname) &&
		ulog_fname.find(DIR_DELIM_CHAR) != std::string::npos) {

		std::string full_name;
		if (fullpath(ulog_fname.c_str())) {
			full_name = ulog_fname;
		} else {
			Ad->LookupString(ATTR_JOB_IWD, full_name);
			full_name += DIR_DELIM_CHAR;
			full_name += ulog_fname;
		}
		AddDownloadFilenameRemap(condor_basename(full_name.c_str()), full_name.c_str());
	}

	if(!download_filename_remaps.IsEmpty()) {
		dprintf(D_FULLDEBUG, "FileTransfer: output file remaps: %s\n",download_filename_remaps.Value());
	}
	return 1;
}

bool
FileTransfer::IsDataflowJob( ClassAd *job_ad ) {

	bool is_dataflow = false;
	std::set<int> input_timestamps;
	std::set<int> output_timestamps;
	std::string iwd;
	std::string input_files;
	std::string output_files;
	std::string token;
	struct stat file_stat;

	// Lookup the working directory
	job_ad->LookupString( ATTR_JOB_IWD, iwd );

	// Parse the list of input files
	job_ad->LookupString( ATTR_TRANSFER_INPUT_FILES, input_files );
	std::stringstream is( input_files );
	while ( getline( is, token, ',' ) ) {
		// Skip any file path that looks like a URL or transfer plugin related
		if ( token.find( "://" ) == std::string::npos ) {
			// Stat each file. Add the last-modified timestamp to set of timestamps.
			std::string input_filename = iwd + DIR_DELIM_CHAR + token;
			if ( stat( input_filename.c_str(), &file_stat ) == 0 ) {
				input_timestamps.insert( file_stat.st_mtime );
			}
		}
	}

	// Parse the list of output files
	job_ad->LookupString( ATTR_TRANSFER_OUTPUT_FILES, output_files );
	std::stringstream os( output_files );
	while ( getline( os, token, ',' ) ) {
		// Stat each file. Add the last-modified timestamp to set of timestamps.
		std::string output_filename = iwd + DIR_DELIM_CHAR + token;
		if ( stat( output_filename.c_str(), &file_stat ) == 0 ) {
			output_timestamps.insert( file_stat.st_mtime );
		}
		else {
			// Failure to stat this output file suggests the file doesn't exist.
			// A job must have all declared outputs to be a dataflow job. Abort.
			return false;
		}
	}

	// If the oldest output file is more recent than the newest input files,
	// then this is a dataflow job.
	if ( !input_timestamps.empty() && !output_timestamps.empty() ) {
		auto newest_input = input_timestamps.rbegin();
		auto oldest_output = output_timestamps.begin();
		is_dataflow = *oldest_output > *newest_input;
	}

	return is_dataflow;
}

#ifdef HAVE_HTTP_PUBLIC_FILES
int
FileTransfer::AddInputFilenameRemaps(ClassAd *Ad) {
	dprintf(D_FULLDEBUG,"Entering FileTransfer::AddInputFilenameRemaps\n");

	if(!Ad) {
		dprintf(D_FULLDEBUG, "FileTransfer::AddInputFilenameRemaps -- job ad null\n");
	  	return 1;
	}
	
	download_filename_remaps = "";
	char *remap_fname = NULL;

	// when downloading files from the job, apply input name remaps
	if (Ad->LookupString(ATTR_TRANSFER_INPUT_REMAPS,&remap_fname)) {
		AddDownloadFilenameRemaps(remap_fname);
		free(remap_fname);
		remap_fname = NULL;
	}
	if(!download_filename_remaps.IsEmpty()) {
		dprintf(D_FULLDEBUG, "FileTransfer: input file remaps: %s\n",download_filename_remaps.Value());
	}
	return 1;
}
#endif


int
FileTransfer::Init(
	ClassAd *Ad,
	bool want_check_perms /* false */,
	priv_state priv /* PRIV_UNKNOWN */,
	bool use_file_catalog /* = true */)
{
	char buf[ATTRLIST_MAX_EXPRESSION];
	char *dynamic_buf = NULL;

	ASSERT( daemonCore );	// full Init require DaemonCore methods

	if( did_init ) {
			// no need to except, just quietly return success
		return 1;
	}

	dprintf(D_FULLDEBUG,"entering FileTransfer::Init\n");

	m_use_file_catalog = use_file_catalog;

	simple_init = false;

	if (!TranskeyTable) {
		// initialize our hashtable
		if (!(TranskeyTable = new TranskeyHashTable(hashFunction)))
		{
			// failed to allocate our hashtable ?!?!
			return 0;
		}
		
	}

	if (ActiveTransferTid >= 0) {
		EXCEPT("FileTransfer::Init called during active transfer!");
	}

	if (!TransThreadTable) {
		// initialize our thread hashtable
		if (!(TransThreadTable =
			  new TransThreadHashTable(hashFuncInt))) {
			// failed to allocate our hashtable ?!?!
			return 0;
		}
	}


	// Note: we must register commands here instead of our constructor 
	// to ensure that daemonCore object has been initialized before we 
	// call Register_Command.
	if ( !CommandsRegistered  ) {
		CommandsRegistered = TRUE;
		daemonCore->Register_Command(FILETRANS_UPLOAD,"FILETRANS_UPLOAD",
				(CommandHandler)&FileTransfer::HandleCommands,
				"FileTransfer::HandleCommands()",NULL,WRITE);
		daemonCore->Register_Command(FILETRANS_DOWNLOAD,"FILETRANS_DOWNLOAD",
				(CommandHandler)&FileTransfer::HandleCommands,
				"FileTransfer::HandleCommands()",NULL,WRITE);
		ReaperId = daemonCore->Register_Reaper("FileTransfer::Reaper",
							(ReaperHandler)&FileTransfer::Reaper,
							"FileTransfer::Reaper()",NULL);
		if (ReaperId == 1) {
			EXCEPT("FileTransfer::Reaper() can not be the default reaper!");
		}
	}

	if (Ad->LookupString(ATTR_TRANSFER_KEY, buf, sizeof(buf)) != 1) {
		char tempbuf[80];
		// classad did not already have a TRANSFER_KEY, so
		// generate a new one.  It must be unique and not guessable.
		sprintf(tempbuf,"%x#%x%x%x",++SequenceNum,(unsigned)time(NULL),
			get_csrng_int(), get_csrng_int());
		TransKey = strdup(tempbuf);
		user_supplied_key = FALSE;
		sprintf(tempbuf,"%s=\"%s\"",ATTR_TRANSFER_KEY,TransKey);
		Ad->Insert(tempbuf);

		// since we generated the key, it is only good on our socket.
		// so update TRANSFER_SOCK now as well.
		char const *mysocket = global_dc_sinful();
		ASSERT(mysocket);
		Ad->Assign(ATTR_TRANSFER_SOCKET,mysocket);
	} else {
		// Here the ad we were given already has a Transfer Key.
		TransKey = strdup(buf);
		user_supplied_key = TRUE;
	}

		// Init all the file lists, etc.
	if ( !SimpleInit(Ad, want_check_perms, IsServer(),
			NULL, priv, m_use_file_catalog ) )
	{
		return 0;
	}

		// At this point, we'd better have a transfer socket
	if (Ad->LookupString(ATTR_TRANSFER_SOCKET, buf, sizeof(buf)) != 1) {
		return 0;		
	}
	TransSock = strdup(buf);


	// If we are acting as the server side and we are uploading
	// any changed files, make a list of "intermediate" files
	// stored in our spool space (i.e. if transfer_files=ALWAYS).
	// This list is stored in the ClassAd which is sent to the 
	// client side, so that when the client does a final transfer
	// it can send changed files from that run + all intermediate
	// files.  -Todd Tannenbaum <tannenba@cs.wisc.edu> 6/8/01
	buf[0] = '\0';
	if ( IsServer() && upload_changed_files ) {
		CommitFiles();
		MyString filelist;
		const char* current_file = NULL;
		bool print_comma = false;
			// if desired_priv_state is PRIV_UNKNOWN, the Directory
			// object treats that just like we do: don't switch... 
		Directory spool_space( SpoolSpace, desired_priv_state );
		while ( (current_file=spool_space.Next()) ) {
			if ( UserLogFile && 
				 !file_strcmp(UserLogFile,current_file) ) 
			{
					// dont send UserLog file to the starter
				continue;
			}				

			time_t mod_time;
			filesize_t filesize;
			if ( LookupInFileCatalog(current_file, &mod_time, &filesize) ) {
				// Make certain file isn't just an input file

				// if filesize is -1, it's a special flag meaning to compare
				// the file in the old way, i.e. only checking if it is newer
				// than the stored spool_date.
				if(filesize==-1) {
					if(spool_space.GetModifyTime() <= mod_time) {
						dprintf( D_FULLDEBUG,
					 		"Not including file %s, t: %ld<=%ld, s: N/A\n",
					 		current_file, spool_space.GetModifyTime(), mod_time);
						continue;
					}
					// fall through and include file
				}
				else if((spool_space.GetModifyTime()==mod_time) &&
						(spool_space.GetFileSize()==filesize) ) {
					dprintf( D_FULLDEBUG, 
						 "Not including file %s, t: %ld, "
						 "s: " FILESIZE_T_FORMAT "\n",
						 current_file, spool_space.GetModifyTime(), spool_space.GetFileSize());
					continue;
				}
				dprintf( D_FULLDEBUG, 
					 "Including changed file %s, t: %ld, %ld, "
					 "s: " FILESIZE_T_FORMAT ", " FILESIZE_T_FORMAT "\n",
					 current_file,
					 spool_space.GetModifyTime(), mod_time,
					 spool_space.GetFileSize(), filesize );
			}

			if ( print_comma ) {
				filelist += ",";
			} else {
				print_comma = true;
			}
			filelist += current_file;			
		}
		if ( print_comma ) {
			// we know that filelist has at least one entry, so
			// insert it as an attribute into the ClassAd which
			// will get sent to our peer.
			Ad->InsertAttr(ATTR_TRANSFER_INTERMEDIATE_FILES,filelist.Value());
			dprintf(D_FULLDEBUG,"%s=\"%s\"\n",ATTR_TRANSFER_INTERMEDIATE_FILES,
					filelist.Value());
		}
	}
	if ( IsClient() && upload_changed_files ) {
		dynamic_buf = NULL;
		Ad->LookupString(ATTR_TRANSFER_INTERMEDIATE_FILES,&dynamic_buf);
		dprintf(D_FULLDEBUG,"%s=\"%s\"\n",
				ATTR_TRANSFER_INTERMEDIATE_FILES,
				dynamic_buf ? dynamic_buf : "(none)");
		if ( dynamic_buf ) {
			SpooledIntermediateFiles = strdup(dynamic_buf);
			free(dynamic_buf);
			dynamic_buf = NULL;
		}
	}
	

	// if we are acting as the server side, insert this key 
	// into our hashtable if it is not already there.
	if ( IsServer() ) {
		MyString key(TransKey);
		FileTransfer *transobject;
		if ( TranskeyTable->lookup(key,transobject) < 0 ) {
			// this key is not in our hashtable; insert it
			if ( TranskeyTable->insert(key,this) < 0 ) {
				dprintf(D_ALWAYS,
					"FileTransfer::Init failed to insert key in our table\n");
				return 0;
			}
		} else {
			// this key is already in our hashtable; this is a programmer error!
			EXCEPT("FileTransfer: Duplicate TransferKeys!");
		}
	}

	did_init = true;
	
	return 1;
}

int
FileTransfer::DownloadFiles(bool blocking)
{
	int ret_value;
	ReliSock sock;
	ReliSock *sock_to_use;

	dprintf(D_FULLDEBUG,"entering FileTransfer::DownloadFiles\n");

	if (ActiveTransferTid >= 0) {
		EXCEPT("FileTransfer::DownloadFiles called during active transfer!");
	}

	// Make certain Init() was called.
	if ( Iwd == NULL ) {
		EXCEPT("FileTransfer: Init() never called");
	}

	if (!simple_init) {
		// This method should only be called on the client side, so if
		// we are the server side, there is a programmer error -- do EXCEPT.
		if ( IsServer() ) {
			EXCEPT("FileTransfer: DownloadFiles called on server side");
		}

		sock.timeout(clientSockTimeout);

		if (IsDebugLevel(D_COMMAND)) {
			dprintf (D_COMMAND, "FileTransfer::DownloadFiles(%s,...) making connection to %s\n",
				getCommandStringSafe(FILETRANS_UPLOAD), TransSock ? TransSock : "NULL");
		}

		Daemon d( DT_ANY, TransSock );

		if ( !d.connectSock(&sock,0) ) {
			dprintf( D_ALWAYS, "FileTransfer: Unable to connect to server "
					 "%s\n", TransSock );
			Info.success = 0;
			Info.in_progress = false;
			formatstr( Info.error_desc, "FileTransfer: Unable to connecto to server %s",
					 TransSock );
			return FALSE;
		}

		CondorError err_stack;
		if ( !d.startCommand(FILETRANS_UPLOAD, &sock, 0, &err_stack, NULL, false, m_sec_session_id) ) {
			Info.success = 0;
			Info.in_progress = 0;
			formatstr( Info.error_desc, "FileTransfer: Unable to start "
					   "transfer with server %s: %s", TransSock,
					   err_stack.getFullText().c_str() );
		}

		sock.encode();

		if ( !sock.put_secret(TransKey) ||
			!sock.end_of_message() ) {
			Info.success = 0;
			Info.in_progress = false;
			formatstr( Info.error_desc, "FileTransfer: Unable to start transfer with server %s",
					 TransSock );
			return 0;
		}

		sock_to_use = &sock;
	} else {
		ASSERT(simple_sock);
		sock_to_use = simple_sock;
	}

	ret_value = Download(sock_to_use,blocking);

	// If Download was successful (it returns 1 on success) and
	// upload_changed_files is true, then we must record the current
	// time in last_download_time so in UploadFiles we have a timestamp
	// to compare.  If it is a non-blocking download, we do all this
	// in the thread reaper.
	if ( !simple_init && blocking && ret_value == 1 && upload_changed_files ) {
		time(&last_download_time);
		BuildFileCatalog();
		// Now sleep for 1 second.  If we did not do this, then jobs
		// which run real quickly (i.e. less than a second) would not
		// have their output files uploaded.  The real reason we must
		// sleep here is time_t is only at the resolution on 1 second.
		sleep(1);
	}

	return ret_value;
}


void
FileTransfer::ComputeFilesToSend()
{
	StringList final_files_to_send(NULL,",");
	if (IntermediateFiles) delete(IntermediateFiles);
	IntermediateFiles = NULL;
	FilesToSend = NULL;
	EncryptFiles = NULL;
	DontEncryptFiles = NULL;

	if ( upload_changed_files && last_download_time > 0 ) {
		// Here we will upload only files in the Iwd which have changed
		// since we downloaded last.  We only do this if 
		// upload_changed_files it true, and if last_download_time > 0
		// which means we have already downloaded something.

		// If this is the final transfer, be certain to send back
		// not only the files which have been modified during this run,
		// but also the files which have been modified during
		// previous runs (i.e. the SpooledIntermediateFiles).
		if ( m_final_transfer_flag && SpooledIntermediateFiles ) {
			final_files_to_send.initializeFromString(SpooledIntermediateFiles);
		}

			// if desired_priv_state is PRIV_UNKNOWN, the Directory
			// object treats that just like we do: don't switch... 
		Directory dir( Iwd, desired_priv_state );

		const char *proxy_file = NULL;
		std::string proxy_file_buf;
		if(jobAd.LookupString(ATTR_X509_USER_PROXY, proxy_file_buf)) {			
			proxy_file = condor_basename(proxy_file_buf.c_str());
		}

		const char *f;
		while( (f=dir.Next()) ) {
			// don't send back condor_exec.*
			if ( MATCH == file_strcmp ( f, "condor_exec." ) ) {
				dprintf ( D_FULLDEBUG, "Skipping %s\n", f );
				continue;
			}			
			if( proxy_file && file_strcmp(f, proxy_file) == MATCH ) {
				dprintf( D_FULLDEBUG, "Skipping %s\n", f );
				continue;
			}

			// for now, skip all subdirectory names until we add
			// subdirectory support into FileTransfer.
			if ( dir.IsDirectory() ) {
				dprintf( D_FULLDEBUG, "Skipping dir %s\n", f );
				continue;
			}

			// if this file is has been modified since last download,
			// add it to the list of files to transfer.
			bool send_it = false;

			// look up the file name in the catalog.  if it does not exist, it
			// is a new file, and is always transfered back.  if it the
			// filename does already exist in the catalog, then the
			// modification date and filesize parameters are filled in.
			// if either has changed, transfer the file.

			filesize_t filesize;
			time_t modification_time;
			if ( ExceptionFiles && ExceptionFiles->file_contains(f) ) {
				dprintf ( 
					D_FULLDEBUG, 
					"Skipping file in exception list: %s\n", 
					f );
				continue;
			} else if ( !LookupInFileCatalog(f, &modification_time, &filesize) ) {
				// file was not found.  send it.
				dprintf( D_FULLDEBUG, 
						 "Sending new file %s, time==%ld, size==%ld\n",	
						 f, dir.GetModifyTime(), (long) dir.GetFileSize() );
				send_it = true;
			}
			else if (final_files_to_send.file_contains(f)) {
				dprintf( D_FULLDEBUG, 
						 "Sending previously changed file %s\n", f);
				send_it = true;
			}
			else if (OutputFiles && OutputFiles->file_contains(f)) {
				dprintf(D_FULLDEBUG, 
				        "Sending dynamically added output file %s\n",
				        f);
				send_it = true;
			}
			else if (filesize == -1) {
				// this is a special block of code that should eventually go
				// away.  essentially, setting the filesize to -1 means that
				// we only transfer the file if the timestamp is newer than
				// the spool date stored in the job ad (how it's always worked
				// in the past).  once the FileCatalog is stored persistently
				// somewhere, this mode of operation can go away.
				if (dir.GetModifyTime() > modification_time) {
					// include the file if the time stamp is greater than
					// the spool date (stored in modification_time).
					dprintf( D_FULLDEBUG, 
						 "Sending changed file %s, t: %ld, %ld, "
						 "s: " FILESIZE_T_FORMAT ", N/A\n",
						 f, dir.GetModifyTime(), modification_time,
						 dir.GetFileSize());
					send_it = true;
				} else {
					// if filesize was -1 but the timestamp was earlier than
					// modification_time, do NOT include the file.
					dprintf( D_FULLDEBUG,
					 	"Skipping file %s, t: %ld<=%ld, s: N/A\n",
					 	f, dir.GetModifyTime(), modification_time);
					continue;
				}
			}
			else if ((filesize != dir.GetFileSize()) ||
					(modification_time != dir.GetModifyTime()) ) {
				// file has changed in size or modification time.  this
				// doesn't catch the case where the file was modified
				// without changing size and is then back-dated.  use a hash
				// or something if that's truly needed, and compare the
				// checksums.
				dprintf( D_FULLDEBUG, 
					 "Sending changed file %s, t: %ld, %ld, "
					 "s: " FILESIZE_T_FORMAT ", " FILESIZE_T_FORMAT "\n",
					 f, dir.GetModifyTime(), modification_time,
					 dir.GetFileSize(), filesize );
				send_it = true;
			}
			else {
				dprintf( D_FULLDEBUG,
						 "Skipping file %s, t: %" PRIi64"==%" PRIi64
						 ", s: %" PRIi64"==%" PRIi64"\n",
						 f,
						 (PRIi64_t)dir.GetModifyTime(),
						 (PRIi64_t)modification_time,
						 (PRIi64_t)dir.GetFileSize(),
						 (PRIi64_t)filesize );
				continue;
			}
			if(send_it) {
				if (!IntermediateFiles) {
					// Initialize it with intermediate files
					// which we already have spooled.  We want to send
					// back these files + any that have changed this time.
					IntermediateFiles = new StringList(NULL,",");
					FilesToSend = IntermediateFiles;
					EncryptFiles = EncryptOutputFiles;
					DontEncryptFiles = DontEncryptOutputFiles;
				}
				// now append changed file to list only if not already there 
				if ( IntermediateFiles->file_contains(f) == FALSE ) {
					IntermediateFiles->append(f);
				}
			}
		}
	}
}

void
FileTransfer::RemoveInputFiles(const char *sandbox_path)
{
	char *old_iwd;
	int old_transfer_flag;
	StringList do_not_remove;
	const char *f;

	if (!sandbox_path) {
		ASSERT(SpoolSpace);
		sandbox_path = SpoolSpace;
	}

	// See if the sandbox_path exists.  If it does not, we're done.
	if ( !IsDirectory(sandbox_path) ) {
		return;
	}

	old_iwd = Iwd;
	old_transfer_flag = m_final_transfer_flag;

	Iwd = strdup(sandbox_path);
	m_final_transfer_flag = 1;

	ComputeFilesToSend();

	// if FilesToSend is still NULL, then the user did not
	// want anything sent back via modification date.  
	if ( FilesToSend == NULL ) {
		FilesToSend = OutputFiles;
		EncryptFiles = EncryptOutputFiles;
		DontEncryptFiles = DontEncryptOutputFiles;
	}

	// Make a new list that only contains file basenames.
	FilesToSend->rewind();
	while ( (f=FilesToSend->next()) ) {
		do_not_remove.append( condor_basename(f) );
	}

	// Now, remove all files in the sandbox_path EXCEPT
	// for files in list do_not_remove.
	Directory dir( sandbox_path, desired_priv_state );

	while( (f=dir.Next()) ) {
			// for now, skip all subdirectory names until we add
			// subdirectory support into FileTransfer.
		if( dir.IsDirectory() ) {
			continue;
		}
			
			// skip output files
		if ( do_not_remove.file_contains(f) == TRUE ) {
			continue;
		}

			// if we made it here, we are looking at an "input" file.
			// so remove it.
		dir.Remove_Current_File();
	}

	m_final_transfer_flag = old_transfer_flag;
	free(Iwd);
	Iwd = old_iwd;

	return;
}


int
FileTransfer::UploadFiles(bool blocking, bool final_transfer)
{
    ReliSock sock;
	ReliSock *sock_to_use;

	StringList changed_files(NULL,",");

	dprintf(D_FULLDEBUG,
		"entering FileTransfer::UploadFiles (final_transfer=%d)\n",
		final_transfer ? 1 : 0);

	if (ActiveTransferTid >= 0) {
		EXCEPT("FileTransfer::UpLoadFiles called during active transfer!");
	}

	// Make certain Init() was called.
	if ( Iwd == NULL ) {
		EXCEPT("FileTransfer: Init() never called");
	}

	// This method should only be called on the client side, so if
	// we are the server side, there is a programmer error -- do EXCEPT.
	if ( !simple_init && IsServer() ) {
		EXCEPT("FileTransfer: UploadFiles called on server side");
	}

	// If we're a client talking to a 7.5.6 or older schedd, we want
	// to send the user log as an input file.
	if ( UserLogFile && TransferUserLog && simple_init && !nullFile( UserLogFile ) ) {
		if ( !InputFiles->file_contains( UserLogFile ) )
			InputFiles->append( UserLogFile );
	}

	// set flag saying if this is the last upload (i.e. job exited)
	m_final_transfer_flag = final_transfer ? 1 : 0;

	// figure out what to send based upon modification date
	ComputeFilesToSend();

	// if FilesToSend is still NULL, then the user did not
	// want anything sent back via modification date.  so
	// send the input or output sandbox, depending what 
	// direction we are going.
	if ( FilesToSend == NULL ) {
		if ( simple_init ) {
			if ( IsClient() ) {
				// condor_submit sending to the schedd
				FilesToSend = InputFiles;
				EncryptFiles = EncryptInputFiles;
				DontEncryptFiles = DontEncryptInputFiles;
			} else {
				// schedd sending to condor_transfer_data
				FilesToSend = OutputFiles;
				EncryptFiles = EncryptOutputFiles;
				DontEncryptFiles = DontEncryptOutputFiles;
			}
		} else {
			// starter sending back to the shadow
			FilesToSend = OutputFiles;
			EncryptFiles = EncryptOutputFiles;
			DontEncryptFiles = DontEncryptOutputFiles;
		}

	}

	if ( !simple_init ) {
		// Optimization: files_to_send now contains the files to upload.
		// If files_to_send is NULL, then we have nothing to send, so
		// we can return with SUCCESS immedidately.
		if ( FilesToSend == NULL ) {
			return 1;
		}

		sock.timeout(clientSockTimeout);

		if (IsDebugLevel(D_COMMAND)) {
			dprintf (D_COMMAND, "FileTransfer::UploadFiles(%s,...) making connection to %s\n",
				getCommandStringSafe(FILETRANS_DOWNLOAD), TransSock ? TransSock : "NULL");
		}

		Daemon d( DT_ANY, TransSock );

		if ( !d.connectSock(&sock,0) ) {
			dprintf( D_ALWAYS, "FileTransfer: Unable to connect to server "
					 "%s\n", TransSock );
			Info.success = 0;
			Info.in_progress = false;
			formatstr( Info.error_desc, "FileTransfer: Unable to connecto to server %s",
					 TransSock );
			return FALSE;
		}

		CondorError err_stack;
		if ( !d.startCommand(FILETRANS_DOWNLOAD, &sock, clientSockTimeout, &err_stack, NULL, false, m_sec_session_id) ) {
			Info.success = 0;
			Info.in_progress = 0;
			formatstr( Info.error_desc, "FileTransfer: Unable to start "
					   "transfer with server %s: %s", TransSock,
					   err_stack.getFullText().c_str() );
		}

		sock.encode();

		if ( !sock.put_secret(TransKey) ||
			!sock.end_of_message() ) {
			Info.success = 0;
			Info.in_progress = false;
			formatstr( Info.error_desc, "FileTransfer: Unable to start transfer with server %s",
					 TransSock );
			return 0;
		}

		dprintf( D_FULLDEBUG,
				 "FileTransfer::UploadFiles: sent TransKey=%s\n", TransKey );

		sock_to_use = &sock;
	} else {
		ASSERT(simple_sock);
		sock_to_use = simple_sock;
	}


	int retval = Upload(sock_to_use,blocking);

	return( retval );
}

int
FileTransfer::HandleCommands(Service *, int command, Stream *s)
{
	FileTransfer *transobject;
	char *transkey = NULL;

	dprintf(D_FULLDEBUG,"entering FileTransfer::HandleCommands\n");

	if ( s->type() != Stream::reli_sock ) {
		// the FileTransfer object only works on TCP, not UDP
		return 0;
	}
	ReliSock *sock = (ReliSock *) s;

	// turn off timeouts on sockets, since our peer could get suspended
	// (like in the case of the starter sending files back to the shadow)
	sock->timeout(0);

	// code() allocates memory for the string if the pointer is NULL.
	if (!sock->get_secret(transkey) ||
		!sock->end_of_message() ) {
		dprintf(D_FULLDEBUG,
			    	"FileTransfer::HandleCommands failed to read transkey\n");
		if (transkey) free(transkey);
		return 0;
	}
	dprintf(D_FULLDEBUG,
					"FileTransfer::HandleCommands read transkey=%s\n",transkey);

	MyString key(transkey);
	free(transkey);
	if ( (TranskeyTable == NULL) || 
		 (TranskeyTable->lookup(key,transobject) < 0) ) {		
		// invalid transkey sent; send back 0 for failure
		sock->snd_int(0,1);	// sends a "0" then an end_of_record
		dprintf(D_FULLDEBUG,"transkey is invalid!\n");
		// sleep for 5 seconds to prevent brute-force attack on guessing key
		sleep(5);
		return FALSE;
	}

	switch (command) {
		case FILETRANS_UPLOAD:
			// We want to upload all files listed as InputFiles,
			// but first append to InputFiles any files in our SpoolSpace.
			// And before we do that, call CommitFiles() to finish any
			// previous commit which may have been prematurely aborted.
			{
			const char *currFile;
			transobject->CommitFiles();
			Directory spool_space( transobject->SpoolSpace, 
								   transobject->getDesiredPrivState() );
			while ( (currFile=spool_space.Next()) ) {
				if (transobject->UserLogFile && 
						!file_strcmp(transobject->UserLogFile,currFile)) 
				{
						// Don't send the userlog from the shadow to starter
					continue;
				} else {
						// We aren't looking at the userlog file... ship it!
					const char *filename = spool_space.GetFullPath();
					if ( !transobject->InputFiles->file_contains(filename) &&
						 !transobject->InputFiles->file_contains(condor_basename(filename)) ) {
						transobject->InputFiles->append(filename);
					}
				}
			}
			transobject->FilesToSend = transobject->InputFiles;
			transobject->EncryptFiles = transobject->EncryptInputFiles;
			transobject->DontEncryptFiles = transobject->DontEncryptInputFiles;
			transobject->Upload(sock,ServerShouldBlock);
			}
			break;
		case FILETRANS_DOWNLOAD:
			transobject->Download(sock,ServerShouldBlock);
			break;
		default:
			dprintf(D_ALWAYS,
				"FileTransfer::HandleCommands: unrecognized command %d\n",
				command);
			return 0;
			break;
	}

	return 1;
	// return KEEP_STREAM;
}


bool
FileTransfer::SetServerShouldBlock( bool block )
{
	bool old_value = ServerShouldBlock;
	ServerShouldBlock = block;
	return old_value;
}

int
FileTransfer::Reaper(Service *, int pid, int exit_status)
{
	FileTransfer *transobject;
	if (!TransThreadTable || TransThreadTable->lookup(pid,transobject) < 0) {
		dprintf(D_ALWAYS, "unknown pid %d in FileTransfer::Reaper!\n", pid);
		return FALSE;
	}
	transobject->ActiveTransferTid = -1;
	TransThreadTable->remove(pid);

	transobject->Info.duration = time(NULL)-transobject->TransferStart;
	transobject->Info.in_progress = false;
	if( WIFSIGNALED(exit_status) ) {
		transobject->Info.success = false;
		transobject->Info.try_again = true;
		transobject->Info.error_desc.formatstr("File transfer failed (killed by signal=%d)", WTERMSIG(exit_status));
		if( transobject->registered_xfer_pipe ) {
			transobject->registered_xfer_pipe = false;
			daemonCore->Cancel_Pipe(transobject->TransferPipe[0]);
		}
		dprintf( D_ALWAYS, "%s\n", transobject->Info.error_desc.Value() );
	} else {
		if( WEXITSTATUS(exit_status) == 1 ) {
			dprintf( D_ALWAYS, "File transfer completed successfully.\n" );
			transobject->Info.success = true;
		} else {
			dprintf( D_ALWAYS, "File transfer failed (status=%d).\n",
					 WEXITSTATUS(exit_status) );
			transobject->Info.success = false;
		}
	}

		// Close the write end of the pipe so we don't block trying
		// to read from it if the child closes it prematurely.
		// We don't do this until this late stage in the game, because
		// in windows everything currently happens in the main thread.
	if( transobject->TransferPipe[1] != -1 ) {
		daemonCore->Close_Pipe(transobject->TransferPipe[1]);
		transobject->TransferPipe[1] = -1;
	}

		// if we haven't already read the final status update, do it now
	if( transobject->registered_xfer_pipe ) {
		// It's possible that the pipe contains a progress update message
		// followed by the final update message. Keep reading until we
		// get the final message or encounter an error.
		do {
			transobject->ReadTransferPipeMsg();
		} while ( transobject->Info.success &&
				  transobject->Info.xfer_status != XFER_STATUS_DONE );
	}

	if( transobject->registered_xfer_pipe ) {
		transobject->registered_xfer_pipe = false;
		daemonCore->Cancel_Pipe(transobject->TransferPipe[0]);
	}

	daemonCore->Close_Pipe(transobject->TransferPipe[0]);
	transobject->TransferPipe[0] = -1;

	if ( transobject->Info.success ) {
		if ( transobject->Info.type == DownloadFilesType ) {
			transobject->downloadEndTime = condor_gettimestamp_double();

		} else if ( transobject->Info.type == UploadFilesType ) {
			transobject->uploadEndTime = condor_gettimestamp_double();

		}
	}

	// If Download was successful (it returns 1 on success) and
	// upload_changed_files is true, then we must record the current
	// time in last_download_time so in UploadFiles we have a timestamp
	// to compare.  If it is a non-blocking download, we do all this
	// in the thread reaper.
	if ( transobject->Info.success && transobject->upload_changed_files &&
		 transobject->IsClient() && transobject->Info.type == DownloadFilesType ) {
		time(&(transobject->last_download_time));
		transobject->BuildFileCatalog(0, transobject->Iwd, &(transobject->last_download_catalog));
		// Now sleep for 1 second.  If we did not do this, then jobs
		// which run real quickly (i.e. less than a second) would not
		// have their output files uploaded.  The real reason we must
		// sleep here is time_t is only at the resolution on 1 second.
		sleep(1);
	}

	transobject->callClientCallback();

	return TRUE;
}

void
FileTransfer::callClientCallback()
{
	if (ClientCallback) {
		dprintf(D_FULLDEBUG,
				"Calling client FileTransfer handler function.\n");
		(*(ClientCallback))(this);
	}
	if (ClientCallbackCpp) {
		dprintf(D_FULLDEBUG,
				"Calling client FileTransfer handler function.\n");
		((ClientCallbackClass)->*(ClientCallbackCpp))(this);
	}
}

bool
FileTransfer::ReadTransferPipeMsg()
{
	int n;

	char cmd=0;
	n = daemonCore->Read_Pipe( TransferPipe[0], &cmd, sizeof(cmd) );
	if(n != sizeof( cmd )) goto read_failed;

	if( cmd == IN_PROGRESS_UPDATE_XFER_PIPE_CMD ) {
		int i=XFER_STATUS_UNKNOWN;
		n = daemonCore->Read_Pipe( TransferPipe[0],
								   (char *)&i,
								   sizeof( int ) );
		if(n != sizeof( int )) goto read_failed;
		Info.xfer_status = (FileTransferStatus)i;

		if( ClientCallbackWantsStatusUpdates ) {
			callClientCallback();
		}
	}
	else if( cmd == FINAL_UPDATE_XFER_PIPE_CMD ) {
		Info.xfer_status = XFER_STATUS_DONE;

		n = daemonCore->Read_Pipe( TransferPipe[0],
								   (char *)&Info.bytes,
								   sizeof( filesize_t) );
		if(n != sizeof( filesize_t )) goto read_failed;
		if( Info.type == DownloadFilesType ) {
			bytesRcvd += Info.bytes;
		}
		else {
			bytesSent += Info.bytes;
		}

		n = daemonCore->Read_Pipe( TransferPipe[0],
								   (char *)&Info.try_again,
								   sizeof( bool ) );
		if(n != sizeof( bool )) goto read_failed;

	
		n = daemonCore->Read_Pipe( TransferPipe[0],
								   (char *)&Info.hold_code,
								   sizeof( int ) );
		if(n != sizeof( int )) goto read_failed;

		n = daemonCore->Read_Pipe( TransferPipe[0],
								   (char *)&Info.hold_subcode,
								   sizeof( int ) );
		if(n != sizeof( int )) goto read_failed;

		int error_len = 0;
		n = daemonCore->Read_Pipe( TransferPipe[0],
								   (char *)&error_len,
								   sizeof( int ) );
		if(n != sizeof( int )) goto read_failed;

		if(error_len) {
			char *error_buf = new char[error_len];
			ASSERT(error_buf);

			n = daemonCore->Read_Pipe( TransferPipe[0],
									   error_buf,
									   error_len );
			if(n != error_len) goto read_failed;
			Info.error_desc = error_buf;

			delete [] error_buf;
		}

		int spooled_files_len = 0;
		n = daemonCore->Read_Pipe( TransferPipe[0],
								   (char *)&spooled_files_len,
								   sizeof( int ) );
		if(n != sizeof( int )) goto read_failed;

		if(spooled_files_len) {
			char *spooled_files_buf = new char[spooled_files_len];
			ASSERT(spooled_files_buf);

			n = daemonCore->Read_Pipe( TransferPipe[0],
									   spooled_files_buf,
									   spooled_files_len );
			if(n != spooled_files_len) goto read_failed;
			Info.spooled_files = spooled_files_buf;

			delete [] spooled_files_buf;
		}

		if( registered_xfer_pipe ) {
			registered_xfer_pipe = false;
			daemonCore->Cancel_Pipe(TransferPipe[0]);
		}
	}
	else {
		EXCEPT("Invalid file transfer pipe command %d",cmd);
	}

	return true;

 read_failed:
	Info.success = false;
	Info.try_again = true;
	if( Info.error_desc.IsEmpty() ) {
		Info.error_desc.formatstr("Failed to read status report from file transfer pipe (errno %d): %s",errno,strerror(errno));
		dprintf(D_ALWAYS,"%s\n",Info.error_desc.Value());
	}
	if( registered_xfer_pipe ) {
		registered_xfer_pipe = false;
		daemonCore->Cancel_Pipe(TransferPipe[0]);
	}

	return false;
}

void
FileTransfer::UpdateXferStatus(FileTransferStatus status)
{
	if( Info.xfer_status != status ) {
		bool write_failed = false;
		if( TransferPipe[1] != -1 ) {
			int n;
			char cmd = IN_PROGRESS_UPDATE_XFER_PIPE_CMD;

			n = daemonCore->Write_Pipe( TransferPipe[1],
										&cmd,
										sizeof(cmd) );
			if(n != sizeof(cmd)) write_failed = true;

			if(!write_failed) {
				int i = status;
				n = daemonCore->Write_Pipe( TransferPipe[1],
											(char *)&i,
											sizeof(int) );
				if(n != sizeof(int)) write_failed = true;
			}
		}

		if( !write_failed ) {
			Info.xfer_status = status;
		}
	}
}

int
FileTransfer::TransferPipeHandler(int p)
{
	ASSERT( p == TransferPipe[0] );

	return ReadTransferPipeMsg();
}

int
FileTransfer::Download(ReliSock *s, bool blocking)
{
	dprintf(D_FULLDEBUG,"entering FileTransfer::Download\n");
	
	if (ActiveTransferTid >= 0) {
		EXCEPT("FileTransfer::Download called during active transfer!");
	}

	Info.duration = 0;
	Info.type = DownloadFilesType;
	Info.success = true;
	Info.in_progress = true;
	Info.xfer_status = XFER_STATUS_UNKNOWN;
	TransferStart = time(NULL);

	if (blocking) {

		int status = DoDownload( &Info.bytes, (ReliSock *) s );
		Info.duration = time(NULL)-TransferStart;
		Info.success = ( status >= 0 );
		Info.in_progress = false;
		return Info.success;

	} else {

		ASSERT( daemonCore );

		// make a pipe to communicate with our thread
		if (!daemonCore->Create_Pipe(TransferPipe,true)) {
			dprintf(D_ALWAYS, "Create_Pipe failed in "
					"FileTransfer::Upload\n");
			return FALSE;
		}

		if (-1 == daemonCore->Register_Pipe(TransferPipe[0],
											"Download Results",
											(PipeHandlercpp)&FileTransfer::TransferPipeHandler,
											"TransferPipeHandler",
											this)) {
			dprintf(D_ALWAYS,"FileTransfer::Upload() failed to register pipe.\n");
			return FALSE;
		}
		else {
			registered_xfer_pipe = true;
		}

		download_info *info = (download_info *)malloc(sizeof(download_info));
		ASSERT ( info );
		info->myobj = this;
		ActiveTransferTid = daemonCore->
			Create_Thread((ThreadStartFunc)&FileTransfer::DownloadThread,
						  (void *)info, s, ReaperId);
		if (ActiveTransferTid == FALSE) {
			dprintf(D_ALWAYS,
					"Failed to create FileTransfer DownloadThread!\n");
			ActiveTransferTid = -1;
			free(info);
			return FALSE;
		}
		dprintf(D_FULLDEBUG,
				"FileTransfer: created download transfer process with id %d\n",
				ActiveTransferTid);
		// daemonCore will free(info) when the thread exits
		TransThreadTable->insert(ActiveTransferTid, this);

		downloadStartTime = condor_gettimestamp_double();

	}
	
	return 1;
}

int
FileTransfer::DownloadThread(void *arg, Stream *s)
{
	filesize_t	total_bytes;

	dprintf(D_FULLDEBUG,"entering FileTransfer::DownloadThread\n");
	FileTransfer * myobj = ((download_info *)arg)->myobj;
	int status = myobj->DoDownload( &total_bytes, (ReliSock *)s );

	if(!myobj->WriteStatusToTransferPipe(total_bytes)) {
		return 0;
	}
	return ( status == 0 );
}

void
FileTransfer::AddDownloadFilenameRemap(char const *source_name,char const *target_name) {
	if(!download_filename_remaps.IsEmpty()) {
		download_filename_remaps += ";";
	}
	download_filename_remaps += source_name;
	download_filename_remaps += "=";
	download_filename_remaps += target_name;
}

void
FileTransfer::AddDownloadFilenameRemaps(char const *remaps) {
	if(!download_filename_remaps.IsEmpty()) {
		download_filename_remaps += ";";
	}
	download_filename_remaps += remaps;
}


/*
  Define a macro to restore our priv state (if needed) and return.  We
  do this so we don't leak priv states in functions where we need to
  be in our desired state.
*/

#define return_and_resetpriv(i)                     \
    if( saved_priv != PRIV_UNKNOWN )                \
        _set_priv(saved_priv,__FILE__,__LINE__,1);  \
    if ( m_reuse_dir && !reservation_id.empty() ) { \
        CondorError err;                            \
        if (!m_reuse_dir->ReleaseSpace(reservation_id, err)) { \
            dprintf(D_FULLDEBUG, "Failed to release space: %s\n", \
                err.getFullText().c_str());         \
        }                                           \
    }                                               \
    return i;


int
FileTransfer::DoDownload( filesize_t *total_bytes, ReliSock *s)
{
	int rc = 0;
	filesize_t bytes=0;
	filesize_t peer_max_transfer_bytes=0;
	MyString filename;;
	MyString fullname;
	int final_transfer = 0;
	bool download_success = true;
	bool try_again = true;
	int hold_code = 0;
	int hold_subcode = 0;
	MyString error_buf;
	int delegation_method = 0; /* 0 means this transfer is not a delegation. 1 means it is.*/
	time_t start, elapsed;
	int numFiles = 0;
	ClassAd pluginStatsAd;

	// Variable for deferred transfers, used to transfer multiple files at once
	// by certain filte transfer plugins. These need to be scoped to the full
	// function.
	bool isDeferredTransfer = false;
	classad::ClassAdUnParser unparser;
	std::map<std::string, std::string> deferredTransfers;
	std::unique_ptr<classad::ClassAd> thisTransfer( new classad::ClassAd() );

	bool I_go_ahead_always = false;
	bool peer_goes_ahead_always = false;
	DCTransferQueue xfer_queue(m_xfer_queue_contact_info);
	CondorError errstack;

	priv_state saved_priv = PRIV_UNKNOWN;
	*total_bytes = 0;

	downloadStartTime = condor_gettimestamp_double();

		/* Track the potential data reuse
		 */
	std::vector<ReuseInfo> reuse_info;
	std::string reservation_id;

		// When we are signing URLs, we want to make sure that the requested
		// prefix is valid.
	std::vector<std::string> output_url_prefixes;
	if (OutputDestination)
	{
		dprintf(D_FULLDEBUG, "DoDownload: Valid output URL prefix: %s\n", OutputDestination);
		output_url_prefixes.emplace_back(OutputDestination);
	}
	std::string remaps;
	if (jobAd.EvaluateAttrString(ATTR_TRANSFER_OUTPUT_REMAPS, remaps)) {
		StringList remaps_list(remaps.c_str(), ";");
		remaps_list.rewind();
		const char *list_item;
		while ( (list_item = remaps_list.next()) ) {
			std::string list_item_str(list_item);
			auto idx = list_item_str.find("=");
			if (idx != std::string::npos) {
				std::string url = list_item_str.substr(idx + 1);
				trim(url);
				dprintf(D_FULLDEBUG, "DoDownload: Valid output URL prefix: %s\n", url.c_str());
				output_url_prefixes.emplace_back(url);
			}
		}
	}

	// we want to tell get_file() to perform an fsync (i.e. flush to disk)
	// the files we download if we are the client & we will need to upload
	// the changed files later on.  why do we need this fsync, you ask?  	
	// because we figure out which files have changed by looking at the file's
	// modification time.  on some operating systems, the file modification time
	// is _not_ when it was really modified, but when the modifications are actually
	// commited to disk.  thus we must fsync in order to make certain we do not think
	// that files like condor_exec.exe have been modified, etc. -Todd <tannenba@cs>
	bool want_fsync = ( ((IsClient() && !simple_init) ||  // starter receiving
						 (IsServer() && simple_init))     // schedd receiving
						 && upload_changed_files );

	dprintf(D_FULLDEBUG,"entering FileTransfer::DoDownload sync=%d\n",
					want_fsync ? 1 : 0);

	s->decode();

	// find out if encryption is enabled by default or not on this socket
	bool socket_default_crypto = s->get_encryption();

	// find out if this is the final download.  if so, we put the files
	// into the user's Iwd instead of our SpoolSpace.
	if( !s->code(final_transfer) ) {
		dprintf(D_FULLDEBUG,"DoDownload: exiting at %d\n",__LINE__);
		return_and_resetpriv( -1 );
	}
//	dprintf(D_FULLDEBUG,"TODD filetransfer DoDownload final_transfer=%d\n",final_transfer);

	filesize_t sandbox_size = 0;
	if( PeerDoesXferInfo ) {
		ClassAd xfer_info;
		if( !getClassAd(s,xfer_info) ) {
			dprintf(D_FULLDEBUG,"DoDownload: failed to receive xfer info; exiting at %d\n",__LINE__);
			return_and_resetpriv( -1 );
		}
		xfer_info.LookupInteger(ATTR_SANDBOX_SIZE,sandbox_size);
	}

	if( !s->end_of_message() ) {
		dprintf(D_FULLDEBUG,"DoDownload: exiting at %d\n",__LINE__);
		return_and_resetpriv( -1 );
	}	

	if( !final_transfer && IsServer() ) {
		SpooledJobFiles::createJobSpoolDirectory(&jobAd,desired_priv_state);
	}

	bool sign_s3_urls = param_boolean("SIGN_S3_URLS", true) && PeerDoesS3Urls;

		/*
		  If we want to change priv states, do it now.
		  Even if we don't transfer any files, we write a commit
		  file at the end.
		*/
	if( want_priv_change ) {
		saved_priv = set_priv( desired_priv_state );
	}

	// Start the main download loop. Read reply codes + filenames off a
	// socket wire, s, then handle downloads according to the reply code.
	for (;;) {
		TransferCommand xfer_command = TransferCommand::Unknown;
		{
			int reply;
			if( !s->code(reply) ) {
				dprintf(D_FULLDEBUG,"DoDownload: exiting at %d\n",__LINE__);
				return_and_resetpriv( -1 );
			}
			xfer_command = static_cast<TransferCommand>(reply);
		}
		if( !s->end_of_message() ) {
			dprintf(D_FULLDEBUG,"DoDownload: exiting at %d\n",__LINE__);
			return_and_resetpriv( -1 );
		}
		dprintf( D_FULLDEBUG, "FILETRANSFER: incoming file_command is %i\n", static_cast<int>(xfer_command));
		if( xfer_command == TransferCommand::Finished ) {
			break;
		}

		if ((xfer_command == TransferCommand::EnableEncryption) || (PeerDoesS3Urls && xfer_command == TransferCommand::DownloadUrl)) {
			bool cryp_ret = s->set_crypto_mode(true);
			if (!cryp_ret) {
				dprintf(D_ALWAYS,"DoDownload: failed to enable crypto on incoming file, exiting at %d\n",__LINE__);
				return_and_resetpriv( -1 );
			}
		} else if (xfer_command == TransferCommand::DisableEncryption) {
			s->set_crypto_mode(false);
		} else {
			bool cryp_ret = s->set_crypto_mode(socket_default_crypto);
			if(!cryp_ret) {
				dprintf(D_ALWAYS,"DoDownload: failed to change crypto to %i on incoming file, "
					"exiting at %d\n", socket_default_crypto, __LINE__);
				return_and_resetpriv( -1 );
			}
		}

		if( !s->code(filename) ) {
			dprintf(D_FULLDEBUG,"DoDownload: exiting at %d\n",__LINE__);
			return_and_resetpriv( -1 );
		}

			// This check must come after we have called set_priv()
		if( !LegalPathInSandbox(filename.Value(),Iwd) ) {
			// Our peer sent us an illegal path!

			download_success = false;
			try_again = false;
			hold_code = CONDOR_HOLD_CODE_DownloadFileError;
			hold_subcode = EPERM;

			error_buf.formatstr_cat(
				" Attempt to write to illegal sandbox path: %s",
				filename.Value());

			dprintf(D_ALWAYS,"DoDownload: attempt to write to illegal sandbox path by our peer %s: %s.\n",
					s->peer_description(),
					filename.Value());

			// Just write to /dev/null and go ahead with the download.
			// This allows us to consume the rest of the downloads and
			// propagate the error message, put the job on hold, etc.
			filename = NULL_FILE;
		}

		if( !strcmp(filename.Value(),NULL_FILE) ) {
			fullname = filename;
		}
		else if( final_transfer || IsClient() ) {
			MyString remap_filename;
			int res = filename_remap_find(download_filename_remaps.Value(),filename.Value(),remap_filename,0);
			dprintf(D_FULLDEBUG, "REMAP: res is %i -> %s !\n", res, remap_filename.Value());
			if (res == -1) {
				// there was loop in the file transfer remaps, so set a good
				// hold reason
				error_buf.formatstr("remaps resulted in a cycle: %s", remap_filename.Value());
				dprintf(D_ALWAYS,"REMAP: DoDownload: %s\n",error_buf.Value());
				download_success = false;
				try_again = false;
				hold_code = CONDOR_HOLD_CODE_DownloadFileError;
				hold_subcode = EPERM;

					// In order for the wire protocol to remain in a well
					// defined state, we must consume the rest of the
					// file transmission without writing.
				fullname = NULL_FILE;
			}
			else if(res) {
					// If we are a client downloading the output sandbox, it makes no sense for
					// us to "download" _to_ a URL; the server sent us this in a logic error
					// unless it was simply a status report (reply == 999)
				if (IsUrl(remap_filename.Value())) {
					if (xfer_command != TransferCommand::Other) {
						error_buf.formatstr("Remap of output file resulted in a URL: %s", remap_filename.Value());
						dprintf(D_ALWAYS, "REMAP: DoDownload: %s\n",error_buf.Value());
						download_success = false;
						try_again = false;
						hold_code = CONDOR_HOLD_CODE_DownloadFileError;
						hold_subcode = EPERM;
						fullname = NULL_FILE;
					} else {
						// fullname is used in various error messages; keep it
						// as something reasonabel.
						fullname.formatstr("%s%c%s",Iwd,DIR_DELIM_CHAR,filename.Value());
					}
				// legit remap was found
				} else if(fullpath(remap_filename.Value())) {
					fullname = remap_filename;
				}
				else {
					fullname.formatstr("%s%c%s",Iwd,DIR_DELIM_CHAR,remap_filename.Value());
				}
				dprintf(D_FULLDEBUG,"Remapped downloaded file from %s to %s\n",filename.Value(),remap_filename.Value());
			}
			else {
				// no remap found
				fullname.formatstr("%s%c%s",Iwd,DIR_DELIM_CHAR,filename.Value());
			}
#ifdef WIN32
			// check for write permission on this file, if we are supposed to check
			if ( (fullname != NULL_FILE) && perm_obj && (perm_obj->write_access(fullname.Value()) != 1) ) {
				// we do _not_ have permission to write this file!!
				error_buf.formatstr("Permission denied to write file %s!",
				                   fullname.Value());
				dprintf(D_ALWAYS,"DoDownload: %s\n",error_buf.Value());
				download_success = false;
				try_again = false;
				hold_code = CONDOR_HOLD_CODE_DownloadFileError;
				hold_subcode = EPERM;

					// In order for the wire protocol to remain in a well
					// defined state, we must consume the rest of the
					// file transmission without writing.
				fullname = NULL_FILE;
			}
#endif
		} else {
			fullname.formatstr("%s%c%s",TmpSpoolSpace,DIR_DELIM_CHAR,filename.Value());
		}

		auto iter = std::find_if(reuse_info.begin(), reuse_info.end(),
			[&](ReuseInfo &info){return !strcmp(filename.Value(), info.filename().c_str());});
		bool should_reuse = !reservation_id.empty() && m_reuse_dir && iter != reuse_info.end();

		if( PeerDoesGoAhead ) {
			if( !s->end_of_message() ) {
				dprintf(D_FULLDEBUG,"DoDownload: failed on eom before GoAhead: exiting at %d\n",__LINE__);
				return_and_resetpriv( -1 );
			}

			if( !I_go_ahead_always ) {
					// The following blocks until getting the go-ahead
					// (e.g.  from the local schedd) to receive the
					// file.  It then sends a message to our peer
					// telling it to go ahead.
				if( !ObtainAndSendTransferGoAhead(xfer_queue,true,s,sandbox_size,fullname.Value(),I_go_ahead_always) ) {
					dprintf(D_FULLDEBUG,"DoDownload: exiting at %d\n",__LINE__);
					return_and_resetpriv( -1 );
				}
			}

				// We have given permission to peer to go ahead
				// with transfer.  Now do the reverse: wait for
				// peer to tell is that it is ready to send.
			if( !peer_goes_ahead_always ) {

				if( !ReceiveTransferGoAhead(s,fullname.Value(),true,peer_goes_ahead_always,peer_max_transfer_bytes) ) {
					dprintf(D_FULLDEBUG, "DoDownload: exiting at %d\n",__LINE__);
					return_and_resetpriv( -1 );
				}
			}

			s->decode();
		}

		UpdateXferStatus(XFER_STATUS_ACTIVE);

		filesize_t this_file_max_bytes = -1;
		filesize_t max_bytes_slack = 65535;
		if( MaxDownloadBytes < 0 ) {
			this_file_max_bytes = -1; // no limit
		}
		else if( MaxDownloadBytes + max_bytes_slack >= *total_bytes ) {

				// We have told the sender our limit, and a
				// well-behaved sender will not send more than that.
				// We give the sender a little slack, because there
				// may be minor differences in how the sender and
				// receiver account for the size of some things (like
				// proxies and what-not).  It is best if the sender
				// reaches the limit first, because that path has
				// better error handling.  If instead the receiver
				// hits its limit first, the connection is closed, and
				// the sender will not understand why.

			this_file_max_bytes = MaxDownloadBytes + max_bytes_slack - *total_bytes;
		}
		else {
			this_file_max_bytes = 0;
		}


		// On WinNT and apparently, some Unix, too, even doing an
		// fsync on the file does not get rid of the lazy-write
		// behavior which in the modification time being set a few
		// seconds into the future.  Instead of sleeping for 30+
		// seconds here in the starter & thus delaying the start of
		// the job, we call _utime to manually set the modification
		// time of the file we just wrote backwards in time by a few
		// minutes!  MLOP!! Since we are doing this, we may as well
		// not bother to fsync every file.
//		dprintf(D_FULLDEBUG,"TODD filetransfer DoDownload fullname=%s\n",fullname.Value());
		start = time(NULL);
		
		// Setup the FileTransferStats object for this file, which we'll use
		// to gather per-transfer statistics (different from the other
		// statistics gathering which only tracks cumulative totals)
		FileTransferStats thisFileStats;
		thisFileStats.TransferFileBytes = 0;
		thisFileStats.TransferFileName = filename.Value();
		thisFileStats.TransferProtocol = "cedar";
		thisFileStats.TransferStartTime = condor_gettimestamp_double();
		thisFileStats.TransferType = "download";

		// Create a ClassAd we'll use to store stats from a file transfer
		// plugin, if we end up using one.
		ClassAd pluginStatsAd;

		// Until we are told otherwise, assume this file transfer will not be
		// deferred until the end of the loop.
		isDeferredTransfer = false;

		if (xfer_command == TransferCommand::Other) {
			// filename already received:
			// .  verify that it is the same as FileName attribute in following classad
			// .  optimization: could be the version protocol instead
			//
			// receive the classad
			ClassAd file_info;
			if (!getClassAd(s, file_info)) {
				dprintf(D_FULLDEBUG,"DoDownload: exiting at %d\n",__LINE__);
				return_and_resetpriv( -1 );
			}

				
			// examine subcommand
			//
			TransferSubCommand subcommand;
			{
				int subcommand_int;
				if (!file_info.LookupInteger("SubCommand", subcommand_int)) {
					subcommand = TransferSubCommand::Unknown;
				} else {
					subcommand = static_cast<TransferSubCommand>(subcommand_int);
				}
			}

			// perform specified subcommand
			//
			// (this can be made a switch statement when more show up)
			//

			if(subcommand == TransferSubCommand::UploadUrl) {
				// 7 == send local file using plugin
				
				std::string rt_src;
				std::string rt_dst;
				std::string rt_err;
				int      rt_result = 0;
				if(!file_info.LookupInteger("Result",rt_result)) {
					rt_result = -1;
				}

				if(!file_info.LookupString("Filename", rt_src)) {
					rt_src = "<null>";
				}

				if(!file_info.LookupString("OutputDestination", rt_dst)) {
					rt_dst = "<null>";
				}

				if(!file_info.LookupString("ErrorString", rt_err)) {
					rt_err = "<null>";
				}

				// TODO: write to job log success/failure for each file (as a custom event?)
				dprintf(D_ALWAYS, "DoDownload: other side transferred %s to %s and got result %i\n",
						rt_src.c_str(), rt_dst.c_str(), rt_result );

				if(rt_result == 0) {
					rc = 0;
				} else {
					// handle the error now and bypass error handling
					// that hapens further down
					rc = 0; 

					error_buf.formatstr(
						"%s at %s failed due to remote transfer hook error: %s",
						get_mySubSystem()->getName(),
						s->my_ip_str(),fullname.Value());
					download_success = false;
					try_again = false;
					hold_code = CONDOR_HOLD_CODE_DownloadFileError;
					hold_subcode = rt_result;

					dprintf(D_ALWAYS,
						"DoDownload: consuming rest of transfer and failing "
						"after encountering the following error: %s\n",
						error_buf.Value());
				}
			} else if (subcommand == TransferSubCommand::ReuseInfo) {
					// We must consume the EOM in order to send the ClassAd later.
				if (!s->end_of_message()) {
					dprintf(D_FULLDEBUG,"DoDownload: exiting at %d\n",__LINE__);
				}
				ClassAd ad;
				if (m_reuse_dir == nullptr) {
					dprintf(D_FULLDEBUG, "DoDownload: No data reuse directory available; ignoring potential reuse info.\n");
					ad.InsertAttr("Result", 1);
					rc = 0;
				} else {
					classad::Value value;
					std::string tag;
					if (!file_info.EvaluateAttr("ReuseList", value) ||
						(value.GetType() != classad::Value::SLIST_VALUE &&
						value.GetType() != classad::Value::LIST_VALUE) ||
						!file_info.EvaluateAttrString("Tag", tag))
					{
						dprintf(D_FULLDEBUG, "The reuse info ClassAd is missing attributes.\n");
						dPrintAd(D_FULLDEBUG, file_info);
						rc = 0;
					} else {
						classad_shared_ptr<classad::ExprList> exprlist;
						value.IsSListValue(exprlist);
						std::vector<std::string> retrieved_files;
						for (auto &list_entry : (*exprlist)) {
							classad::Value file_ad_value;
							if (!list_entry->Evaluate(file_ad_value)) {
								dprintf(D_FULLDEBUG, "Failed to evaluate list entry.\n");
								continue;
							}
							classad_shared_ptr<classad::ClassAd> file_ad;
							if (!file_ad_value.IsSClassAdValue(file_ad)) {
								dprintf(D_FULLDEBUG, "Failed to evaluate list entry to ClassAd.\n");
								continue;
							}
							std::string filename;
							if (!file_ad->EvaluateAttrString("FileName", filename)) {
								dprintf(D_FULLDEBUG, "List entry is missing FileName attr.\n");
								continue;
							}
							std::string checksum_type;
							if (!file_ad->EvaluateAttrString("ChecksumType", checksum_type)) {
								dprintf(D_FULLDEBUG, "List entry is missing ChecksumType attr.\n");
								continue;
							}
							std::string checksum;
							if (!file_ad->EvaluateAttrString("Checksum", checksum)) {
								dprintf(D_FULLDEBUG, "List entry is missing Checksum attr.\n");
								continue;
							}
							long long size;
							if (!file_ad->EvaluateAttrInt("Size", size)) {
								dprintf(D_FULLDEBUG, "List entry is missing Size attr.\n");
								continue;
							}
							std::string dest_fname = std::string(Iwd) + DIR_DELIM_CHAR + filename;
							CondorError err;
							if (!m_reuse_dir->RetrieveFile(dest_fname, checksum, checksum_type, tag,
								err))
							{
								dprintf(D_FULLDEBUG, "Failed to retrieve file from data"
									" reuse directory: %s\n", err.getFullText().c_str());
								reuse_info.emplace_back(filename, checksum, checksum_type,
									tag, size);
								continue;
							}
							dprintf(D_FULLDEBUG, "Successfully retrieved %s from data reuse directory into job sandbox.\n", filename.c_str());
							retrieved_files.push_back(filename);
						}
						std::unique_ptr<classad::ExprList> retrieved_list(new classad::ExprList());
						for (const auto &file : retrieved_files) {
							classad::ExprTree *expr = classad::Literal::MakeString(file);
							retrieved_list->push_back(expr);
						}
						uint64_t to_retrieve = std::accumulate(reuse_info.begin(), reuse_info.end(),
							0, [](uint64_t val, ReuseInfo &info) {return info.size() + val;});
						dprintf(D_FULLDEBUG, "There are %lu bytes to retrieve.\n", to_retrieve);
						if (to_retrieve) {
							CondorError err;
							if (!m_reuse_dir->ReserveSpace(to_retrieve, 3600, tag, reservation_id,
								err))
							{
								dprintf(D_FULLDEBUG, "Failed to reserve space for data reuse:"
									" %s\n", err.getFullText().c_str());
								retrieved_files.clear();
								reuse_info.clear();
							}
						}
						ad.Insert("ReuseList", retrieved_list.release());
						rc = 0;
					}
				}
				s->encode();
				if (!putClassAd(s, ad) || !s->end_of_message()) {
					dprintf(D_FULLDEBUG,"DoDownload: exiting at %d\n",__LINE__);
					return_and_resetpriv( -1 );
				}
				s->decode();
				continue;
			} else if (subcommand == TransferSubCommand::SignUrls) {
				dprintf(D_FULLDEBUG, "DoDownload: Received request to sign URLs.\n");
					// We must consume the EOM in order to send the ClassAd later.
				if (!s->end_of_message()) {
					dprintf(D_FULLDEBUG, "DoDownload: exiting at %d\n",__LINE__);
					return_and_resetpriv( -1 );
				}
				ClassAd result_ad;
				classad::Value value;
				if (!file_info.EvaluateAttr("SignList", value) ||
					(value.GetType() != classad::Value::SLIST_VALUE &&
					value.GetType() != classad::Value::LIST_VALUE))
				{
					dprintf(D_FULLDEBUG, "DoDownload: The signing URL list info in ClassAd is missing.\n");
					dPrintAd(D_FULLDEBUG, file_info);
					rc = 0;
				} else {
					classad_shared_ptr<classad::ExprList> exprlist;
					value.IsSListValue(exprlist);
					std::vector<std::string> signed_urls;
					for (auto list_entry : (*exprlist)) {
						std::string url_value;
						classad::Value value;
						if (!list_entry->Evaluate(value)) {
							dprintf(D_FULLDEBUG, "DoDownload: Failed to evaluate list entry.\n");
							signed_urls.push_back("");
						}
						else if (!value.IsStringValue(url_value))
						{
							dprintf(D_FULLDEBUG, "DoDownload: Failed to evaluate list entry to string.\n");
							signed_urls.push_back("");
						}
						else if (sign_s3_urls && url_value.substr(0, 5) == "s3://")
						{
							bool has_good_prefix = false;
							for (const auto &prefix : output_url_prefixes) {
								if (url_value.substr(0, prefix.size()) == prefix) {
									has_good_prefix = true;
									break;
								}
							}
								// We don't deal with normalization correctly -- avoid
								// any URL that has ".." in it.
							if (url_value.find("/..") != std::string::npos) {
								has_good_prefix = false;
							}
							if (has_good_prefix) {
								dprintf(D_FULLDEBUG, "DoDownload: URL will be signed: %s.\n", url_value.c_str());
								std::string signed_url;
								CondorError err;
								if (!htcondor::generate_presigned_url(jobAd, url_value, "PUT", signed_url, err)) {
									dprintf(D_ALWAYS, "DoDownload: Failure when signing URL: %s", err.getFullText().c_str());
									signed_urls.push_back("");
								} else {
									signed_urls.push_back(signed_url);
								}
							} else {
								dprintf(D_FULLDEBUG, "DoDownload: URL has invalid prefix: %s.\n", url_value.c_str());
								signed_urls.push_back("");
							}
						}
						else
						{
							signed_urls.push_back(url_value);
						}
					}
					classad::ExprList url_list;
					for (const auto &url : signed_urls) {
						auto expr = classad::Literal::MakeString(url);
						url_list.push_back(expr);
					}
					result_ad.Insert("SignList", url_list.Copy());
					rc = 0;
				}
				s->encode();
					// Send resulting list of signed URLs, encrypted if possible.
				classad::References encrypted_attrs{"SignList"};
				if (!putClassAd(s, result_ad, 0, &encrypted_attrs) || !s->end_of_message()) {
					dprintf(D_FULLDEBUG,"DoDownload: exiting at %d\n",__LINE__);
					return_and_resetpriv( -1 );
				}
				s->decode();
				continue;
			} else {
				// unrecongized subcommand
				dprintf(D_ALWAYS, "FILETRANSFER: unrecognized subcommand %i! skipping!\n", static_cast<int>(subcommand));
				dPrintAd(D_FULLDEBUG, file_info);
				
				rc = 0;
			}
		} else if (xfer_command == TransferCommand::DownloadUrl) {
			// new filetransfer command.  5 means that the next file is a
			// 3rd party transfer.  cedar will not send the file itself,
			// and instead will send the URL over the wire.  the receiving
			// side must then retreive the URL using one of the configured
			// filetransfer plugins.

			MyString URL;
			// receive the URL from the wire

			if (!s->code(URL)) {
				dprintf(D_FULLDEBUG,"DoDownload: exiting at %d\n",__LINE__);
				return_and_resetpriv( -1 );
			}

			if( multifile_plugins_enabled ) {
				
				// Determine which plugin to invoke, and whether it supports multiple
				// file transfer.
				MyString pluginPath = DetermineFileTransferPlugin( errstack, URL.Value(), fullname.Value() );
				bool thisPluginSupportsMultifile = false;
				if( plugins_multifile_support.find( pluginPath ) != plugins_multifile_support.end() ) {
					thisPluginSupportsMultifile = plugins_multifile_support[pluginPath];
				}

				if( thisPluginSupportsMultifile ) {
					// Do not send the file right now! 
					// Instead, add it to a deferred list, which we'll deal with 
					// after the main download loop.
					dprintf( D_FULLDEBUG, "DoDownload: deferring transfer of URL %s "
						" until end of download loop.\n", URL.Value() );
					thisTransfer->Clear();
					thisTransfer->InsertAttr( "Url", URL );
					thisTransfer->InsertAttr( "LocalFileName", fullname );
					std::string thisTransferString;
					unparser.Unparse( thisTransferString, thisTransfer.get() );

					// Add this result to our deferred transfers map.
					if ( deferredTransfers.find( pluginPath ) == deferredTransfers.end() ) {
						deferredTransfers.insert( std::pair<std::string, std::string>( pluginPath, thisTransferString ) );
					} 
					else {
						deferredTransfers[pluginPath] += thisTransferString;
					}

					isDeferredTransfer = true;
				}
			}

			if( !isDeferredTransfer ) {
				dprintf( D_FULLDEBUG, "DoDownload: doing a URL transfer: (%s) to (%s)\n", URL.Value(), fullname.Value());
				rc = InvokeFileTransferPlugin(errstack, URL.Value(), fullname.Value(), &pluginStatsAd, LocalProxyName.Value());
				CondorError err;
				if (rc == 0 && should_reuse && !m_reuse_dir->CacheFile(fullname.Value(), iter->checksum(),
					iter->checksum_type(), reservation_id, err))
				{
					dprintf(D_FULLDEBUG, "Failed to save file %s for reuse: %s\n", fullname.Value(),
					err.getFullText().c_str());
				}
			}

		} else if ( xfer_command == TransferCommand::XferX509 ) {
			if ( PeerDoesGoAhead || s->end_of_message() ) {
				rc = (s->get_x509_delegation( fullname.Value(), false, NULL ) == ReliSock::delegation_ok) ? 0 : -1;
				dprintf( D_FULLDEBUG,
				         "DoDownload: get_x509_delegation() returned %d\n",
				         rc );
				if (rc == 0) {
					// ZKM FUTURE TODO: allow this to exist outside of the job sandbox -- we may
					// need the proxy to create the sandbox itself (if execute dir is NFSv4) but
					// that will require some higher-level refactoring
					LocalProxyName = fullname;
				}
			} else {
				rc = -1;
			}
			delegation_method = 1;/* This is a delegation, unseuccessful or not */
		} else if( xfer_command == TransferCommand::Mkdir ) { // mkdir
			condor_mode_t file_mode = NULL_FILE_PERMISSIONS;
			if( !s->code(file_mode) ) {
				rc = -1;
				dprintf(D_ALWAYS,"DoDownload: failed to read mkdir mode.\n");
			}
			else {
				if (file_mode == NULL_FILE_PERMISSIONS) {
					// Don't create subdirectories with mode 0000!
					// If file_mode is still NULL_FILE_PERMISSIONS here, it
					// likely means that our peer is likely a Windows machine,
					// since Windows will always claim a mode of 0000.
					// In this case, default to mode 0700, which is a
					// conservative default, and matches what we do in
					// ReliSock::get_file().
					file_mode = (condor_mode_t) 0700;
				}
				mode_t old_umask = umask(0);
				rc = mkdir(fullname.Value(),(mode_t)file_mode);
				umask(old_umask);
				if( rc == -1 && errno == EEXIST ) {
						// The directory name already exists.  If it is a
						// directory, just leave it alone, because the
						// user may want us to append files to an
						// existing output directory.  Otherwise, try
						// to remove it and try again.
					StatInfo st( fullname.Value() );
					if( !st.Error() && st.IsDirectory() ) {
						dprintf(D_FULLDEBUG,"Requested to create directory but using existing one: %s\n",fullname.Value());
						rc = 0;
					}
					else if( !strcmp(fullname.Value(),NULL_FILE) ) {
							// we are just fast-forwarding through the
							// download, so just ignore this request
						rc = 0;
					}
					else {
						IGNORE_RETURN remove(fullname.Value());
						old_umask = umask(0);
						rc = mkdir(fullname.Value(),(mode_t)file_mode);
						umask(old_umask);
					}
				}
				if( rc == -1 ) {
					// handle the error now and bypass error handling
					// that hapens further down
					rc = 0; 

					int the_error = errno;
					error_buf.formatstr(
						"%s at %s failed to create directory %s: %s (errno %d)",
						get_mySubSystem()->getName(),
						s->my_ip_str(),fullname.Value(),
						strerror(the_error),the_error);
					download_success = false;
					try_again = false;
					hold_code = CONDOR_HOLD_CODE_DownloadFileError;
					hold_subcode = the_error;

					dprintf(D_ALWAYS,
						"DoDownload: consuming rest of transfer and failing "
						"after encountering the following error: %s\n",
						error_buf.Value());
				}
			}
		} else if ( TransferFilePermissions ) {
			rc = s->get_file_with_permissions( &bytes, fullname.Value(), false, this_file_max_bytes, &xfer_queue );
			CondorError err;
			if (rc == 0 && should_reuse && !m_reuse_dir->CacheFile(fullname.Value(), iter->checksum(),
					iter->checksum_type(), reservation_id, err))
			{
				dprintf(D_FULLDEBUG, "Failed to save file %s for reuse: %s\n", fullname.Value(),
					err.getFullText().c_str());
			}
		} else {
			rc = s->get_file( &bytes, fullname.Value(), false, false, this_file_max_bytes, &xfer_queue );
		}

		elapsed = time(NULL)-start;
		thisFileStats.TransferEndTime = condor_gettimestamp_double();
		thisFileStats.ConnectionTimeSeconds = thisFileStats.TransferEndTime - thisFileStats.TransferStartTime;

		if( rc < 0 ) {
			int the_error = errno;
			error_buf.formatstr("%s at %s failed to receive file %s",
			                  get_mySubSystem()->getName(),
							  s->my_ip_str(),fullname.Value());
			download_success = false;
			if(rc == GET_FILE_OPEN_FAILED || rc == GET_FILE_WRITE_FAILED ||
					rc == GET_FILE_PLUGIN_FAILED) {
				// errno is well defined in this case, and transferred data
				// has been consumed so that the wire protocol is in a well
				// defined state

				if (rc == GET_FILE_PLUGIN_FAILED) {
					error_buf.formatstr_cat(": %s", errstack.getFullText().c_str());
				} else {
					error_buf.replaceString("receive","write to");
					error_buf.formatstr_cat(": (errno %d) %s",the_error,strerror(the_error));
				}

				// Since there is a well-defined errno describing what just
				// went wrong while trying to open the file, put the job
				// on hold.  Errors that are deemed to be transient can
				// be periodically released from hold.

				try_again = false;
				hold_code = CONDOR_HOLD_CODE_DownloadFileError;
				hold_subcode = the_error;

				dprintf(D_ALWAYS,
						"DoDownload: consuming rest of transfer and failing "
						"after encountering the following error: %s\n",
						error_buf.Value());
			}
			else {
				// Assume we had some transient problem (e.g. network timeout)
				// In the current implementation of get_file(), errno is not
				// well defined in this case, so we can't report a specific
				// error message.
				try_again = true;
				hold_code = CONDOR_HOLD_CODE_DownloadFileError;
				hold_subcode = the_error;

				if( rc == GET_FILE_MAX_BYTES_EXCEEDED ) {
					try_again = false;
					error_buf.formatstr_cat(": max total download bytes exceeded (max=%ld MB)",
											(long int)(MaxDownloadBytes/1024/1024));
					hold_code = CONDOR_HOLD_CODE_MaxTransferOutputSizeExceeded;
					hold_subcode = 0;
				}

				dprintf(D_ALWAYS,"DoDownload: %s\n",error_buf.Value());

					// The wire protocol is not in a well defined state
					// at this point.  Try sending the ack message indicating
					// what went wrong, for what it is worth.
				SendTransferAck(s,download_success,try_again,hold_code,hold_subcode,error_buf.Value());

				dprintf(D_FULLDEBUG,"DoDownload: exiting at %d\n",__LINE__);
				return_and_resetpriv( -1 );
			}
		}

		if ( ExecFile && !file_strcmp( condor_basename( ExecFile ), filename.Value() ) ) {
				// We're receiving the executable, make sure execute
				// bit is set
				// TODO How should we modify the permisions of the
				//   executable? Adding any group or world permissions
				//   seems wrong. For now, behave the same way as the
				//   starter.
#if 0
			struct stat stat_buf;
			if ( stat( fullname.Value(), &stat_buf ) < 0 ) {
				dprintf( D_ALWAYS, "Failed to stat executable %s, errno=%d (%s)\n",
						 fullname.Value(), errno, strerror(errno) );
			} else if ( ! (stat_buf.st_mode & S_IXUSR) ) {
				stat_buf.st_mode |= S_IXUSR;
				if ( chmod( fullname.Value(), stat_buf.st_mode ) < 0 ) {
					dprintf( D_ALWAYS, "Failed to set execute bit on %s, errno=%d (%s)\n",
							 fullname.Value(), errno, strerror(errno) );
				}
			}
#else
			if ( chmod( fullname.Value(), 0755 ) < 0 ) {
				dprintf( D_ALWAYS, "Failed to set execute bit on %s, errno=%d (%s)\n",
						 fullname.Value(), errno, strerror(errno) );
			}
#endif
		}

		if ( want_fsync ) {
			struct utimbuf timewrap;

			time_t current_time = time(NULL);
			timewrap.actime = current_time;		// set access time to now
			timewrap.modtime = current_time;	// set modify time to now

			utime(fullname.Value(),&timewrap);
		}

		if( !s->end_of_message() ) {
			return_and_resetpriv( -1 );
		}
		*total_bytes += bytes;
		thisFileStats.TransferFileBytes += bytes;
		thisFileStats.TransferTotalBytes += bytes;
		bytes = 0;

		numFiles++;

		// Gather a few more statistics
		thisFileStats.TransferSuccess = download_success;

		// Merge the file transfer stats we recorded here with the stats 
		// retrieved from a plugin. If we didn't use a file transfer plugin 
		// this time, this ClassAd will just be empty.
		ClassAd thisFileStatsAd;
		thisFileStats.Publish(thisFileStatsAd);
		thisFileStatsAd.Update(pluginStatsAd);

		// Write stats to disk
		if( !isDeferredTransfer ) {
			OutputFileTransferStats(thisFileStatsAd);
		}

		// Get rid of compiler set-but-not-used warnings on Linux
		// Hopefully the compiler can just prune out the emitted code.
		if (delegation_method) {}
		if (elapsed) {}
	}
	// End of the main download loop

        // Release transfer queue slot after file has been put but before the
        // final transfer ACKs are done.  In the future where multifile transfers
        // plugins are used in DoDownload, this would allow DoDownload side to
        // perform external plugin-based transfers without the queue slot
        //
	xfer_queue.ReleaseTransferQueueSlot();

	// Now that we've completed the main file transfer loop, it's time to 
	// transfer all files that needed a third party plugin. Iterate over the list
	// of deferred transfers, and invoke each set with the appopriate plugin.
	if ( hold_code == 0 ) {
		for ( auto it = deferredTransfers.begin(); it != deferredTransfers.end(); ++ it ) {
			rc = InvokeMultipleFileTransferPlugin( errstack, it->first, it->second, 
				LocalProxyName.Value(), false, nullptr );
			if (rc == 0) {
				/*  TODO: handle deferred files.  We may need to unparse the deferredTransfers files. */
			} else {
				dprintf( D_ALWAYS, "FILETRANSFER: Multiple file download failed: %s\n",
					errstack.getFullText().c_str() );
				download_success = false;
				hold_code = CONDOR_HOLD_CODE_DownloadFileError;
				hold_subcode = rc;
				try_again = false;
				error_buf.formatstr( "%s", errstack.getFullText().c_str() );
			}
		}
	}

	// go back to the state we were in before file transfer
	s->set_crypto_mode(socket_default_crypto);

	bytesRcvd += (*total_bytes);

	// Receive final report from the sender to make sure all went well.
	bool upload_success = false;
	MyString upload_error_buf;
	bool upload_try_again = true;
	int upload_hold_code = 0;
	int upload_hold_subcode = 0;
	GetTransferAck(s,upload_success,upload_try_again,upload_hold_code,
				   upload_hold_subcode,upload_error_buf);
	if(!upload_success) {
		// Our peer had some kind of problem sending the files.

		char const *peer_ip_str = "disconnected socket";
		if(s->type() == Stream::reli_sock) {
			peer_ip_str = ((Sock *)s)->get_sinful_peer();
		}

		MyString download_error_buf;
		download_error_buf.formatstr("%s failed to receive file(s) from %s",
						  get_mySubSystem()->getName(),peer_ip_str);
		error_buf.formatstr("%s; %s",
						  upload_error_buf.Value(),
						  download_error_buf.Value());
		dprintf(D_ALWAYS,"DoDownload: %s\n",error_buf.Value());

		download_success = false;
		SendTransferAck(s,download_success,upload_try_again,upload_hold_code,
						upload_hold_subcode,download_error_buf.Value());

			// store full-duplex error description, because only our side
			// of the story was stored in above call to SendTransferAck
		Info.error_desc = error_buf.Value();

		dprintf( D_FULLDEBUG, "DoDownload: exiting with upload errors\n" );
		return_and_resetpriv( -1 );
	}

	if( !download_success ) {
		SendTransferAck(s,download_success,try_again,hold_code,
						hold_subcode,error_buf.Value());

		dprintf( D_FULLDEBUG, "DoDownload: exiting with download errors\n" );
		return_and_resetpriv( -1 );
	}

	if ( !final_transfer && IsServer() ) {
		MyString buf;
		int fd;
		// we just stashed all the files in the TmpSpoolSpace.
		// write out the commit file.

		buf.formatstr("%s%c%s",TmpSpoolSpace,DIR_DELIM_CHAR,COMMIT_FILENAME);
#if defined(WIN32)
		if ((fd = safe_open_wrapper_follow(buf.Value(), O_WRONLY | O_CREAT | O_TRUNC | 
			_O_BINARY | _O_SEQUENTIAL, 0644)) < 0)
#else
		if ((fd = safe_open_wrapper_follow(buf.Value(), O_WRONLY | O_CREAT | O_TRUNC, 0644)) < 0)
#endif
		{
			dprintf(D_ALWAYS, 
				"FileTransfer::DoDownload failed to write commit file\n");
			return_and_resetpriv( -1 );
		}

		// copy in list of files to remove here
		::close(fd);

		// Now actually perform the commit.
		CommitFiles();

	}

	downloadEndTime = condor_gettimestamp_double();

	download_success = true;
	SendTransferAck(s,download_success,try_again,hold_code,hold_subcode,NULL);

		// Log some tcp statistics about this transfer
	if (*total_bytes > 0) {
		char *stats = s->get_statistics();
		int cluster = -1;
		int proc = -1;
		jobAd.LookupInteger(ATTR_CLUSTER_ID, cluster);
		jobAd.LookupInteger(ATTR_PROC_ID, proc);

		std::string full_stats;
		formatstr(full_stats, "File Transfer Download: JobId: %d.%d files: %d bytes: %lld seconds: %.2f dest: %s %s\n", 
			cluster, proc, numFiles, (long long)*total_bytes, (downloadEndTime - downloadStartTime), s->peer_ip_str(), (stats ? stats : ""));
		Info.tcp_stats = full_stats.c_str();
		dprintf(D_STATS, "%s", full_stats.c_str());
	}


	return_and_resetpriv( 0 );
}

void
FileTransfer::GetTransferAck(Stream *s,bool &success,bool &try_again,int &hold_code,int &hold_subcode,MyString &error_desc)
{
	if(!PeerDoesTransferAck) {
		success = true;
		return;
	}

	s->decode();

	ClassAd ad;
	if(!getClassAd(s, ad) || !s->end_of_message()) {
		char const *ip = NULL;
		if(s->type() == Sock::reli_sock) {
			ip = ((ReliSock *)s)->get_sinful_peer();
		}
		dprintf(D_FULLDEBUG,"Failed to receive download acknowledgment from %s.\n",
				ip ? ip : "(disconnected socket)");
		success = false;
		try_again = true; // could just be a transient network problem
		return;
	}
	int result = -1;
	if(!ad.LookupInteger(ATTR_RESULT,result)) {
		MyString ad_str;
		sPrintAd(ad_str, ad);
		dprintf(D_ALWAYS,"Download acknowledgment missing attribute: %s.  Full classad: [\n%s]\n",ATTR_RESULT,ad_str.Value());
		success = false;
		try_again = false;
		hold_code = CONDOR_HOLD_CODE_InvalidTransferAck;
		hold_subcode = 0;
		error_desc.formatstr("Download acknowledgment missing attribute: %s",ATTR_RESULT);
		return;
	}
	if(result == 0) {
		success = true;
		try_again = false;
	}
	else if(result > 0) {
		success = false;
		try_again = true;
	}
	else {
		success = false;
		try_again = false;
	}

	if(!ad.LookupInteger(ATTR_HOLD_REASON_CODE,hold_code)) {
		hold_code = 0;
	}
	if(!ad.LookupInteger(ATTR_HOLD_REASON_SUBCODE,hold_subcode)) {
		hold_subcode = 0;
	}
	char *hold_reason_buf = NULL;
	if(ad.LookupString(ATTR_HOLD_REASON,&hold_reason_buf)) {
		error_desc = hold_reason_buf;
		free(hold_reason_buf);
	}
}

void
FileTransfer::SaveTransferInfo(bool success,bool try_again,int hold_code,int hold_subcode,char const *hold_reason)
{
	Info.success = success;
	Info.try_again = try_again;
	Info.hold_code = hold_code;
	Info.hold_subcode = hold_subcode;
	if( hold_reason ) {
		Info.error_desc = hold_reason;
	}
}

void
FileTransfer::SendTransferAck(Stream *s,bool success,bool try_again,int hold_code,int hold_subcode,char const *hold_reason)
{
	// Save failure information.
	SaveTransferInfo(success,try_again,hold_code,hold_subcode,hold_reason);

	if(!PeerDoesTransferAck) {
		dprintf(D_FULLDEBUG,"SendTransferAck: skipping transfer ack, because peer does not support it.\n");
		return;
	}

	ClassAd ad;
	int result;
	if(success) {
		result = 0;
	}
	else if(try_again) {
		result = 1;  //failed for transient reasons
	}
	else {
		result = -1; //failed -- do not try again (ie put on hold)
	}

	ad.Assign(ATTR_RESULT,result);
	if(!success) {
		ad.Assign(ATTR_HOLD_REASON_CODE,hold_code);
		ad.Assign(ATTR_HOLD_REASON_SUBCODE,hold_subcode);
		if(hold_reason) {
			ad.Assign(ATTR_HOLD_REASON,hold_reason);
		}
	}
	s->encode();
	if(!putClassAd(s, ad) || !s->end_of_message()) {
		char const *ip = NULL;
		if(s->type() == Sock::reli_sock) {
			ip = ((ReliSock *)s)->get_sinful_peer();
		}
		dprintf(D_ALWAYS,"Failed to send download %s to %s.\n",
		        success ? "acknowledgment" : "failure report",
		        ip ? ip : "(disconnected socket)");
	}
}

void
FileTransfer::CommitFiles()
{
	MyString buf;
	MyString newbuf;
	MyString swapbuf;
	const char *file;

	if ( IsClient() ) {
		return;
	}

	int cluster = -1;
	int proc = -1;
	jobAd.LookupInteger(ATTR_CLUSTER_ID, cluster);
	jobAd.LookupInteger(ATTR_PROC_ID, proc);

	priv_state saved_priv = PRIV_UNKNOWN;
	if( want_priv_change ) {
		saved_priv = set_priv( desired_priv_state );
	}

	Directory tmpspool( TmpSpoolSpace, desired_priv_state );

	buf.formatstr("%s%c%s",TmpSpoolSpace,DIR_DELIM_CHAR,COMMIT_FILENAME);
	if ( access(buf.Value(),F_OK) >= 0 ) {
		// the commit file exists, so commit the files.

		MyString SwapSpoolSpace;
		SwapSpoolSpace.formatstr("%s.swap",SpoolSpace);
		bool swap_dir_ready = SpooledJobFiles::createJobSwapSpoolDirectory(&jobAd,desired_priv_state);
		if( !swap_dir_ready ) {
			EXCEPT("Failed to create %s",SwapSpoolSpace.Value());
		}

		while ( (file=tmpspool.Next()) ) {
			// don't commit the commit file!
			if ( file_strcmp(file,COMMIT_FILENAME) == MATCH )
				continue;
			buf.formatstr("%s%c%s",TmpSpoolSpace,DIR_DELIM_CHAR,file);
			newbuf.formatstr("%s%c%s",SpoolSpace,DIR_DELIM_CHAR,file);
			swapbuf.formatstr("%s%c%s",SwapSpoolSpace.Value(),DIR_DELIM_CHAR,file);

				// If the target name exists, move it into the swap
				// directory.  This serves two purposes:
				//   1. potentially allow rollback
				//   2. handle case of target being a non-empty directory,
				//      which cannot be overwritten by rename()
			if( access(newbuf.Value(),F_OK) >= 0 ) {
				if ( rename(newbuf.Value(),swapbuf.Value()) < 0 ) {
					EXCEPT("FileTransfer CommitFiles failed to move %s to %s: %s",newbuf.Value(),swapbuf.Value(),strerror(errno));
				}
			}

			if ( rotate_file(buf.Value(),newbuf.Value()) < 0 ) {
				EXCEPT("FileTransfer CommitFiles Failed -- What Now?!?!");
			}
		}
		// TODO: remove files specified in commit file

		SpooledJobFiles::removeJobSwapSpoolDirectory(&jobAd);
	}

	// We have now commited the files in tmpspool, if we were supposed to.
	// So now blow away tmpspool.
	tmpspool.Remove_Entire_Directory();
	if( want_priv_change ) {
		ASSERT( saved_priv != PRIV_UNKNOWN );
		set_priv( saved_priv );
	}
}

int
FileTransfer::Upload(ReliSock *s, bool blocking)
{
	dprintf(D_FULLDEBUG,"entering FileTransfer::Upload\n");

	if (ActiveTransferTid >= 0) {
		EXCEPT("FileTransfer::Upload called during active transfer!");
	}

	Info.duration = 0;
	Info.type = UploadFilesType;
	Info.success = true;
	Info.in_progress = true;
	Info.xfer_status = XFER_STATUS_UNKNOWN;
	TransferStart = time(NULL);

	if (blocking) {
		int status = DoUpload( &Info.bytes, (ReliSock *)s);
		Info.duration = time(NULL)-TransferStart;
		Info.success = (Info.bytes >= 0) && (status == 0);
		Info.in_progress = false;
		return Info.success;

	} else {

		ASSERT( daemonCore );

		// make a pipe to communicate with our thread
		if (!daemonCore->Create_Pipe(TransferPipe,true)) {
			dprintf(D_ALWAYS, "Create_Pipe failed in "
					"FileTransfer::Upload\n");
			return FALSE;
		}

		if (-1 == daemonCore->Register_Pipe(TransferPipe[0],
											"Upload Results",
											(PipeHandlercpp)&FileTransfer::TransferPipeHandler,
											"TransferPipeHandler",
											this)) {
			dprintf(D_ALWAYS,"FileTransfer::Upload() failed to register pipe.\n");
			return FALSE;
		}
		else {
			registered_xfer_pipe = true;
		}

		upload_info *info = (upload_info *)malloc(sizeof(upload_info));
		ASSERT( info );
		info->myobj = this;
		ActiveTransferTid = daemonCore->
			Create_Thread((ThreadStartFunc)&FileTransfer::UploadThread,
						  (void *)info, s, ReaperId);
		if (ActiveTransferTid == FALSE) {
			dprintf(D_ALWAYS, "Failed to create FileTransfer UploadThread!\n");
			free(info);
			ActiveTransferTid = -1;
			return FALSE;
		}
		dprintf(D_FULLDEBUG,
				"FileTransfer: created upload transfer process with id %d\n",
				ActiveTransferTid);
		// daemonCore will free(info) when the thread exits
		TransThreadTable->insert(ActiveTransferTid, this);

		uploadStartTime = time(NULL);
	}
		
	return 1;
}

bool
FileTransfer::WriteStatusToTransferPipe(filesize_t total_bytes)
{
	int n;
	bool write_failed = false;

	if(!write_failed) {
		char cmd = FINAL_UPDATE_XFER_PIPE_CMD;

		n = daemonCore->Write_Pipe( TransferPipe[1],
									&cmd,
									sizeof(cmd) );
		if(n != sizeof(cmd)) write_failed = true;
	}

	if(!write_failed) {
		n = daemonCore->Write_Pipe( TransferPipe[1],
				   (char *)&total_bytes,
				   sizeof(filesize_t) );
		if(n != sizeof(filesize_t)) write_failed = true;
	}
	if(!write_failed) {
		n = daemonCore->Write_Pipe( TransferPipe[1],
				   (char *)&Info.try_again,
				   sizeof(bool) );
		if(n != sizeof(bool)) write_failed = true;
	}
	if(!write_failed) {
		n = daemonCore->Write_Pipe( TransferPipe[1],
				   (char *)&Info.hold_code,
				   sizeof(int) );
		if(n != sizeof(int)) write_failed = true;
	}
	if(!write_failed) {
		n = daemonCore->Write_Pipe( TransferPipe[1],
				   (char *)&Info.hold_subcode,
				   sizeof(int) );
		if(n != sizeof(int)) write_failed = true;
	}
	int error_len = Info.error_desc.Length();
	if(error_len) {
		error_len++; //write the null too
	}
	if(!write_failed) {
		n = daemonCore->Write_Pipe( TransferPipe[1],
				   (char *)&error_len,
				   sizeof(int) );
		if(n != sizeof(int)) write_failed = true;
	}
	if(!write_failed) {
		n = daemonCore->Write_Pipe( TransferPipe[1],
				   Info.error_desc.Value(),
				   error_len );
		if(n != error_len) write_failed = true;
	}

	int spooled_files_len = Info.spooled_files.Length();
	if(spooled_files_len) {
		spooled_files_len++; //write the null too
	}
	if(!write_failed) {
		n = daemonCore->Write_Pipe( TransferPipe[1],
				   (char *)&spooled_files_len,
				   sizeof(int) );
		if(n != sizeof(int)) write_failed = true;
	}
	if(!write_failed) {
		n = daemonCore->Write_Pipe( TransferPipe[1],
				   Info.spooled_files.Value(),
				   spooled_files_len );
		if(n != spooled_files_len) write_failed = true;
	}

	if(write_failed) {
		dprintf(D_ALWAYS,"Failed to write transfer status to pipe (errno %d): %s\n",errno,strerror(errno));
		return false;
	}

	return true;
}

int
FileTransfer::UploadThread(void *arg, Stream *s)
{
	dprintf(D_FULLDEBUG,"entering FileTransfer::UploadThread\n");
	FileTransfer * myobj = ((upload_info *)arg)->myobj;

	if (s == NULL) {
		return 0;
	}

	filesize_t	total_bytes;
	int status = myobj->DoUpload( &total_bytes, (ReliSock *)s );
	if(!myobj->WriteStatusToTransferPipe(total_bytes)) {
		return 0;
	}
	return ( status >= 0 );
}

/**
 * This function is responsible for invoking a given multifile transfer plugin on a set of
 * files in the execution sandbox AND sending the appropriate response back to the DoDownload
 * side of the file transfer.
 *
 * This can only be called from the DoUpload context; as it will write to the provided ReliSock,
 * many assumptions are made about where it is invoking from inside DoUpload.  For example, it
 * assumes that DoUpload is responsible for the transfer header for the first file.
 *
 * The implementation consists of invoking the `InvokeMultipleFileTransferPlugin` method and
 * parsing the output as appropriate.
 *
 * For each transfer performed by the multi plugin, it will:
 *   - send a transfer header (EOM, INT/TransferCommand::Other, EOM, S/filename, EOM).
 *     Transfer header is skipped for the first file; DoUpload is supposed to do this.
 *   - Send a classad summarizing the transfer result.
 *   - EOM*.
 *
 *  * Depending on the setting of send_trailing_eom, it may skip the EOM for the
 *  very last transfer.
 *
 * - @param pluginPath: The location of the
 * - @returns: -1 on fatal error, 0 for a non-fatal error, and otherwise a fake number
 *   of bytes to use for the transfer summary.
 */
ssize_t
FileTransfer::InvokeMultiUploadPlugin(const std::string &pluginPath, const std::string &input, ReliSock &sock, bool send_trailing_eom, CondorError &err)
{
	std::vector<std::unique_ptr<ClassAd>> result_ads;
	auto result = InvokeMultipleFileTransferPlugin(err, pluginPath, input,
		LocalProxyName.Value(), true, &result_ads);

	size_t bytes = 0;
	int count = 0;
	bool classad_contents_good = true;
	for (const auto &xfer_result: result_ads) {
		std::string filename;
		if (!xfer_result->EvaluateAttrString("TransferFileName", filename)) {
			dprintf(D_FULLDEBUG, "DoUpload: Multi-file plugin at %s did not produce valid response; missing TransferFileName.\n", pluginPath.c_str());
			err.pushf("FILETRANSFER", 1, "Multi-file plugin at %s did not produce valid response; missing TransferFileName", pluginPath.c_str());
			classad_contents_good = false;
		}

		// Caller sends these headers for the first file only; we are responsible
		// for sending them subsequently.
		if (count) {
			// This is the trailing EOM from the last command.
			if( !sock.end_of_message() ) {
				dprintf(D_FULLDEBUG,"DoUpload: exiting at %d\n",__LINE__);
				return -1;
			}

			if( !sock.snd_int(static_cast<int>(TransferCommand::Other), false) ) {
				dprintf(D_FULLDEBUG,"DoUpload: exiting at %d\n",__LINE__);
				return -1;
			}
			if( !sock.end_of_message() ) {
				dprintf(D_FULLDEBUG,"DoUpload: exiting at %d\n",__LINE__);
				return -1;
			}

			if( !sock.put(condor_basename(filename.c_str())) ) {
				dprintf(D_FULLDEBUG,"DoUpload: exiting at %d\n",__LINE__);
				return -1;
			}
			if( !sock.end_of_message() ) {
				dprintf(D_FULLDEBUG, "DoUpload: failed on eom before GoAhead; exiting at %d\n",__LINE__);
				return -1;
			}
		}
			// From here on out, we are mostly converting the outcome of the multifile
			// transfer plugin to the ClassAd format required by the file transfer object.

		count++;
		ClassAd file_info;
		file_info.InsertAttr("ProtocolVersion", 1);
		file_info.InsertAttr("Command", static_cast<int>(TransferCommand::Other));
		file_info.InsertAttr("SubCommand", static_cast<int>(TransferSubCommand::UploadUrl));

			// Filename is expected to be relative to the sandbox directory; if we don't
			// call condor_basename here, the shadow may see the absolute path to the execute
			// directory and flag it as illegal.
		file_info.InsertAttr("Filename", condor_basename(filename.c_str()));
		std::string output_url;
		if (!xfer_result->EvaluateAttrString("TransferUrl", output_url)) {
			dprintf(D_FULLDEBUG, "DoUpload: Multi-file plugin at %s did not produce valid response; missing TransferUrl.\n", pluginPath.c_str());
			err.pushf("FILETRANSFER", 1, "Multi-file plugin at %s did not produce valid response; missing TransferUrl", pluginPath.c_str());
			classad_contents_good = false;
		}
		file_info.InsertAttr("OutputDestination", output_url);
		bool xfer_success;
		if (!xfer_result->EvaluateAttrBool("TransferSuccess", xfer_success)) {
			dprintf(D_FULLDEBUG, "DoUpload: Multi-file plugin at %s did not produce valid response; missing TransferSuccess.\n", pluginPath.c_str());
			err.pushf("FILETRANSFER", 1, "Multi-file plugin at %s did not produce valid response; missing TransferSuccess", pluginPath.c_str());
			classad_contents_good = false;
		}
		file_info.InsertAttr("Result", xfer_success ? 0 : 1);
		if (!xfer_success) {
			std::string transfer_error;
			if (!xfer_result->EvaluateAttrString("TransferError", transfer_error)) {
				dprintf(D_FULLDEBUG, "DoUpload: Multi-file plugin at %s did not produce valid response; missing TransferError for failed transfer.\n", pluginPath.c_str());
				err.pushf("FILETRANSFER", 1, "Multi-file plugin at %s did not produce valid response; missing TransferError for failed transfer", pluginPath.c_str());
				classad_contents_good = false;
			}
			file_info.InsertAttr("ErrorString", transfer_error);
		}
		if (!putClassAd(&sock, file_info)) {
			dprintf(D_FULLDEBUG, "DoDownload: When sending upload summaries to the remote side, a socket communication failed.\n");
			return -1;
		}

		classad::ClassAdUnParser unp;
		std::string serialized;
		unp.Unparse(serialized, &file_info);
		bytes += serialized.size();
	}
	if ( send_trailing_eom && !sock.end_of_message() ) {
		dprintf(D_FULLDEBUG,"DoUpload: exiting at %d\n",__LINE__);
		return -1;
	}

	if (!classad_contents_good) {return 0;}

	if (result == 0) {
		return bytes;
	}
	return -1;
}


int
FileTransfer::DoUpload(filesize_t *total_bytes, ReliSock *s)
{
	int rc;
	MyString fullname;
	filesize_t bytes;
	filesize_t peer_max_transfer_bytes = -1; // unlimited
	bool is_the_executable;
	bool upload_success = false;
	bool do_download_ack = false;
	bool do_upload_ack = false;
	bool try_again = false;
	int hold_code = 0;
	int hold_subcode = 0;
	int numFiles = 0;
	MyString error_desc;
	bool I_go_ahead_always = false;
	bool peer_goes_ahead_always = false;
	DCTransferQueue xfer_queue(m_xfer_queue_contact_info);

		// Declaration to make the return_and_reset_priv macro happy.
        std::string reservation_id;


	// use an error stack to keep track of failures when invoke plugins,
	// perhaps more of this can be instrumented with it later.
	CondorError errstack;

	// If a bunch of file transfers failed strictly due to
	// PUT_FILE_OPEN_FAILED, then we keep track of the information relating to
	// the first failed one, and continue to attempt to transfer the rest in
	// the list. At the end of the transfer, the job will go on hold with the
	// information of the first failed transfer. This is to allow things like
	// corefiles and whatnot to be brought back to the spool even if the user
	// job hadn't completed writing all the files as specified in
	// transfer_output_files. These variables represent the saved state of the
	// first failed transfer. See gt #487.
	bool first_failed_file_transfer_happened = false;
	bool first_failed_upload_success = false;
	bool first_failed_try_again = false;
	int first_failed_hold_code = 0;
	int first_failed_hold_subcode = 0;
	MyString first_failed_error_desc;
	int first_failed_line_number = 0;

	bool should_invoke_output_plugins, tmp;
	if (!jobAd.EvaluateAttrBool("OutputPluginsOnlyOnExit", tmp)) {
		should_invoke_output_plugins = m_final_transfer_flag;
	} else {
		if (!InitDownloadFilenameRemaps(&jobAd)) {
			return -1;
		}
		should_invoke_output_plugins = !tmp;
	}

	uploadStartTime = condor_gettimestamp_double();

	*total_bytes = 0;
	dprintf(D_FULLDEBUG,"entering FileTransfer::DoUpload\n");

	priv_state saved_priv = PRIV_UNKNOWN;
	if( want_priv_change ) {
		saved_priv = set_priv( desired_priv_state );
	}

	// Aggregate multiple file uploads; we will upload them all at once
	std::string currentUploadPlugin;
	std::string currentUploadRequests;
	int currentUploadDeferred = 0;

	// record the state it was in when we started... the "default" state
	bool socket_default_crypto = s->get_encryption();

	FileTransferList filelist;
	ExpandFileTransferList( FilesToSend, filelist );

	filesize_t sandbox_size = 0;
	FileTransferList::iterator filelist_it;
		// Calculate the sandbox size as the sum of the known file transfer items
		// (only those that are transferred via CEDAR).
	sandbox_size = std::accumulate(filelist.begin(),
		filelist.end(),
		sandbox_size,
		[](filesize_t partial_sum, FileTransferItem &item) {return partial_sum + item.fileSize();});

	s->encode();

	// tell the server if this is the final transfer or not.
	// if it is the final transfer, the server places the files
	// into the user's Iwd.  if not, the files go into SpoolSpace.
	if( !s->code(m_final_transfer_flag) ) {
		dprintf(D_FULLDEBUG,"DoUpload: exiting at %d\n",__LINE__);
		return_and_resetpriv( -1 );
	}
	if( PeerDoesXferInfo ) {
		ClassAd xfer_info;
		xfer_info.Assign(ATTR_SANDBOX_SIZE,sandbox_size);
		if( !putClassAd(s,xfer_info) ) {
			dprintf(D_FULLDEBUG,"DoUpload: failed to send xfer_info; exiting at %d\n",__LINE__);
			return_and_resetpriv( -1 );
		}
	}
	if( !s->end_of_message() ) {
		dprintf(D_FULLDEBUG,"DoUpload: exiting at %d\n",__LINE__);
		return_and_resetpriv( -1 );
	}

	std::vector<ReuseInfo> reuse_info;
	std::string tag;
	if (jobAd.EvaluateAttrString(ATTR_USER, tag))
	{
		dprintf(D_FULLDEBUG, "DoUpload: Tag to use for data reuse: %s\n", tag.c_str());
	} else {
		tag = "";
	}

	// Pre-compute various attributes about the file transfers.
	//
	// Right now, this is limited to calculating output URLs (must be done after prior
	// expansion of the transfer list); in the future, it might be a good place
	// to augment the file transfer items with checksum information.
	bool sign_s3_urls = param_boolean("SIGN_S3_URLS", true) && PeerDoesS3Urls;
		// We must pre-compute the list of URLs we need signed; the downloader-side
		// (typically the shadow...) to try and sign these.
	std::vector<std::string> s3_urls_to_sign;
	for (auto &fileitem : filelist) {
			// Pre-calculate if the uploader will be doing some uploads;
			// if so, we want to determine this now so we can sort correctly.
		if ( should_invoke_output_plugins ) {
			std::string local_output_url;
			if (OutputDestination) {
				local_output_url = OutputDestination;
				local_output_url += '/';
				local_output_url += fileitem.srcName();
			}
			else {
				MyString remap_filename;
				if ((1 == filename_remap_find(download_filename_remaps.Value(), fileitem.srcName().c_str(), remap_filename, 0)) && IsUrl(remap_filename.Value())) {
					local_output_url = remap_filename.Value();
				}
			}
			if (sign_s3_urls && local_output_url.substr(0, 5) == "s3://") {
				s3_urls_to_sign.push_back(local_output_url);
			}
			fileitem.setDestUrl(local_output_url);
		}
		if (PeerDoesReuseInfo) {
			std::string checksum_info;
			if ( ExecFile && !simple_init && !tag.empty() &&
				(MATCH == file_strcmp(fileitem.srcName().c_str(), ExecFile)) &&
				jobAd.EvaluateAttrString("ExecutableChecksum", checksum_info))
			{
				std::string checksum_type, checksum;
				auto sep = checksum_info.find(':');
				if (sep == std::string::npos) {
					checksum_type = "sha256";
					checksum = checksum_info;
				} else {
					checksum_type = checksum_info.substr(0, sep);
					checksum = checksum_info.substr(sep + 1);
				}
				reuse_info.emplace_back("condor_exec.exe", checksum, checksum_type, tag, fileitem.fileSize());
			}
		}
		const std::string &src_url = fileitem.srcName();
		if (sign_s3_urls && fileitem.isSrcUrl() && (fileitem.srcScheme() == "s3")) {
			std::string new_src_url = "https://" + src_url.substr(5);
			dprintf(D_FULLDEBUG, "DoUpload: Will sign %s for remote transfer.\n", src_url.c_str());
			std::string signed_url;
			CondorError err;
			if (htcondor::generate_presigned_url(jobAd, src_url, "GET", signed_url, err)) {
				fileitem.setSrcName(signed_url);
			} else {
				dprintf(D_ALWAYS, "DoUpload: Failed to sign URL - %s\n", err.getFullText().c_str());
			}
		}
	}

	std::unordered_set<std::string> skip_files;
	if (!reuse_info.empty())
	{
		dprintf(D_FULLDEBUG, "DoUpload: Sending remote side hints about potential file reuse.\n");

			// Indicate a ClassAd-based command.
		if( !s->snd_int(static_cast<int>(TransferCommand::Other), false) || !s->end_of_message() ) {
			dprintf(D_FULLDEBUG,"DoUpload: exiting at %d\n",__LINE__);
			return_and_resetpriv( -1 );
		}
			// Fake an empty filename.
		if (!s->put("") || !s->end_of_message()) {
			dprintf(D_FULLDEBUG,"DoUpload: exiting at %d\n",__LINE__);
			return_and_resetpriv(-1);
		}

			// Here, we must wait for the go-ahead from the transfer peer.
		if (!ReceiveTransferGoAhead(s, "", false, peer_goes_ahead_always, peer_max_transfer_bytes)) {
			dprintf(D_FULLDEBUG, "DoUpload: exiting at %d\n",__LINE__);
			return_and_resetpriv( -1 );
		}
			// Obtain the transfer token from the transfer queue.
		if (!ObtainAndSendTransferGoAhead(xfer_queue, false, s, sandbox_size, "", I_go_ahead_always) ) {
			dprintf(D_FULLDEBUG, "DoUpload: exiting at %d\n",__LINE__);
			return_and_resetpriv( -1 );
		}

		ClassAd file_info;
		auto sub = static_cast<int>(TransferSubCommand::ReuseInfo);
		file_info.InsertAttr("SubCommand", sub);
		file_info.InsertAttr("Tag", tag);
		std::vector<ExprTree*> info_list;
		for (auto &info : reuse_info) {
			classad::ClassAd *ad = new classad::ClassAd();
			ad->InsertAttr("FileName", info.filename());
			ad->InsertAttr("ChecksumType", info.checksum_type());
			ad->InsertAttr("Checksum", info.checksum());
			ad->InsertAttr("Size", static_cast<long long>(info.size()));
			info_list.push_back(ad);
		}
		file_info.Insert("ReuseList", classad::ExprList::MakeExprList(info_list));
		if (!putClassAd(s, file_info) || !s->end_of_message()) {
			dprintf(D_FULLDEBUG,"DoUpload: exiting at %d\n",__LINE__);
			return_and_resetpriv(-1);
		}
		ClassAd reuse_ad;
		s->decode();
		if (!getClassAd(s, reuse_ad)) {
			dprintf(D_FULLDEBUG,"DoUpload: exiting at %d\n",__LINE__);
			return_and_resetpriv(-1);
		}
		if (!s->end_of_message()) {
			dprintf(D_FULLDEBUG,"DoUpload: exiting at %d\n",__LINE__);
			return_and_resetpriv(-1);
		}
		s->encode();
		classad::Value value;
		classad_shared_ptr<classad::ExprList> exprlist;
		if (reuse_ad.EvaluateAttr("ReuseList", value) && value.IsSListValue(exprlist))
		{
			dprintf(D_FULLDEBUG, "DoUpload: Remote side sent back a list of files that were reused.\n");
			for (auto list_entry : (*exprlist)) {
				classad::Value entry_val;
				std::string fname;
				if (!list_entry->Evaluate(entry_val) || !entry_val.IsStringValue(fname)) {
					continue;
				}
				if (ExecFile && fname == "condor_exec.exe") {
					fname = ExecFile;
				}
				dprintf(D_FULLDEBUG, "DoUpload: File %s was reused.\n", fname.c_str());
				skip_files.insert(fname);
			}
		} else {
			dprintf(D_FULLDEBUG, "DoUpload: Remote side indicated there were no reused files.\n");
		}
	}

	std::unordered_map<std::string, std::string> s3_url_map;
	if (!s3_urls_to_sign.empty()) {
		dprintf(D_FULLDEBUG, "DoUpload: Requesting %lu URLs to sign.\n", s3_urls_to_sign.size());

			// Indicate a ClassAd-based command.
		if (!s->snd_int(static_cast<int>(TransferCommand::Other), false) || !s->end_of_message()) {
			dprintf(D_FULLDEBUG,"DoUpload: exiting at %d\n", __LINE__);
			return_and_resetpriv(-1);
		}
			// Fake an empty filename.
		if (!s->put("") || !s->end_of_message()) {
			dprintf(D_FULLDEBUG,"DoUpload: exiting at %d\n", __LINE__);
			return_and_resetpriv(-1);
		}

			// Here, we must wait for the go-ahead from the transfer peer.
		if (!ReceiveTransferGoAhead(s, "", false, peer_goes_ahead_always, peer_max_transfer_bytes)) {
			dprintf(D_FULLDEBUG, "DoUpload: exiting at %d\n", __LINE__);
			return_and_resetpriv(-1);
		}
			// Obtain the transfer token from the transfer queue.
		if (!ObtainAndSendTransferGoAhead(xfer_queue, false, s, sandbox_size, "", I_go_ahead_always) ) {
			dprintf(D_FULLDEBUG, "DoUpload: exiting at %d\n", __LINE__);
			return_and_resetpriv(-1);
		}

		ClassAd file_info;
		auto sub = static_cast<int>(TransferSubCommand::SignUrls);
		file_info.InsertAttr("SubCommand", sub);
		std::vector<ExprTree*> info_list;
		for (auto &info : s3_urls_to_sign) {
			info_list.push_back(classad::Literal::MakeString(info));
		}
		file_info.Insert("SignList", classad::ExprList::MakeExprList(info_list));

		if (!putClassAd(s, file_info) || !s->end_of_message()) {
			dprintf(D_FULLDEBUG, "DoUpload: exiting at %d\n", __LINE__);
			return_and_resetpriv(-1);
		}
		ClassAd signed_ad;
		s->decode();
		if (!getClassAd(s, signed_ad) ||
			!s->end_of_message())
		{
			dprintf(D_FULLDEBUG, "DoUpload: exiting at %d\n", __LINE__);
			return_and_resetpriv(-1);
		}
		s->encode();
		classad::Value value;
		classad_shared_ptr<classad::ExprList> exprlist;
		if (signed_ad.EvaluateAttr("SignList", value) && value.IsSListValue(exprlist))
		{
			dprintf(D_FULLDEBUG, "DoUpload: Remote side sent back a list of %d URLs that were signed.\n", exprlist->size());
			size_t idx = 0;
			for (auto list_entry : (*exprlist)) {
				if (idx == s3_urls_to_sign.size()) {
					dprintf(D_FULLDEBUG, "DoUpload: WARNING - remote side sent too few results\n");
					break;
				}
				classad::Value entry_val;
				std::string signed_url;
				if (!list_entry->Evaluate(entry_val) || !entry_val.IsStringValue(signed_url)) {
					idx++;
					dprintf(D_FULLDEBUG, "DoUpload: WARNING - not a valid string entry\n");
					continue;
				}

				if (!signed_url.empty()) {
					s3_url_map.insert({s3_urls_to_sign[idx], signed_url});
				}
				idx++;
			}
		}
	}

	std::sort(filelist.begin(), filelist.end());
	for (auto &fileitem : filelist)
	{
			// If there's a signed URL to work with, we should use that instead.
		auto iter = s3_url_map.find(fileitem.destUrl());
		if (iter != s3_url_map.end()) {
			fileitem.setDestUrl(iter->second);
		}

		auto &filename = fileitem.srcName();
		auto &dest_dir = fileitem.destDir();

			// Anything the remote side was able to reuse we do not send again.
		if (skip_files.find(filename) != skip_files.end()) {
			continue;
		}

		if( !dest_dir.empty() ) {
			dprintf(D_FULLDEBUG,"DoUpload: sending file %s to %s%c\n", filename.c_str(), dest_dir.c_str(), DIR_DELIM_CHAR);
		}
		else {
			dprintf(D_FULLDEBUG,"DoUpload: sending file %s\n", filename.c_str());
		}

		if( fileitem.isSrcUrl() ) {
			if( param_boolean("ENABLE_URL_TRANSFERS", true) ) {
				// looks like a URL
				fullname = filename;
				dprintf(D_FULLDEBUG, "DoUpload: sending %s as URL.\n", filename.c_str());
			} else {
				// A URL was requested but the sysadmin has disabled URL transfers; this
				// should have been prevented by matchmaking, so we fail this instead of
				// treating the URL as a filename.
				dprintf(D_ALWAYS, "DoUpload: WARNING - URL transfers were disabled by the sysadmin, "
					"but this transfer requires URL transfers to function; failing");
				return_and_resetpriv( -1 );
			}
		} else if( !fullpath( filename.c_str() ) ){
			// looks like a relative path
			fullname.formatstr("%s%c%s",Iwd,DIR_DELIM_CHAR,filename.c_str());
		} else {
			// looks like an unix absolute path or a windows path
			fullname = filename;
		}

		MyString dest_filename;
		if ( ExecFile && !simple_init && (file_strcmp(ExecFile,filename.c_str())==0 )) {
			// this file is the job executable
			is_the_executable = true;
			dest_filename = CONDOR_EXEC;
		} else {
			// this file is _not_ the job executable
			is_the_executable = false;

			if( !dest_dir.empty() ) {
				dest_filename.formatstr("%s%c",dest_dir.c_str(),DIR_DELIM_CHAR);
			}

			// condor_basename works for URLs
				// If we signed the URL, we added a bunch of garbage to the query string.
				// Strip that out at this point.
			auto idx = filename.find("?");
			std::string tmp_filename = filename.substr(0, idx);

			dprintf(D_FULLDEBUG, "DoUpload: Will transfer to filename %s.\n", tmp_filename.c_str());
			dest_filename.formatstr_cat( "%s", condor_basename(tmp_filename.c_str()) );
		}

		// check for read permission on this file, if we are supposed to check.
		// do not check the executable, since it is likely sitting in the SPOOL
		// directory.
		//
		// also, don't check URLs
#ifdef WIN32
		if( !fileitem.isSrcUrl() && perm_obj && !is_the_executable &&
			(perm_obj->read_access(fullname.Value()) != 1) ) {
			// we do _not_ have permission to read this file!!
			upload_success = false;
			error_desc.formatstr("error reading from %s: permission denied",fullname.Value());
			do_upload_ack = true;    // tell receiver that we failed
			do_download_ack = true;
			try_again = false; // put job on hold
			hold_code = CONDOR_HOLD_CODE_UploadFileError;
			hold_subcode = EPERM;
			return ExitDoUpload(total_bytes,numFiles, s,saved_priv,socket_default_crypto,
			                    upload_success,do_upload_ack,do_download_ack,
								try_again,hold_code,hold_subcode,
								error_desc.Value(),__LINE__);
		}
#else
		if (is_the_executable) {} // Done to get rid of the compiler set-but-not-used warnings.
#endif


		// The number 999 means we will still send the filename, and then send a
		// classad immediately following the filename, and the classad will say
		// what action to perform.  this will allow potential changes without
		// breaking the wire protocol and hopefully will be more forward and
		// backward compatible for future updates.
		//

		// default to the socket default
		TransferCommand file_command = TransferCommand::XferFile;
		TransferSubCommand file_subcommand = TransferSubCommand::Unknown;

		// find out if this file is in DontEncryptFiles
		if ( DontEncryptFiles->file_contains_withwildcard(filename.c_str()) ) {
			// turn crypto off for this file (actually done below)
			file_command = TransferCommand::DisableEncryption;
		}

		// now find out if this file is in EncryptFiles.  if it was
		// also in DontEncryptFiles, that doesn't matter, this will
		// override.
		if ( EncryptFiles->file_contains_withwildcard(filename.c_str()) ) {
			// turn crypto on for this file (actually done below)
			file_command = TransferCommand::EnableEncryption;
		}

		// We want to delegate the job's x509 proxy, rather than just
		// copy it.
		if ( X509UserProxy && file_strcmp( filename.c_str(), X509UserProxy ) == 0 &&
			 DelegateX509Credentials ) {

			file_command = TransferCommand::XferX509;
		}

		if ( fileitem.isSrcUrl() ) {
			file_command = TransferCommand::DownloadUrl;
		}

		std::string multifilePluginPath;
		if ( fileitem.isDestUrl() ) {
			dprintf(D_FULLDEBUG, "FILETRANSFER: Using command 999:7 for output URL destination: %s\n",
				fileitem.destUrl().c_str());

			// switch from whatever command we had before to new classad
			// command new classad command 999 and subcommand 7.
			//
			// 7 == invoke plugin to store file
			file_command = TransferCommand::Other;
			file_subcommand = TransferSubCommand::UploadUrl;

			if (multifile_plugins_enabled) {
				std::string pluginPath = DetermineFileTransferPlugin( errstack, fileitem.destUrl().c_str(), fullname.c_str() );
				if ( (plugins_multifile_support.find( pluginPath ) != plugins_multifile_support.end()) && \
				plugins_multifile_support[pluginPath] ) {
					multifilePluginPath = pluginPath;
				}
			}
		}
		if (multifilePluginPath.empty()) {
			dprintf(D_FULLDEBUG, "Will upload output URL using single-file plugin.\n");
		} else {
			dprintf(D_FULLDEBUG, "Will upload output URL using multi-file plugin.\n");
		}

		// Flush out any transfers if we can no longer defer the prior work we had built up.
		// We can't defer if the plugin name changed *or* we hit a transfer that doesn't
		// require a plugin at all.
		if (!currentUploadPlugin.empty() && (multifilePluginPath != currentUploadPlugin)) {
			dprintf (D_FULLDEBUG, "DoUpload: Executing multifile plugin for multiple transfers.\n");
			auto result = InvokeMultiUploadPlugin(currentUploadPlugin, currentUploadRequests, *s, true, errstack);
			if (-1 == result) {
				return_and_resetpriv( -1 );
			} else if (result == 0) {
				error_desc.formatstr_cat(": %s", errstack.getFullText().c_str());
				if (!first_failed_file_transfer_happened) {
					first_failed_file_transfer_happened = true;
					first_failed_upload_success = false;
					first_failed_try_again = false;
					first_failed_hold_code = CONDOR_HOLD_CODE_UploadFileError;
					first_failed_hold_subcode = 1;
					first_failed_error_desc = error_desc;
					first_failed_line_number = __LINE__;
				}
			}
			currentUploadPlugin = "";
			currentUploadRequests = "";
			currentUploadDeferred = 0;
		}

		bool fail_because_mkdir_not_supported = false;
		bool fail_because_symlink_not_supported = false;
		if( fileitem.isDirectory() ) {
			if( fileitem.isSymlink() ) {
				fail_because_symlink_not_supported = true;
				dprintf(D_ALWAYS,"DoUpload: attempting to transfer symlink %s which points to a directory.  This is not supported.\n", filename.c_str());
			}
			else if( PeerUnderstandsMkdir ) {
				file_command = TransferCommand::Mkdir;
			}
			else {
				fail_because_mkdir_not_supported = true;
				dprintf(D_ALWAYS,"DoUpload: attempting to transfer directory %s, but the version of Condor we are talking to is too old to support that!\n",
						filename.c_str());
			}
		}

		dprintf ( D_FULLDEBUG, "FILETRANSFER: outgoing file_command is %i for %s\n",
				static_cast<int>(file_command), filename.c_str() );

			// Frustratingly, we cannot skip the header of the first transfer command
			// if we are defering uploads as we may have to acquire a transfer token below.
			// The protocol also requires us to acquire a transfer token AFTER the filename
			// is sent; hence, we cannot simply reorder the logic.
			//
			// Because we send the header now, `InvokeMultiUploadPlugin` does not for the first
			// transfer command.
		bool no_defer_header = multifilePluginPath.empty() || !currentUploadDeferred;
		if (no_defer_header) {
			if( !s->snd_int(static_cast<int>(file_command), false) ) {
				dprintf(D_FULLDEBUG,"DoUpload: exiting at %d\n",__LINE__);
				return_and_resetpriv( -1 );
			}
			if( !s->end_of_message() ) {
				dprintf(D_FULLDEBUG,"DoUpload: exiting at %d\n",__LINE__);
				return_and_resetpriv( -1 );
			}
		}

		// now enable the crypto decision we made; if we are sending a URL down the pipe
		// (potentially embedding an authorization itself), ensure we encrypt.
		if (file_command == TransferCommand::EnableEncryption || (PeerDoesS3Urls && (file_command == TransferCommand::DownloadUrl))) {
			bool cryp_ret = s->set_crypto_mode(true);
			if (!cryp_ret) {
				dprintf(D_ALWAYS,"DoUpload: failed to enable crypto on outgoing file, exiting at %d\n",__LINE__);
				return_and_resetpriv( -1 );
			}

		} else if (file_command == TransferCommand::DisableEncryption) {
			s->set_crypto_mode(false);
		}
		else {
			bool cryp_ret = s->set_crypto_mode(socket_default_crypto);
			if (!cryp_ret) {
				dprintf(D_ALWAYS,"DoUpload: failed to set default crypto on outgoing file, exiting at %d\n",__LINE__);
				return_and_resetpriv( -1 );
			}
		}

		// for command 999, this string must equal the Attribute "Filename" in
		// the classad that follows.  it wouldn't really need to be sent here
		// but is more wire-compatible with older versions if we do.
		//
		// should we send a protocol version string instead?  or some other token
		// like 'CLASSAD'?
		//
		if( no_defer_header && !s->put(dest_filename.Value()) ) {
			dprintf(D_FULLDEBUG,"DoUpload: exiting at %d\n",__LINE__);
			return_and_resetpriv( -1 );
		}

		if( PeerDoesGoAhead ) {
			if( no_defer_header && !s->end_of_message() ) {
				dprintf(D_FULLDEBUG, "DoUpload: failed on eom before GoAhead; exiting at %d\n",__LINE__);
				return_and_resetpriv( -1 );
			}

			if( !peer_goes_ahead_always ) {
					// Now wait for our peer to tell us it is ok for us to
					// go ahead and send data.
				if( !ReceiveTransferGoAhead(s,fullname.Value(),false,peer_goes_ahead_always,peer_max_transfer_bytes) ) {
					dprintf(D_FULLDEBUG, "DoUpload: exiting at %d\n",__LINE__);
					return_and_resetpriv( -1 );
				}
			}

			if( !I_go_ahead_always ) {
					// Now tell our peer when it is ok for us to read data
					// from disk for sending.
				if( !ObtainAndSendTransferGoAhead(xfer_queue,false,s,sandbox_size,fullname.Value(),I_go_ahead_always) ) {
					dprintf(D_FULLDEBUG, "DoUpload: exiting at %d\n",__LINE__);
					return_and_resetpriv( -1 );
				}
			}

			s->encode();
		}
		// Multifile uploads imply we execute multiple commands at once; although we can lie to the other side,
		// maintenance of the state becomes quite complex.  Hence, we defer uploads only when the protocol
		// is completely asynchronous.
		//
		// NOTE: if we ever want to reacquire the token (or acquire an alternate token for non-CEDAR transfers),
		// then this would provide a natural synchronization point.
		bool can_defer_uploads = !PeerDoesGoAhead || (peer_goes_ahead_always && I_go_ahead_always);

		UpdateXferStatus(XFER_STATUS_ACTIVE);

		filesize_t this_file_max_bytes = -1;
		filesize_t effective_max_upload_bytes = MaxUploadBytes;
		bool using_peer_max_transfer_bytes = false;
		if( peer_max_transfer_bytes >= 0 && (peer_max_transfer_bytes < effective_max_upload_bytes || effective_max_upload_bytes < 0) ) {
				// For superior error handling, it is best for the
				// uploading side to know about the downloading side's
				// max transfer byte limit.  This prevents the
				// uploading side from trying to send more than the
				// maximum, which would cause the downloading side to
				// close the connection, which would cause the
				// uploading side to assume there was a communication
				// error rather than an intentional stop.
			effective_max_upload_bytes = peer_max_transfer_bytes;
			using_peer_max_transfer_bytes = true;
			dprintf(D_FULLDEBUG,"DoUpload: changing maximum upload MB from %ld to %ld at request of peer.\n",
					(long int)(effective_max_upload_bytes >= 0 ? effective_max_upload_bytes/1024/1024 : effective_max_upload_bytes),
					(long int)(peer_max_transfer_bytes/1024/1024));
		}
		if( effective_max_upload_bytes < 0 ) {
			this_file_max_bytes = -1; // no limit
		}
		else if( effective_max_upload_bytes >= *total_bytes ) {
			this_file_max_bytes = effective_max_upload_bytes - *total_bytes;
		}
		else {
			this_file_max_bytes = 0;
		}

		if ( file_command == TransferCommand::Other) {
			// new-style, send classad

			ClassAd file_info;
			file_info.Assign("ProtocolVersion", 1);
			file_info.Assign("Command", static_cast<int>(file_command));
			file_info.Assign("SubCommand", static_cast<int>(file_subcommand));

			// only one subcommand at the moment: 7
			//
			// 7 is "Report to shadow the final status of invoking a transfer
			// hook to move the output file"

			if(file_subcommand == TransferSubCommand::UploadUrl) {
				// make the URL out of Attr OutputDestination and filename
				MyString source_filename;
				source_filename = Iwd;
				source_filename += DIR_DELIM_CHAR;
				source_filename += filename;

				const std::string &local_output_url = fileitem.destUrl();

				// Potentially execute the multifile plugin.  Note all the error handling
				// occurs outside this gigantic if block - we must carefully set `rc` for it
				// to work correctly.
				if (!multifilePluginPath.empty()) {
					currentUploadPlugin = multifilePluginPath;

					classad::ClassAdUnParser unparser;
					ClassAd xfer_ad;
					xfer_ad.InsertAttr( "Url", local_output_url );
					xfer_ad.InsertAttr( "LocalFileName", fullname );
					std::string xfer_str;
					unparser.Unparse( xfer_str, &xfer_ad );

					currentUploadRequests += xfer_str;
					currentUploadDeferred ++;

					// If we cannot defer uploads, we must execute the plugin now -- with one file.
					if (!can_defer_uploads) {
						dprintf (D_FULLDEBUG, "DoUpload: Executing multifile plugin for multiple transfers.\n");
						auto result = InvokeMultiUploadPlugin(currentUploadPlugin, currentUploadRequests, *s, false, errstack);
						if (-1 == result) {
							return_and_resetpriv( -1 );
						}
						currentUploadPlugin = "";
						currentUploadRequests = "";
						currentUploadDeferred = 0;
						rc = (result == 0) ? -1 : 0;
					} else {
						rc = 0;
					}
				} else {
					// actually invoke the plugin.  this could block indefinitely.
					ClassAd pluginStatsAd;
					dprintf (D_FULLDEBUG, "DoUpload: calling IFTP(fn,U): fn\"%s\", U\"%s\"\n", source_filename.Value(), local_output_url.c_str());
					dprintf (D_FULLDEBUG, "LocalProxyName: %s\n", LocalProxyName.Value());
					rc = InvokeFileTransferPlugin(errstack, source_filename.Value(), local_output_url.c_str(), &pluginStatsAd, LocalProxyName.Value());
					dprintf (D_FULLDEBUG, "DoUpload: IFTP(fn,U): fn\"%s\", U\"%s\" returns %i\n", source_filename.Value(), local_output_url.c_str(), rc);

					// report the results:
					file_info.Assign("Filename", source_filename);
					file_info.Assign("OutputDestination", local_output_url);

					// will either be 0 (success) or -4 (GET_FILE_PLUGIN_FAILED)
					file_info.Assign("Result", rc);

					// nonzero indicates failure, put the ErrStack into the classad
					if (rc) {
						file_info.Assign("ErrorString", errstack.getFullText());
					}

					// it's all assembled, so send the ad using stream s.
					// don't end the message, it's done below.
					// Always encrypt the URL as it might contain an authorization.
					const classad::References encrypted_attrs{"OutputDestination"};
					if(!putClassAd(s, file_info, 0, &encrypted_attrs)) {
						dprintf(D_FULLDEBUG,"DoDownload: exiting at %d\n",__LINE__);
						return_and_resetpriv( -1 );
					}

					// compute the size of what we sent
					MyString junkbuf;
					sPrintAd(junkbuf, file_info);
					bytes = junkbuf.Length();
				}
			} else {
				dprintf( D_ALWAYS, "DoUpload: invalid subcommand %i, skipping %s.",
						static_cast<int>(file_subcommand), filename.c_str());
				bytes = 0;
				rc = 0;
			}
		} else if ( file_command == TransferCommand::XferX509 ) {
			if ( (PeerDoesGoAhead || s->end_of_message()) ) {
				time_t expiration_time = GetDesiredDelegatedJobCredentialExpiration(&jobAd);
				rc = s->put_x509_delegation( &bytes, fullname.Value(), expiration_time, NULL );
				dprintf( D_FULLDEBUG,
				         "DoUpload: put_x509_delegation() returned %d\n",
				         rc );
			} else {
				rc = -1;
			}
		} else if (file_command == TransferCommand::DownloadUrl) {
			// send the URL and that's it for now.
			// TODO: this should probably be a classad
			if(!s->code(fullname)) {
				dprintf( D_FULLDEBUG, "DoUpload: failed to send fullname: %s\n", fullname.Value());
				rc = -1;
			} else {
				dprintf( D_FULLDEBUG, "DoUpload: sent fullname and NO eom: %s\n", fullname.Value());
				rc = 0;
			}

			// on the sending side, we don't know how many bytes the actual
			// file was, since we aren't the ones downloading it.  to find out
			// the length, we'd have to make a connection to some server (via a
			// plugin, for which no API currently exists) and ask it, and i
			// don't want to add that latency.
			// 
			// instead we add the length of the URL itself, since that's what
			// we sent.
			bytes = fullname.Length();

		} else if( file_command == TransferCommand::Mkdir ) { // mkdir
			// the only data sent is the file_mode.
			bytes = sizeof( fileitem.fileMode() );

			if( !s->put( fileitem.fileMode() ) ) {
				rc = -1;
				dprintf(D_ALWAYS,"DoUpload: failed to send mkdir mode\n");
			}
			else {
				rc = 0;
			}
		} else if( fail_because_mkdir_not_supported || fail_because_symlink_not_supported ) {
			if( TransferFilePermissions ) {
				rc = s->put_file_with_permissions( &bytes, NULL_FILE );
			}
			else {
				rc = s->put_file( &bytes, NULL_FILE );
			}
			if( rc == 0 ) {
				rc = PUT_FILE_OPEN_FAILED;
				errno = EISDIR;
			}
		} else if ( TransferFilePermissions ) {
			rc = s->put_file_with_permissions( &bytes, fullname.Value(), this_file_max_bytes, &xfer_queue );
		} else {
			rc = s->put_file( &bytes, fullname.Value(), 0, this_file_max_bytes, &xfer_queue );
		}
		if( rc < 0 ) {
			int the_error = errno;
			upload_success = false;
			error_desc.formatstr("error sending %s",fullname.Value());
			if((rc == PUT_FILE_OPEN_FAILED) || (rc == PUT_FILE_PLUGIN_FAILED) || (rc == PUT_FILE_MAX_BYTES_EXCEEDED)) {
				try_again = false; // put job on hold
				hold_code = CONDOR_HOLD_CODE_UploadFileError;
				hold_subcode = the_error;

				if (rc == PUT_FILE_OPEN_FAILED) {
					// In this case, put_file() has transmitted a zero-byte
					// file in place of the failed one. This means there is an
					// ack waiting for us to read back which we do at the end of
					// the while loop.

					error_desc.replaceString("sending","reading from");
					error_desc.formatstr_cat(": (errno %d) %s",the_error,strerror(the_error));
					if( fail_because_mkdir_not_supported ) {
						error_desc.formatstr_cat("; Remote condor version is too old to transfer directories.");
					}
					if( fail_because_symlink_not_supported ) {
						error_desc.formatstr_cat("; Transfer of symlinks to directories is not supported.");
					}
				} else if ( rc == PUT_FILE_MAX_BYTES_EXCEEDED ) {
					StatInfo this_file_stat(fullname.Value());
					filesize_t this_file_size = this_file_stat.GetFileSize();
					error_desc.formatstr_cat(": max total %s bytes exceeded (max=%ld MB, this file=%ld MB)",
											 using_peer_max_transfer_bytes ? "download" : "upload",
											 (long int)(effective_max_upload_bytes/1024/1024),
											 (long int)(this_file_size/1024/1024));
					hold_code = using_peer_max_transfer_bytes ? CONDOR_HOLD_CODE_MaxTransferOutputSizeExceeded : CONDOR_HOLD_CODE_MaxTransferInputSizeExceeded;
					the_error = 0;
				} else {
					// add on the error string from the errstack used
					error_desc.formatstr_cat(": %s", errstack.getFullText().c_str());
				}

				// We'll continue trying to transfer the rest of the files
				// in question, but we'll record the information we need from
				// the first failure. Notice that this means we won't know
				// the complete set of files which failed to transfer back
				// but have become zero length files on the submit side.
				// We'd need to append those failed files to some kind of an
				// attribute in the job ad representing this failure. That
				// is not currently implemented....

				if (first_failed_file_transfer_happened == false) {
					first_failed_file_transfer_happened = true;
					first_failed_upload_success = false;
					first_failed_try_again = false;
					first_failed_hold_code = hold_code;
					first_failed_hold_subcode = the_error;
					first_failed_error_desc = error_desc;
					first_failed_line_number = __LINE__;
				}
			}
			else {
				// We can't currently tell the different between other
				// put_file() errors that will generate an ack error
				// report, and those that are due to a genuine
				// disconnect between us and the receiver.  Therefore,
				// always try reading the download ack.
				do_download_ack = true;
				// The stream _from_ us to the receiver is in an undefined
				// state.  Some network operation may have failed part
				// way through the transmission, so we cannot expect
				// the other side to be able to read our upload ack.
				do_upload_ack = false;
				try_again = true;

				// for the more interesting reasons why the transfer failed,
				// we can try again and see what happens.
				return ExitDoUpload(total_bytes,numFiles, s,saved_priv,
								socket_default_crypto,upload_success,
								do_upload_ack,do_download_ack,
			                    try_again,hold_code,hold_subcode,
			                    error_desc.Value(),__LINE__);
			}
		}

		if( !currentUploadDeferred && !s->end_of_message() ) {
			dprintf(D_FULLDEBUG,"DoUpload: socket communication failure; exiting at line %d\n",__LINE__);
			return_and_resetpriv( -1 );
		}

		*total_bytes += bytes;
		numFiles++;

			// The spooled files list is used to generate
			// SpooledOutputFiles, which replaces TransferOutputFiles
			// when pulling output from the spool directory.  We don't
			// really know here whether the other side is writing to the
			// spool or not, but we generate the list just in case.
			//
			// If we transfer directories, only include the directory
			// in the spooled files list, not its contents.  Also skip
			// the stdout/stderr files, since those are handled
			// separately when building the list of files to transfer.

		if( dest_filename.FindChar(DIR_DELIM_CHAR) < 0 &&
			dest_filename != condor_basename(JobStdoutFile.Value()) &&
			dest_filename != condor_basename(JobStderrFile.Value()) &&
			(file_command != TransferCommand::Other || file_subcommand != TransferSubCommand::UploadUrl) )
		{
			Info.addSpooledFile( dest_filename.Value() );
		}
	}
	// Release transfer queue slot after file has been put but before the
	// final transfer statistics are done.  The remote side (typically, the starter),
	// currently does multifile transfer plugins during this time and we do not want
	// to keep the queue slot held when this transfer plugin is invoked.
	xfer_queue.ReleaseTransferQueueSlot();

	// Clear out the multi-upload queue; we must do the error handling locally if it fails.
	if (!currentUploadRequests.empty()) {
		auto result = InvokeMultiUploadPlugin(currentUploadPlugin, currentUploadRequests, *s, true, errstack);
		if (-1 == result) {
			return_and_resetpriv( -1 );
		}
		if (result == 0) {
			error_desc.formatstr_cat(": %s", errstack.getFullText().c_str());
			if (!first_failed_file_transfer_happened) {
				first_failed_file_transfer_happened = true;
				first_failed_upload_success = false;
				first_failed_try_again = false;
				first_failed_hold_code = CONDOR_HOLD_CODE_UploadFileError;
				first_failed_hold_subcode = 1;
				first_failed_error_desc = error_desc;
				first_failed_line_number = __LINE__;
			}
		}
		total_bytes += result;
	}

	do_download_ack = true;
	do_upload_ack = true;

	if (first_failed_file_transfer_happened == true) {
		return ExitDoUpload(total_bytes,numFiles, s,saved_priv,socket_default_crypto,
			first_failed_upload_success,do_upload_ack,do_download_ack,
			first_failed_try_again,first_failed_hold_code,
			first_failed_hold_subcode,first_failed_error_desc.Value(),
			first_failed_line_number);
	}

	uploadEndTime = condor_gettimestamp_double();

	upload_success = true;
	return ExitDoUpload(total_bytes,numFiles, s,saved_priv,socket_default_crypto,
	                    upload_success,do_upload_ack,do_download_ack,
	                    try_again,hold_code,hold_subcode,NULL,__LINE__);
}

void
FileTransfer::setTransferQueueContactInfo(char const *contact) {
	m_xfer_queue_contact_info = TransferQueueContactInfo(contact);
}

bool
FileTransfer::ObtainAndSendTransferGoAhead(DCTransferQueue &xfer_queue,bool downloading,Stream *s,filesize_t sandbox_size,char const *full_fname,bool &go_ahead_always)
{
	bool result;
	bool try_again = true;
	int hold_code = 0;
	int hold_subcode = 0;
	MyString error_desc;

	result = DoObtainAndSendTransferGoAhead(xfer_queue,downloading,s,sandbox_size,full_fname,go_ahead_always,try_again,hold_code,hold_subcode,error_desc);

	if( !result ) {
		SaveTransferInfo(false,try_again,hold_code,hold_subcode,error_desc.Value());
		if( error_desc.Length() ) {
			dprintf(D_ALWAYS,"%s\n",error_desc.Value());
		}
	}
	return result;
}

std::string
FileTransfer::GetTransferQueueUser()
{
	std::string user;
	ClassAd *job = GetJobAd();
	if( job ) {
		std::string user_expr;
		if( param(user_expr,"TRANSFER_QUEUE_USER_EXPR","strcat(\"Owner_\",Owner)") ) {
			ExprTree *user_tree = NULL;
			if( ParseClassAdRvalExpr( user_expr.c_str(), user_tree ) == 0 && user_tree ) {
				classad::Value val;
				const char *str = NULL;
				if ( EvalExprTree(user_tree,job,NULL,val) && val.IsStringValue(str) )
				{
					user = str;
				}
				delete user_tree;
			}
		}
	}
	return user;
}

bool
FileTransfer::DoObtainAndSendTransferGoAhead(DCTransferQueue &xfer_queue,bool downloading,Stream *s,filesize_t sandbox_size,char const *full_fname,bool &go_ahead_always,bool &try_again,int &hold_code,int &hold_subcode,MyString &error_desc)
{
	ClassAd msg;
	int go_ahead = GO_AHEAD_UNDEFINED;
	int alive_interval = 0;
	time_t last_alive = time(NULL);
		//extra time to reserve for sending msg to our file xfer peer
	const int alive_slop = 20;
	int min_timeout = 300;

	std::string queue_user = GetTransferQueueUser();

	s->decode();
	if( !s->get(alive_interval) || !s->end_of_message() ) {
		error_desc.formatstr("ObtainAndSendTransferGoAhead: failed on alive_interval before GoAhead");
		return false;
	}

	if( Sock::get_timeout_multiplier() > 0 ) {
		min_timeout *= Sock::get_timeout_multiplier();
	}

	int timeout = alive_interval;
	if( timeout < min_timeout ) {
		timeout = min_timeout;

			// tell peer the new timeout
		msg.Assign(ATTR_TIMEOUT,timeout);
			// GO_AHEAD_UNDEFINED just means that our peer should keep waiting
		msg.Assign(ATTR_RESULT,go_ahead);

		s->encode();
		if( !putClassAd(s, msg) || !s->end_of_message() ) {
			error_desc.formatstr("Failed to send GoAhead new timeout message.");
		}
	}
	ASSERT( timeout > alive_slop );
	timeout -= alive_slop;

	if( !xfer_queue.RequestTransferQueueSlot(downloading,sandbox_size,full_fname,m_jobid.Value(),queue_user.c_str(),timeout,error_desc) )
	{
		go_ahead = GO_AHEAD_FAILED;
	}

	bool first_poll = true;
	while(1) {
		if( go_ahead == GO_AHEAD_UNDEFINED ) {
			timeout = alive_interval - (time(NULL) - last_alive) - alive_slop;
			if( timeout < min_timeout ) timeout = min_timeout;
			if( first_poll ) {
					// Use a short timeout on the first time, so we quickly report
					// that the transfer is queued, if it is.
				timeout = 5;
			}
			bool pending = true;
			if( xfer_queue.PollForTransferQueueSlot(timeout,pending,error_desc) )
			{
				// In the current version of HTCondor, the file transfer
				// queue slot lasts as long as the TCP connection does.
				// Hence, there is no need to keep checking for GoAhead
				// for each file; just let 'em rip.
				go_ahead = GO_AHEAD_ALWAYS;
			}
			else if( !pending ) {
				go_ahead = GO_AHEAD_FAILED;
			}
		}

		char const *ip = s->peer_ip_str();
		char const *go_ahead_desc = "";
		if( go_ahead < 0 ) go_ahead_desc = "NO ";
		if( go_ahead == GO_AHEAD_UNDEFINED ) go_ahead_desc = "PENDING ";

		dprintf( go_ahead < 0 ? D_ALWAYS : D_FULLDEBUG,
				 "Sending %sGoAhead for %s to %s %s%s.\n",
				 go_ahead_desc,
				 ip ? ip : "(null)",
				 downloading ? "send" : "receive",
				 full_fname,
				 (go_ahead == GO_AHEAD_ALWAYS) ? " and all further files":"");

		s->encode();
		msg.Assign(ATTR_RESULT,go_ahead); // go ahead
		if( downloading ) {
			msg.Assign(ATTR_MAX_TRANSFER_BYTES,MaxDownloadBytes);
		}
		if( go_ahead < 0 ) {
				// tell our peer what exactly went wrong
			msg.Assign(ATTR_TRY_AGAIN,try_again);
			msg.Assign(ATTR_HOLD_REASON_CODE,hold_code);
			msg.Assign(ATTR_HOLD_REASON_SUBCODE,hold_subcode);
			if( error_desc.Length() ) {
				msg.Assign(ATTR_HOLD_REASON,error_desc.Value());
			}
		}
		if( !putClassAd(s, msg) || !s->end_of_message() ) {
			error_desc.formatstr("Failed to send GoAhead message.");
			try_again = true;
			return false;
		}
		last_alive = time(NULL);

		if( go_ahead != GO_AHEAD_UNDEFINED ) {
			break;
		}

		UpdateXferStatus(XFER_STATUS_QUEUED);
	}

	if( go_ahead == GO_AHEAD_ALWAYS ) {
		go_ahead_always = true;
	}

	return go_ahead > 0;
}

bool
FileTransfer::ReceiveTransferGoAhead(
	Stream *s,
	char const *fname,
	bool downloading,
	bool &go_ahead_always,
	filesize_t &peer_max_transfer_bytes)
{
	bool try_again = true;
	int hold_code = 0;
	int hold_subcode = 0;
	MyString error_desc;
	bool result;
	int alive_interval;
	int old_timeout;
	const int slop_time = 20; // extra time to wait when alive_interval expires
	const int min_alive_interval = 300;

	// How frequently peer should tell us that it is still alive while
	// we are waiting for GoAhead.  Note that the peer may respond
	// with its own specification of timeout if it does not agree with
	// ours.  This is an important issue, because our peer may need to
	// talk to some other service (i.e. the schedd) before getting
	// back to us.

	alive_interval = clientSockTimeout;
	if( alive_interval < min_alive_interval ) {
		alive_interval = min_alive_interval;
	}
	old_timeout = s->timeout(alive_interval + slop_time);

	result = DoReceiveTransferGoAhead(s,fname,downloading,go_ahead_always,peer_max_transfer_bytes,try_again,hold_code,hold_subcode,error_desc,alive_interval);

	s->timeout( old_timeout );

	if( !result ) {
		SaveTransferInfo(false,try_again,hold_code,hold_subcode,error_desc.Value());
		if( error_desc.Length() ) {
			dprintf(D_ALWAYS,"%s\n",error_desc.Value());
		}
	}

	return result;
}

bool
FileTransfer::DoReceiveTransferGoAhead(
	Stream *s,
	char const *fname,
	bool downloading,
	bool &go_ahead_always,
	filesize_t &peer_max_transfer_bytes,
	bool &try_again,
	int &hold_code,
	int &hold_subcode,
	MyString &error_desc,
	int alive_interval)
{
	int go_ahead = GO_AHEAD_UNDEFINED;

	s->encode();

	if( !s->put(alive_interval) || !s->end_of_message() ) {
		error_desc.formatstr("DoReceiveTransferGoAhead: failed to send alive_interval");
		return false;
	}

	s->decode();

	while(1) {
		ClassAd msg;
		if( !getClassAd(s, msg) || !s->end_of_message() ) {
			char const *ip = s->peer_ip_str();
			error_desc.formatstr("Failed to receive GoAhead message from %s.",
							   ip ? ip : "(null)");

			return false;
		}

		go_ahead = GO_AHEAD_UNDEFINED;
		if(!msg.LookupInteger(ATTR_RESULT,go_ahead)) {
			MyString msg_str;
			sPrintAd(msg_str, msg);
			error_desc.formatstr("GoAhead message missing attribute: %s.  "
							   "Full classad: [\n%s]",
							   ATTR_RESULT,msg_str.Value());
			try_again = false;
			hold_code = CONDOR_HOLD_CODE_InvalidTransferGoAhead;
			hold_subcode = 1;
			return false;
		}

		filesize_t mtb = peer_max_transfer_bytes;
		if( msg.LookupInteger(ATTR_MAX_TRANSFER_BYTES,mtb) ) {
			peer_max_transfer_bytes = mtb;
		}

		if( go_ahead == GO_AHEAD_UNDEFINED ) {
				// This is just an "alive" message from our peer.
				// Keep looping.

			int new_timeout = -1;
			if( msg.LookupInteger(ATTR_TIMEOUT,new_timeout) &&
				new_timeout != -1)
			{
				// our peer wants a different timeout
				s->timeout(new_timeout);
				dprintf(D_FULLDEBUG,"Peer specified different timeout "
				        "for GoAhead protocol: %d (for %s)\n",
						new_timeout, fname);
			}

			dprintf(D_FULLDEBUG,"Still waiting for GoAhead for %s.\n",fname);
			UpdateXferStatus(XFER_STATUS_QUEUED);
			continue;
		}

		if(!msg.LookupBool(ATTR_TRY_AGAIN,try_again)) {
			try_again = true;
		}

		if(!msg.LookupInteger(ATTR_HOLD_REASON_CODE,hold_code)) {
			hold_code = 0;
		}
		if(!msg.LookupInteger(ATTR_HOLD_REASON_SUBCODE,hold_subcode)) {
			hold_subcode = 0;
		}
		char *hold_reason_buf = NULL;
		if(msg.LookupString(ATTR_HOLD_REASON,&hold_reason_buf)) {
			error_desc = hold_reason_buf;
			free(hold_reason_buf);
		}

		break;
	}

	if( go_ahead <= 0 ) {
		return false;
	}

	if( go_ahead == GO_AHEAD_ALWAYS ) {
		go_ahead_always = true;
	}

	dprintf(D_FULLDEBUG,"Received GoAhead from peer to %s %s%s.\n",
			downloading ? "receive" : "send",
			fname,
			go_ahead_always ? " and all further files" : "");

	return true;
}

int
FileTransfer::ExitDoUpload(filesize_t *total_bytes, int numFiles, ReliSock *s, priv_state saved_priv, bool socket_default_crypto, bool upload_success, bool do_upload_ack, bool do_download_ack, bool try_again, int hold_code, int hold_subcode, char const *upload_error_desc,int DoUpload_exit_line)
{
	int rc = upload_success ? 0 : -1;
	bool download_success = false;
	MyString error_buf;
	MyString download_error_buf;
	char const *error_desc = NULL;

	dprintf(D_FULLDEBUG,"DoUpload: exiting at %d\n",DoUpload_exit_line);

	if( saved_priv != PRIV_UNKNOWN ) {
		_set_priv(saved_priv,__FILE__,DoUpload_exit_line,1);
	}

#ifdef WIN32
		// unsigned __int64 to float not implemented on Win32
	bytesSent += (float)(signed __int64)*total_bytes;
#else 
	bytesSent += *total_bytes;
#endif

	if(do_upload_ack) {
		// peer is still expecting us to send a file command
		if(!PeerDoesTransferAck && !upload_success) {
			// We have no way to tell the other side that something has
			// gone wrong other than slamming the connection without
			// sending the final file command 0.  Therefore, send nothing.
		}
		else {
			// no more files to send
			s->snd_int(static_cast<int>(TransferCommand::Finished), TRUE);

			// go back to the state we were in before file transfer
			s->set_crypto_mode(socket_default_crypto);

			MyString error_desc_to_send;
			if(!upload_success) {
				error_desc_to_send.formatstr("%s at %s failed to send file(s) to %s",
										   get_mySubSystem()->getName(),
										   s->my_ip_str(),
										   s->get_sinful_peer());
				if(upload_error_desc) {
					error_desc_to_send.formatstr_cat(": %s",upload_error_desc);
				}
			}
			SendTransferAck(s,upload_success,try_again,hold_code,hold_subcode,
			                error_desc_to_send.Value());
		}
	} else {
		// go back to the state we were in before file transfer
		s->set_crypto_mode(socket_default_crypto);
	}

	// Now find out whether there was an error on the receiver's
	// (i.e. downloader's) end, such as failure to write data to disk.
	// If we have already failed to communicate with the receiver
	// for reasons that are likely to be transient network issues
	// (e.g. timeout writing), then ideally do_download_ack would be false,
	// and we will skip this step.
	if(do_download_ack) {
		GetTransferAck(s,download_success,try_again,hold_code,hold_subcode,
		               download_error_buf);
		if(!download_success) {
			rc = -1;
		}
	}

	if(rc != 0) {
		char const *receiver_ip_str = s->get_sinful_peer();
		if(!receiver_ip_str) {
			receiver_ip_str = "disconnected socket";
		}

		error_buf.formatstr("%s at %s failed to send file(s) to %s",
						  get_mySubSystem()->getName(),
						  s->my_ip_str(),receiver_ip_str);
		if(upload_error_desc) {
			error_buf.formatstr_cat(": %s",upload_error_desc);
		}

		if(!download_error_buf.IsEmpty()) {
			error_buf.formatstr_cat("; %s",download_error_buf.Value());
		}

		error_desc = error_buf.Value();
		if(!error_desc) {
			error_desc = "";
		}

		if(try_again) {
			dprintf(D_ALWAYS,"DoUpload: %s\n",error_desc);
		}
		else {
			dprintf(D_ALWAYS,"DoUpload: (Condor error code %d, subcode %d) %s\n",hold_code,hold_subcode,error_desc);
		}
	}

	// Record error information so it can be copied back through
	// the transfer status pipe and/or observed by the caller
	// of Upload().
	Info.success = rc == 0;
	Info.try_again = try_again;
	Info.hold_code = hold_code;
	Info.hold_subcode = hold_subcode;
	Info.error_desc = error_desc;

		// Log some tcp statistics about this transfer
	if (*total_bytes > 0) {
		int cluster = -1;
		int proc = -1;
		jobAd.LookupInteger(ATTR_CLUSTER_ID, cluster);
		jobAd.LookupInteger(ATTR_PROC_ID, proc);

		char *stats = s->get_statistics();
		std::string full_stats;
		formatstr(full_stats, "File Transfer Upload: JobId: %d.%d files: %d bytes: %lld seconds: %.2f dest: %s %s\n", 
			cluster, proc, numFiles, (long long)*total_bytes, (uploadEndTime - uploadStartTime), s->peer_ip_str(), (stats ? stats : ""));
		Info.tcp_stats = full_stats.c_str();
		dprintf(D_STATS, "%s", full_stats.c_str());
	}

	return rc;
}

void
FileTransfer::stopServer()
{
	abortActiveTransfer();
	if (TransKey) {
		// remove our key from the hash table
		if ( TranskeyTable ) {
			MyString key(TransKey);
			TranskeyTable->remove(key);
			if ( TranskeyTable->getNumElements() == 0 ) {
				// if hash table is empty, delete table as well
				delete TranskeyTable;
				TranskeyTable = NULL;
			}
		}		
		// and free the key as well
		free(TransKey);
		TransKey = NULL;
	}	
}

void
FileTransfer::abortActiveTransfer()
{
	if( ActiveTransferTid != -1 ) {
		ASSERT( daemonCore );
		dprintf(D_ALWAYS,"FileTransfer: killing active transfer %d\n",ActiveTransferTid);
		daemonCore->Kill_Thread(ActiveTransferTid);
		TransThreadTable->remove(ActiveTransferTid);
		ActiveTransferTid = -1;
	}
}

int
FileTransfer::Suspend()
{
	int result = TRUE;	// return TRUE if there currently is no thread

	if (ActiveTransferTid != -1 ) {
		ASSERT( daemonCore );
		result = daemonCore->Suspend_Thread(ActiveTransferTid);
	}

	return result;
}

int
FileTransfer::Continue()
{
	int result = TRUE;	// return TRUE if there currently is no thread

	if (ActiveTransferTid != -1 ) {
		ASSERT( daemonCore );
		result = daemonCore->Continue_Thread(ActiveTransferTid);
	}

	return result;
}


bool
FileTransfer::addOutputFile( const char* filename )
{
	if( ! OutputFiles ) {
		OutputFiles = new StringList;
		ASSERT(OutputFiles != NULL);
	}
	else if( OutputFiles->file_contains(filename) ) {
		return true;
	}
	OutputFiles->append( filename );
	return true;
}

bool
FileTransfer::addFileToExceptionList( const char* filename )
{
	if ( !ExceptionFiles ) {
		ExceptionFiles = new StringList;
		ASSERT ( NULL != ExceptionFiles );
	} else if ( ExceptionFiles->file_contains ( filename ) ) {
		return true;
	}
	ExceptionFiles->append ( filename );
	return true;
}

bool
FileTransfer::changeServer(const char* transkey, const char* transsock)
{

	if ( transkey ) {
		if (TransKey) {
			free(TransKey);
		}
		TransKey = strdup(transkey);
	}

	if ( transsock ) {
		if (TransSock) {
			free(TransSock);
		}
		TransSock = strdup(transsock);
	}

	return true;
}

int	
FileTransfer::setClientSocketTimeout(int timeout)
{
	int old_val = clientSockTimeout;
	clientSockTimeout = timeout;
	return old_val;
}

/* This function must be called by both peers */
void
FileTransfer::setPeerVersion( const char *peer_version )
{
	CondorVersionInfo vi( peer_version );

	setPeerVersion( vi );
}

/* This function must be called by both peers */
void
FileTransfer::setPeerVersion( const CondorVersionInfo &peer_version )
{
	if ( peer_version.built_since_version(6,7,7) ) {
		TransferFilePermissions = true;
	} else {
		TransferFilePermissions = false;
	}
		// The sender tells the receiver whether they're delegating or
		// copying credential files, so it's ok for them to have different
		// values for DelegateX509Credentials.
	if ( peer_version.built_since_version(6,7,19) &&
		 param_boolean( "DELEGATE_JOB_GSI_CREDENTIALS", true ) ) {
		DelegateX509Credentials = true;
	} else {
		DelegateX509Credentials = false;
	}
	if ( peer_version.built_since_version(6,7,20) ) {
		PeerDoesTransferAck = true;
	}
	else {
		PeerDoesTransferAck = false;
		dprintf(D_FULLDEBUG,
			"FileTransfer: peer (version %d.%d.%d) does not support "
			"transfer ack.  Will use older (unreliable) protocol.\n",
			peer_version.getMajorVer(),
			peer_version.getMinorVer(),
			peer_version.getSubMinorVer());
	}
	if( peer_version.built_since_version(6,9,5) ) {
		PeerDoesGoAhead = true;
	}
	else {
		PeerDoesGoAhead = false;
	}

	if( peer_version.built_since_version(7,5,4) ) {
		PeerUnderstandsMkdir = true;
	}
	else {
		PeerUnderstandsMkdir = false;
	}

	if ( peer_version.built_since_version(7,6,0) ) {
		TransferUserLog = false;
	} else {
		TransferUserLog = true;
	}

	if( peer_version.built_since_version(8,1,0) ) {
		PeerDoesXferInfo = true;
	}
	else {
		PeerDoesXferInfo = false;
	}

	PeerDoesReuseInfo = peer_version.built_since_version(8,9,4);
	PeerDoesS3Urls = peer_version.built_since_version(8,9,4);
}


// will take a filename and look it up in our internal catalog.  returns
// true if found and false if not.  also updates the parameters mod_time
// and filesize if they are not null.
bool FileTransfer::LookupInFileCatalog(const char *fname, time_t *mod_time, filesize_t *filesize) {
	CatalogEntry *entry = 0;
	MyString fn = fname;
	if (last_download_catalog->lookup(fn, entry) == 0) {
		// hashtable return code zero means found (!?!)

		// update if passed in
		if (mod_time) {
			*mod_time = entry->modification_time;
		}

		// update if passed in
		if (filesize) {
			*filesize = entry->filesize;
		}

		// we return true, as in 'yes, we found it'
		return true;
	} else {
		// not found
		return false;
	}
}


// normally, we want to build our catalog (last_download_catalog) on the Iwd
// that we already have.  but to support all modes of operation, we can also
// accept a different directory, and a different catalog to put them into.
//
// we take a pointer to this catalog pointer so we can correctly delete and
// recreate it with new. (i prefer this over pass by reference because it is
// explicit from the call site.)  by default, we simply set this pointer to
// our own *last_download_catalog.
//
// also, if spool_time is non-zero, set all modification times to that time.
// this is necessary for now, until we store a persistent copy of the catalog
// somewhere (job ad, or preferably in a file in the spool dir itself).
bool FileTransfer::BuildFileCatalog(time_t spool_time, const char* iwd, FileCatalogHashTable **catalog) {

	if (!iwd) {
		// by default, use the one in this intantiation
		iwd = Iwd;
	}

	if (!catalog) {
		// by default, use the one in this intantiation
		catalog = &last_download_catalog;
	}

	if (*catalog) {
		// iterate through catalog and free memory of CatalogEntry s.
		CatalogEntry *entry_pointer;

		(*catalog)->startIterations();
		while((*catalog)->iterate(entry_pointer)) {
			delete entry_pointer;
		}
		delete (*catalog);
	}

	// If we're going to stick a prime number in here, then let's make it
	// big enough that the chains are decent sized. Suppose you might
	// have 50,000 files. In the case for 997 buckets and even distribution, 
	// the chains would be ~50 entries long. Good enough.
	(*catalog) = new FileCatalogHashTable(hashFunction);

	/* If we've decided not to use a file catalog, then leave it empty. */
	if (m_use_file_catalog == false) {
		/* just leave the catalog empty. */
		return true;
	}

	// now, iterate the directory and put the relavant info into the catalog.
	// this currently excludes directories, and only stores the modification
	// time and filesize.  if you were to add hashes, signatures, etc., that
	// would go here.
	//
	// also note this information is not sufficient to notice a byte changing
	// in a file and the file being backdated, since neither modification time
	// nor filesize change in that case.
	//
	// furthermore, if spool_time was specified, we set filesize to -1 as a
	// flag for special behavior in ComputeFilesToSend and set all file
	// modification times to spool_time.  this essentially builds a catalog
	// that mimics old behavior.
	//
	// make sure this iteration is done as the actual owner of the directory,
	// as it may not be world-readable.
	// desired_priv_state indicates which priv state that is.
	Directory file_iterator(iwd, desired_priv_state);
	const char * f = NULL;
	while( (f = file_iterator.Next()) ) {
		if (!file_iterator.IsDirectory()) {
			CatalogEntry *tmpentry = 0;
			tmpentry = new CatalogEntry;
			if (spool_time) {
				// -1 for filesize is a special flag for old behavior.
				// when checking a file to see if it is new, if the filesize
				// is -1 then the file date must be newer (not just different)
				// than the stored modification date. (see ComputeFilesToSend)
				tmpentry->modification_time = spool_time;
				tmpentry->filesize = -1;
			} else {
				tmpentry->modification_time = file_iterator.GetModifyTime();
				tmpentry->filesize = file_iterator.GetFileSize();
			}
			MyString fn = f;
			(*catalog)->insert(fn, tmpentry);
		}
	}

	// always, succeed
	return true;
}

void FileTransfer::setSecuritySession(char const *session_id) {
	free(m_sec_session_id);
	m_sec_session_id = NULL;
	m_sec_session_id = session_id ? strdup(session_id) : NULL;
}

// Determines the third-party plugin needed for a file transfer.
// Looks at both source and destination to determine which one contains a URL,
// then extracts the method (ie. http, ftp) and uses it to lookup plugin.
MyString FileTransfer::DetermineFileTransferPlugin( CondorError &error, const char* source, const char* dest ) {

	char *URL = NULL;
	MyString plugin;

	// First, check the destination to see if it looks like a URL.
	// If not, source must be the URL.
	if( IsUrl( dest ) ) {
		URL = const_cast<char*>(dest);
		dprintf( D_FULLDEBUG, "FILETRANSFER: using destination to determine "
			"plugin type: %s\n", dest );
	}
	else {
		URL = const_cast<char*>(source);
		dprintf( D_FULLDEBUG, "FILETRANSFER: using source to determine "
			"plugin type: %s\n", source );
	}

	// Find the type of transfer
	auto method = getURLType( URL, true );

	// Hashtable returns zero if found.
	if ( plugin_table->lookup( method, plugin ) ) {
		// no plugin for this type!!!
		error.pushf( "FILETRANSFER", 1, "FILETRANSFER: plugin for type %s not found!", method.c_str() );
		dprintf ( D_FULLDEBUG, "FILETRANSFER: plugin for type %s not found!\n", method.c_str() );
		return NULL;
	}

	return plugin;
}


int FileTransfer::InvokeFileTransferPlugin(CondorError &e, const char* source, const char* dest, ClassAd* plugin_stats, const char* proxy_filename) {

	if (plugin_table == NULL) {
		dprintf(D_FULLDEBUG, "FILETRANSFER: No plugin table defined! (request was %s)\n", source);
		e.pushf("FILETRANSFER", 1, "No plugin table defined (request was %s)", source);
		return GET_FILE_PLUGIN_FAILED;
	}


	// detect which plugin to invoke
	char *URL = NULL;

	// first, check the dest to see if it looks like a URL.  if not, source must
	// be the URL.
	if(IsUrl(dest)) {
		URL = const_cast<char*>(dest);
		dprintf(D_FULLDEBUG, "FILETRANSFER: using destination to determine plugin type: %s\n", dest);
	} else {
		URL = const_cast<char*>(source);
		dprintf(D_FULLDEBUG, "FILETRANSFER: using source to determine plugin type: %s\n", source);
	}

	// find the type of transfer
	const char* colon = strchr(URL, ':');

	if (!colon) {
		// in theory, this should never happen -- then sending side should only
		// send URLS after having checked this.  however, trust but verify.
		e.pushf("FILETRANSFER", 1, "Specified URL does not contain a ':' (%s)", URL);
		return GET_FILE_PLUGIN_FAILED;
	}

	// Find the type of transfer
	auto method = getURLType( URL, true );

	// look up the method in our hash table
	MyString plugin;

	// hashtable returns zero if found.
	if (plugin_table->lookup(method.c_str(), plugin)) {
		// no plugin for this type!!!
		e.pushf("FILETRANSFER", 1, "FILETRANSFER: plugin for type %s not found!", method.c_str());
		dprintf (D_FULLDEBUG, "FILETRANSFER: plugin for type %s not found!\n", method.c_str());
		return GET_FILE_PLUGIN_FAILED;
	}

	
/*	
	// TODO: check validity of plugin name.  should always be an absolute path
	if (absolute_path_check() ) {
		dprintf(D_ALWAYS, "FILETRANSFER: NOT invoking malformed plugin named \"%s\"\n", plugin.Value());
		FAIL();
	}
*/

	// prepare environment for the plugin
	Env plugin_env;

	// start with this environment
	plugin_env.Import();

	// Add any credential directory.
	if (!m_cred_dir.empty()) {
		plugin_env.SetEnv( "_CONDOR_CREDS", m_cred_dir.c_str() );
	}

	// add x509UserProxy if it's defined
	if (proxy_filename && *proxy_filename) {
		plugin_env.SetEnv("X509_USER_PROXY",proxy_filename);
		dprintf(D_FULLDEBUG, "FILETRANSFER: setting X509_USER_PROXY env to %s\n", proxy_filename);
	}

	if (!m_job_ad.empty()) {
		plugin_env.SetEnv("_CONDOR_JOB_AD", m_job_ad.c_str());
	}
	if (!m_machine_ad.empty()) {
		plugin_env.SetEnv("_CONDOR_MACHINE_AD", m_machine_ad.c_str());
	}
	dprintf(D_FULLDEBUG, "FILETRANSFER: setting runtime ads to %s and %s\n", m_job_ad.c_str(), m_machine_ad.c_str());

	// prepare args for the plugin
	ArgList plugin_args;
	plugin_args.AppendArg(plugin.Value());
	plugin_args.AppendArg(source);
	plugin_args.AppendArg(dest);
	dprintf(D_FULLDEBUG, "FILETRANSFER: invoking: %s %s %s\n", plugin.Value(), source, dest);

	// determine if we want to run the plugin with root priv (if available).
	// if so, drop_privs should be false.  the default is to drop privs.
	bool drop_privs = !param_boolean("RUN_FILETRANSFER_PLUGINS_WITH_ROOT", false);

	// Invoke the plugin
	FILE* plugin_pipe = my_popen(plugin_args, "r", FALSE, &plugin_env, drop_privs);

	// Capture stdout from the plugin and dump it to the stats file
	char single_stat[1024];
	while( fgets( single_stat, sizeof( single_stat ), plugin_pipe ) ) {
		if( !plugin_stats->Insert( single_stat ) ) {
			dprintf (D_ALWAYS, "FILETRANSFER: error importing statistic %s\n", single_stat);
		}
	}

	// Close the plugin
	int plugin_status = my_pclose(plugin_pipe);
	dprintf (D_ALWAYS, "FILETRANSFER: plugin %s returned %i\n", plugin.Value(), plugin_status);

	// there is a unique issue when invoking plugins as root where shared
	// libraries defined as relative to $ORIGIN in the RUNPATH will not
	// be loaded for security reasons.  in this case the dynamic loader
	// exits with 127 before even calling main() in the plugin.
	//
	// if we suspect this is the case, let's print a hint since it's
	// otherwise very difficult to understand what is happening and why
	// this failed.
	if (!drop_privs && plugin_status == 32512) {
		dprintf (D_ALWAYS, "FILETRANSFER: ERROR!  You are invoking plugins as root because "
			"you have RUN_FILETRANSFER_PLUGINS_WITH_ROOT set to TRUE.  However, some of "
			"the shared libraries in your plugin are likely paths that are relative to "
			"$ORIGIN, and then dynamic library loader refuses to load those for security "
			"reasons.  Run 'ldd' on your plugin and move needed libraries to a system "
			"location controlled by root. Good luck!\n");
	}

	// any non-zero exit from plugin indicates error.  this function needs to
	// return -1 on error, or zero otherwise, so map plugin_status to the
	// proper value.

	if (plugin_status != 0) {
		std::string errorMessage;
		std::string transferUrl;
		plugin_stats->LookupString("TransferError", errorMessage);
		plugin_stats->LookupString("TransferUrl", transferUrl);
		e.pushf("FILETRANSFER", 1, "non-zero exit (%i) from %s. Error: %s (%s)", 
			plugin_status, plugin.Value(), errorMessage.c_str(), transferUrl.c_str());
		return GET_FILE_PLUGIN_FAILED;
	}

	return 0;
}

// Similar to FileTransfer::InvokeFileTransferPlugin, modified to transfer 
// multiple files in a single plugin invocation.
// Returns 0 on success, error code >= 1 on failure.
int FileTransfer::InvokeMultipleFileTransferPlugin( CondorError &e,
			const std::string &plugin_path, const std::string &transfer_files_string,
			const char* proxy_filename, bool do_upload,
			std::vector<std::unique_ptr<ClassAd>> *result_ads ) {

	ArgList plugin_args;
	CondorClassAdFileIterator adFileIter;
	FILE* input_file;
	FILE* output_file;
	std::string input_filename;
	std::string output_filename;
	std::string plugin_name;

	if ( plugin_table == NULL ) {
		dprintf( D_FULLDEBUG, "FILETRANSFER: No plugin table defined! "
				"(requesting multi-file transfer)\n" );
		e.pushf( "FILETRANSFER", 1, "No plugin table defined (requesting "
				"multi-file transfer)" );
		return GET_FILE_PLUGIN_FAILED;
	}

	// Prepare environment for the plugin
	Env plugin_env;
	plugin_env.Import();

	// Add any credential directory.
	if (!m_cred_dir.empty()) {
		plugin_env.SetEnv( "_CONDOR_CREDS", m_cred_dir.c_str() );
	}

	// Add x509UserProxy if it's defined
	if ( proxy_filename && *proxy_filename ) {
		plugin_env.SetEnv( "X509_USER_PROXY",proxy_filename );
		dprintf( D_FULLDEBUG, "FILETRANSFER: setting X509_USER_PROXY env to %s\n",
				proxy_filename );
	}
	if (!m_job_ad.empty()) {
		plugin_env.SetEnv("_CONDOR_JOB_AD", m_job_ad.c_str());
	}
	if (!m_machine_ad.empty()) {
		plugin_env.SetEnv("_CONDOR_MACHINE_AD", m_machine_ad.c_str());
	}
	dprintf(D_FULLDEBUG, "FILETRANSFER: setting runtime ads to %s and %s\n", m_job_ad.c_str(), m_machine_ad.c_str());


	// Determine if we want to run the plugin with root priv (if available).
	// If so, drop_privs should be false.  the default is to drop privs.
	bool drop_privs = !param_boolean( "RUN_FILETRANSFER_PLUGINS_WITH_ROOT", false );
	if (plugins_from_job.find(plugin_path) != plugins_from_job.end()) { drop_privs = true; }

	// Lookup the initial working directory
	std::string iwd;
	if ( jobAd.LookupString( ATTR_JOB_IWD, iwd ) != 1) {
		dprintf( D_ALWAYS, "FILETRANSFER InvokeMultipleFileTransferPlugin: "
					"Job Ad did not have an IWD! Aborting.\n" );
		return 1;
	}

	// Create an input file for the plugin.
	// Input file consists of the transfer_files_string data (list of classads)
	// which we'll save to a temporary file in the working directory.
	plugin_name = plugin_path.substr( plugin_path.find_last_of("/\\") + 1 );
	input_filename = iwd + "/." + plugin_name + ".in";
	input_file = safe_fopen_wrapper( input_filename.c_str(), "w" );
	if (input_file == nullptr) {
		dprintf( D_ALWAYS, "FILETRANSFER InvokeMultipleFileTransferPlugin: "
					"Could not open %s for writing, aborting\n", input_filename.c_str());
		return 1;
	}
	fputs( transfer_files_string.c_str(), input_file );
	fclose( input_file );

	// Prepare args for the plugin
	output_filename = iwd + "/." + plugin_name + ".out";
	plugin_args.AppendArg( plugin_path.c_str() );
	plugin_args.AppendArg( "-infile" );
	plugin_args.AppendArg( input_filename.c_str() );
	plugin_args.AppendArg( "-outfile" );
	plugin_args.AppendArg( output_filename.c_str() );
	if (do_upload) {
		plugin_args.AppendArg( "-upload" );
	}

	// Invoke the plugin
	dprintf( D_ALWAYS, "FILETRANSFER: invoking: %s \n", plugin_path.c_str() );
	FILE* plugin_pipe = my_popen( plugin_args, "r", FALSE, &plugin_env, drop_privs );
	if( !plugin_pipe ) {
		dprintf ( D_ALWAYS, "FILETRANSFER: failed to invoke multifile transfer "
			"plugin %s, aborting\n", plugin_path.c_str() );
		return GET_FILE_PLUGIN_FAILED;
	}
	int plugin_status = my_pclose( plugin_pipe );
	if( plugin_status >= 0 ) {
		dprintf ( D_ALWAYS, "FILETRANSFER: plugin %s returned %i (%s)\n", 
			plugin_path.c_str(), plugin_status, strerror( plugin_status ) );
	}
	else {
		dprintf ( D_ALWAYS, "FILETRANSFER: plugin %s returned a negative status "
			"code (%d). Something is very wrong, aborting.\n", plugin_path.c_str(), 
			plugin_status );
		return GET_FILE_PLUGIN_FAILED;
	}

	// there is a unique issue when invoking plugins as root where shared
	// libraries defined as relative to $ORIGIN in the RUNPATH will not
	// be loaded for security reasons.  in this case the dynamic loader
	// exits with 127 before even calling main() in the plugin.
	//
	// if we suspect this is the case, let's print a hint since it's
	// otherwise very difficult to understand what is happening and why
	// this failed.
	if ( !drop_privs && plugin_status == 32512 ) {
		dprintf (D_ALWAYS, "FILETRANSFER: ERROR!  You are invoking plugins as root because "
			"you have RUN_FILETRANSFER_PLUGINS_WITH_ROOT set to TRUE.  However, some of "
			"the shared libraries in your plugin are likely paths that are relative to "
			"$ORIGIN, and then dynamic library loader refuses to load those for security "
			"reasons.  Run 'ldd' on your plugin and move needed libraries to a system "
			"location controlled by root. Good luck!\n");
	}

	// Output stats regardless of success or failure
	output_file = safe_fopen_wrapper( output_filename.c_str(), "r" );
	if ( output_file == NULL ) {
		dprintf( D_ALWAYS, "FILETRANSFER: Unable to open curl_plugin output file "
			"%s.\n", input_filename.c_str() );
		return GET_FILE_PLUGIN_FAILED;
	}
	if ( !adFileIter.begin( output_file, false, CondorClassAdFileParseHelper::Parse_new )) {
		dprintf( D_ALWAYS, "FILETRANSFER: Failed to iterate over file transfer output.\n" );
		return GET_FILE_PLUGIN_FAILED;
	}
	else {
		// Iterate over the classads in the file, and output each one
		// to our transfer_history log file.
		ClassAd this_file_stats_ad;
		while ( adFileIter.next( this_file_stats_ad ) > 0 ) {

			OutputFileTransferStats( this_file_stats_ad );

			// If this classad represents a failed transfer, produce an error
			bool transfer_success;
			this_file_stats_ad.LookupBool( "TransferSuccess", transfer_success );
			if ( !transfer_success ) {
				std::string error_message;
				std::string transfer_url;
				this_file_stats_ad.LookupString( "TransferError", error_message );
				this_file_stats_ad.LookupString( "TransferUrl", transfer_url );
				e.pushf( "FILETRANSFER", 1, "non-zero exit (%i) from %s. Error: %s (%s)", 
					plugin_status, plugin_path.c_str(), error_message.c_str(), transfer_url.c_str() );
			}

			if (result_ads) {
				result_ads->emplace_back(new ClassAd());
				result_ads->back()->CopyFrom(this_file_stats_ad);
			}
		}
	}
	fclose(output_file);

	if ( plugin_status != 0 ) {
		return GET_FILE_PLUGIN_FAILED;
	}

	return 0;
}

int FileTransfer::OutputFileTransferStats( ClassAd &stats ) {

	// this log is meant to be kept in the condor LOG directory, so switch to
	// the correct priv state to manipulate files in that dir.
	priv_state saved_priv = set_condor_priv();

	// Read name of statistics file from params
	std::string stats_file_path;
	if (!param( stats_file_path, "FILE_TRANSFER_STATS_LOG" )) {
		return 1;
	}

	// First, check for an existing statistics file. 
	struct stat stats_file_buf;
	int rc = stat( stats_file_path.c_str(), &stats_file_buf );
	if( rc == 0 ) {
		// If it already exists and is larger than 5 Mb, copy the contents 
		// to a .old file. 
		if( stats_file_buf.st_size > 5000000 ) {
			std::string stats_file_old_path = stats_file_path;
			stats_file_old_path += ".old";
			// TODO: Add a lock to prevent two starters from rotating the log 
			// at the same time.
			if (rotate_file(stats_file_path.c_str(), stats_file_old_path.c_str()) != 0) {
				dprintf(D_ALWAYS, "FileTransfer failed to rotate %s to %s\n", stats_file_path.c_str(), stats_file_old_path.c_str());
			}
		}
	}

	// Add some new job-related statistics that were not available from
	// the file transfer plugin.
	int cluster_id;    
	jobAd.LookupInteger( ATTR_CLUSTER_ID, cluster_id );
	stats.Assign( "JobClusterId", cluster_id );

	int proc_id;    
	jobAd.LookupInteger( ATTR_PROC_ID, proc_id );
	stats.Assign( "JobProcId", proc_id );

	std::string owner;
	jobAd.LookupString( ATTR_OWNER, owner );
	stats.Assign( "JobOwner", owner );

	// Output statistics to file
	MyString stats_string;
	MyString stats_output = "***\n";
	sPrintAd( stats_string, stats );
	stats_output += stats_string;

	FILE* stats_file = safe_fopen_wrapper( stats_file_path.c_str(), "a" );
	if( !stats_file ) {
		dprintf( D_ALWAYS, "FILETRANSFER: failed to open statistics file %s with"
			" error %d (%s)\n", stats_file_path.c_str(), errno, strerror(errno) );
	}
	else {
		int stats_file_fd = fileno( stats_file );
		if ( write( stats_file_fd, stats_output.Value(), stats_output.length() ) == -1 ) {
			dprintf( D_ALWAYS, "FILETRANSFER: failed to write to statistics file %s with"
				" error %d (%s)\n", stats_file_path.c_str(), errno, strerror(errno) );
		}
		fclose( stats_file );
	}
	
	// back to previous priv state
	set_priv(saved_priv);

	return 0;
}

MyString FileTransfer::GetSupportedMethods() {
	MyString method_list;

	// iterate plugin_table if it existssrc
	if (plugin_table) {
		MyString junk;
		MyString method;

		plugin_table->startIterations();
		while(plugin_table->iterate(method, junk)) {
			// add comma if needed
			if (!(method_list.IsEmpty())) {
				method_list += ",";
			}
			method_list += method;
		}
		if( I_support_S3 ) {
			// method_list must contain at least "https".
			method_list += ",s3";
		}
	}
	return method_list;
}

int FileTransfer::InitializeJobPlugins(const ClassAd &job, CondorError &e, StringList &infiles)
{
	if ( ! I_support_filetransfer_plugins || ! plugin_table) {
		return 0;
	}

	std::string job_plugins;
	if ( ! job.LookupString(ATTR_TRANSFER_PLUGINS, job_plugins)) {
		return 0;
	}

	StringTokenIterator plugins(job_plugins, 100, ";");
	for (const char * plug = plugins.first(); plug != NULL; plug = plugins.next()) {
		const char * colon = strchr(plug, '=');
		if (colon) {
			MyString methods; methods.set(plug, colon - plug);

			// add the plugin to the front of the input files list
			MyString plugin_path(colon + 1);
			plugin_path.trim();
			if (! infiles.file_contains(plugin_path.c_str())) {
				infiles.insert(plugin_path.c_str());
			}
			// use the file basename as the plugin name, so that when we invoke it
			// we will invoke the copy in the input sandbox
			MyString plugin(condor_basename(plugin_path.c_str()));

			InsertPluginMappings(methods, plugin);
			plugins_multifile_support[plugin] = true;
			plugins_from_job[plugin.c_str()] = true;
			multifile_plugins_enabled = true;
			// add the plugin to the transfer list
		} else {
			dprintf(D_ALWAYS, "FILETRANSFER: no '=' in " ATTR_TRANSFER_PLUGINS " definition '%s'\n", plug);
			e.pushf("FILETRANSFER", 1, "no '=' in " ATTR_TRANSFER_PLUGINS" definition '%s'", plug);
		}
	}

	return 0;
}


int FileTransfer::InitializePlugins(CondorError &e) {

	// see if this is explicitly disabled
	if (!param_boolean("ENABLE_URL_TRANSFERS", true)) {
		I_support_filetransfer_plugins = false;
		return 0;
	}

	char* plugin_list_string = param("FILETRANSFER_PLUGINS");
	if (!plugin_list_string) {
		I_support_filetransfer_plugins = false;
		return 0;
	}

	// See if multifile transfer plugins are enabled
	if (param_boolean("ENABLE_MULTIFILE_TRANSFER_PLUGINS", true)) {
		multifile_plugins_enabled = true;
	}

	// plugin_table is a member variable
	plugin_table = new PluginHashTable(hashFunction);

	StringList plugin_list (plugin_list_string);
	plugin_list.rewind();

	char *p;
	while ((p = plugin_list.next())) {
		// TODO: plugin must be an absolute path (win and unix)
		SetPluginMappings( e, p );

		// Now verify that the plugin supports at least one transfer method.
		MyString methods = GetSupportedMethods();
		if (!methods.IsEmpty()) {
			// we support at least one plugin type
			I_support_filetransfer_plugins = true;
		} else {
			dprintf(D_ALWAYS, "FILETRANSFER: failed to add plugin \"%s\" because: %s\n", p, e.getFullText().c_str());
			e.pushf("FILETRANSFER", 1, "\"%s -classad\" does not support any methods, ignoring", p);
		}
	}

	// If we have an https plug-in, this version of HTCondor also supports S3.
	MyString method, junk;
	plugin_table->startIterations();
	while( plugin_table->iterate( method, junk ) ) {
		if( method == "https" ) {
			I_support_S3 = true;
		}
	}

	free(plugin_list_string);
	return 0;
}


void
FileTransfer::SetPluginMappings( CondorError &e, const char* path )
{
    FILE* fp;
    const char *args[] = { path, "-classad", NULL};
    char buf[1024];

        // first, try to execute the given path with a "-classad"
        // option, and grab the output as a ClassAd
    fp = my_popenv( args, "r", FALSE );

    if( ! fp ) {
        dprintf( D_ALWAYS, "FILETRANSFER: Failed to execute %s, ignoring\n", path );
		e.pushf("FILETRANSFER", 1, "Failed to execute %s, ignoring", path );
        return;
    }
    ClassAd* ad = new ClassAd;
    bool read_something = false;
    while( fgets(buf, 1024, fp) ) {
        read_something = true;
        if( ! ad->Insert(buf) ) {
            dprintf( D_ALWAYS, "FILETRANSFER: Failed to insert \"%s\" into ClassAd, "
                     "ignoring invalid plugin\n", buf );
            delete( ad );
            pclose( fp );
			e.pushf("FILETRANSFER", 1, "Received invalid input '%s', ignoring", buf );
            return;
        }
    }
    my_pclose( fp );
    if( ! read_something ) {
        dprintf( D_ALWAYS,
                 "FILETRANSFER: \"%s -classad\" did not produce any output, ignoring\n",
                 path );
        delete( ad );
		e.pushf("FILETRANSFER", 1, "\"%s -classad\" did not produce any output, ignoring", path );
        return;
    }

	// TODO: verify that plugin type is FileTransfer
	// e.pushf("FILETRANSFER", 1, "\"%s -classad\" is not plugin type FileTransfer, ignoring", path );

	// extract the info we care about
	char* methods = NULL;
	bool this_plugin_supports_multifile = false;
	if ( ad->LookupBool( "MultipleFileSupport", this_plugin_supports_multifile ) ) {
		plugins_multifile_support[path] = this_plugin_supports_multifile;
	}
	
	// Before adding mappings, make sure that if multifile plugins are disabled,
	// this is not a multifile plugin.
	if ( multifile_plugins_enabled || !this_plugin_supports_multifile ) {
		if (ad->LookupString( "SupportedMethods", &methods)) {
			// free the memory, return a MyString
			MyString m = methods;
			free(methods);
			InsertPluginMappings( m, path );
		}
	}

	delete( ad );
	return;
}


void
FileTransfer::InsertPluginMappings(MyString methods, MyString p)
{
	StringList method_list(methods.Value());

	char* m;

	method_list.rewind();
	while((m = method_list.next())) {
		dprintf(D_FULLDEBUG, "FILETRANSFER: protocol \"%s\" handled by \"%s\"\n", m, p.Value());
		if ( plugin_table->insert(m, p, true) != 0 ) {
			dprintf(D_FULLDEBUG, "FILETRANSFER: error adding protocol \"%s\" to plugin table, ignoring\n", m);
		}
	}
}

bool
FileTransfer::ExpandFileTransferList( StringList *input_list, FileTransferList &expanded_list )
{
	bool rc = true;

	if( !input_list ) {
		return true;
	}

	// if this exists and is in the list do it first
	if (X509UserProxy && input_list->contains(X509UserProxy)) {
		if( !ExpandFileTransferList( X509UserProxy, "", Iwd, -1, expanded_list ) ) {
			rc = false;
		}
	}

	// then process the rest of the list
	input_list->rewind();
	char const *path;
	while ( (path=input_list->next()) != NULL ) {
		// skip the proxy if it's defined -- we dealt with it above.
		// everything else gets expanded.  this if would short-circuit
		// true if X509UserProxy is not defined, but i made it explicit.
		if(!X509UserProxy || (X509UserProxy && strcmp(path, X509UserProxy) != 0)) {
			if( !ExpandFileTransferList( path, "", Iwd, -1, expanded_list ) ) {
				rc = false;
			}
		}
	}
	return rc;
}

bool
FileTransfer::ExpandFileTransferList( char const *src_path, char const *dest_dir, char const *iwd, int max_depth, FileTransferList &expanded_list )
{
	ASSERT( src_path );
	ASSERT( dest_dir );
	ASSERT( iwd );

		// To simplify error handling, we always want to include an
		// entry for the specified path, except two cases which are
		// handled later on by removing the entry we add here.
	expanded_list.push_back( FileTransferItem() );
	FileTransferItem &file_xfer_item = expanded_list.back();

	file_xfer_item.setSrcName( src_path );
	file_xfer_item.setDestDir( dest_dir );

	if( IsUrl(src_path) ) {
		return true;
	}

	std::string full_src_path;
	if( !fullpath( src_path ) ) {
		full_src_path = iwd;
		if( full_src_path.length() > 0 ) {
			full_src_path += DIR_DELIM_CHAR;
		}
	}
	full_src_path += src_path;

	StatInfo st( full_src_path.c_str() );

	if( st.Error() != 0 ) {
		return false;
	}

		// TODO: somehow deal with cross-platform file modes.
		// For now, ignore modes on windows.
#ifndef WIN32
	file_xfer_item.setFileMode( (condor_mode_t)st.GetMode() );
#endif

	size_t srclen = file_xfer_item.srcName().length();
	bool trailing_slash = srclen > 0 && IS_ANY_DIR_DELIM_CHAR(src_path[srclen-1]);

	file_xfer_item.setSymlink( st.IsSymlink() );
	file_xfer_item.setDomainSocket( st.IsDomainSocket() );
	file_xfer_item.setDirectory( st.IsDirectory() );

		// If this file is a domain socket, we don't want to send it but it's
		// also not an error. Remove the entry from the list and return true.
	if( file_xfer_item.isDomainSocket() ) {
		dprintf(D_FULLDEBUG, "FILETRANSFER: File %s is a domain socket, excluding "
			"from transfer list\n", full_src_path.c_str() );
		expanded_list.pop_back();
		return true;
	}

	if( !file_xfer_item.isDirectory() ) {
		file_xfer_item.setFileSize(st.GetFileSize());
		return true;
	}

		// do not follow symlinks to directories unless we are just
		// fetching the contents of the directory
	if( !trailing_slash && file_xfer_item.isSymlink() ) {
			// leave it up to our caller to decide if this is an error
		return true;
	}

	if( max_depth == 0 ) {
			// do not scan the contents of the directory
		return true; // this is not considered an error
	}
	if( max_depth > 0 ) {
		max_depth--;
	}

	std::string dest_dir_buf;
	if( trailing_slash ) {
			// If there is a trailing slash and we didn't hit an error,
			// then we only want to transfer the contents of the
			// directory into dest_dir.  We don't want to transfer the
			// directory.
		expanded_list.pop_back();
			// NOTE: do NOT reference file_xfer_item from here on!
	}
	else {
		dest_dir_buf = dest_dir;
		if( dest_dir_buf.length() > 0 ) {
			dest_dir_buf += DIR_DELIM_CHAR;
		}
		dest_dir_buf += condor_basename(src_path);
		dest_dir = dest_dir_buf.c_str();
	}

	Directory dir( &st );
	dir.Rewind();

	bool rc = true;
	char const *file_in_dir;
	while( (file_in_dir=dir.Next()) != NULL ) {

		std::string file_full_path = src_path;
		if( !trailing_slash ) {
			file_full_path += DIR_DELIM_CHAR;
		}
		file_full_path += file_in_dir;

		if( !ExpandFileTransferList( file_full_path.c_str(), dest_dir, iwd, max_depth, expanded_list ) ) {
			rc = false;
		}
	}

	return rc;
}

bool
FileTransfer::ExpandInputFileList( char const *input_list, char const *iwd, MyString &expanded_list, MyString &error_msg )
{
	bool result = true;
	StringList input_files(input_list,",");
	input_files.rewind();
	char const *path;
	while( (path=input_files.next()) != NULL ) {
		bool needs_expansion = false;

		size_t pathlen = strlen(path);
		bool trailing_slash = pathlen > 0 && path[pathlen-1] == DIR_DELIM_CHAR;

		if( trailing_slash && !IsUrl(path) ) {
			needs_expansion = true;
		}

		if( !needs_expansion ) {
				// We intentionally avoid the need to stat any of the entries
				// that don't need to be expanded in case stat is expensive.
			expanded_list.append_to_list(path,",");
		}
		else {
			FileTransferList filelist;
			if( !ExpandFileTransferList( path, "", iwd, 1, filelist ) ) {
				error_msg.formatstr_cat("Failed to expand '%s' in transfer input file list. ",path);
				result = false;
			}
			FileTransferList::iterator filelist_it;
			for( filelist_it = filelist.begin();
				 filelist_it != filelist.end();
				 filelist_it++ )
			{
				expanded_list.append_to_list(filelist_it->srcName(),",");
			}
		}
	}
	return result;
}

bool
FileTransfer::ExpandInputFileList( ClassAd *job, MyString &error_msg ) {

		// If we are spooling input files, input directories that end
		// in a slash must be expanded to list their contents so that
		// when the schedd rewrites ATTR_TRANSFER_INPUT_FILES, it can
		// correctly represent the contents of the spool, without
		// requiring the schedd to iterate through the spool directory
		// to see what files are there.  Alternatively, when spooling
		// input, we could ignore trailing slashes and preserve the
		// source directory in the spool, with its contents inside of
		// it.  However, this could lead to name collisions if
		// something else in the spool has the same name as the directory.
		//
		// Ideally, we would just leave this up to the file transfer
		// object during the actual transfer, similarly to how
		// ATTR_SPOOLED_OUTPUT_FILES works.  However, given the way
		// the job state is managed, that is not an easy task.  If the
		// job submission client (e.g. condor_submit) were to rewrite
		// the file list after transferring the files, it would need
		// to keep the job on hold until it reconnects to the schedd
		// to modify the job, rather than having the schedd modify and
		// release the job in the reaper of the spooling operation.
		// So unless we rewire that, we need to pre-process the input
		// file list during the job submission, before spooling files.

	std::string input_files;
	if( job->LookupString(ATTR_TRANSFER_INPUT_FILES,input_files) != 1 )
	{
		return true; // nothing to do
	}

	std::string iwd;
	if( job->LookupString(ATTR_JOB_IWD,iwd) != 1 )
	{
		error_msg.formatstr("Failed to expand transfer input list because no IWD found in job ad.");
		return false;
	}

	MyString expanded_list;
	if( !FileTransfer::ExpandInputFileList(input_files.c_str(),iwd.c_str(),expanded_list,error_msg) )
	{
		return false;
	}

	if( expanded_list != input_files ) {
		dprintf(D_FULLDEBUG,"Expanded input file list: %s\n",expanded_list.Value());
		job->Assign(ATTR_TRANSFER_INPUT_FILES,expanded_list.Value());
	}
	return true;
}

bool
FileTransfer::LegalPathInSandbox(char const *path,char const *sandbox) {
	bool result = true;

	ASSERT( path );
	ASSERT( sandbox );

	MyString buf = path;
	canonicalize_dir_delimiters( buf );
	path = buf.Value();

	if( fullpath(path) ) {
		return false;
	}

		// now we want to make sure there are no references to ".."
	char *pathbuf = strdup( path );
	char *dirbuf = strdup( path );
	char *filebuf = strdup( path );

	ASSERT( pathbuf );
	ASSERT( dirbuf );
	ASSERT( filebuf );

	bool more = true;
	while( more ) {
		MyString fullpath;
		fullpath.formatstr("%s%c%s",sandbox,DIR_DELIM_CHAR,pathbuf);

		more = filename_split( pathbuf, dirbuf, filebuf );

		if( strcmp(filebuf,"..") == 0 ) {
			result = false;
			break;
		}

		strcpy(pathbuf,dirbuf);
	}

	free( pathbuf );
	free( dirbuf );
	free( filebuf );

	return result;
}

void FileTransfer::FileTransferInfo::addSpooledFile(char const *name_in_spool)
{
	spooled_files.append_to_list(name_in_spool);
}


time_t
GetDesiredDelegatedJobCredentialExpiration(ClassAd *job)
{
	if ( !param_boolean( "DELEGATE_JOB_GSI_CREDENTIALS", true ) ) {
		return 0;
	}

	time_t expiration_time = 0;
	int lifetime = -1;
	if( job ) {
		job->LookupInteger(ATTR_DELEGATE_JOB_GSI_CREDENTIALS_LIFETIME,lifetime);
	}
	if( lifetime < 0 ) {
		lifetime = param_integer("DELEGATE_JOB_GSI_CREDENTIALS_LIFETIME", 3600*24, 0);
	}
	if( lifetime ) {
		expiration_time = time(NULL) + lifetime;
	}
	return expiration_time;
}

time_t
GetDelegatedProxyRenewalTime(time_t expiration_time)
{
	if( expiration_time == 0 ) {
		return 0;
	}
	if ( !param_boolean( "DELEGATE_JOB_GSI_CREDENTIALS", true ) ) {
		return 0;
	}

	time_t now = time(NULL);
	time_t lifetime = expiration_time - now;
	double lifetime_frac = param_double( "DELEGATE_JOB_GSI_CREDENTIALS_REFRESH", 0.25,0,1);
	return now + (time_t)floor(lifetime*lifetime_frac);
}

void
GetDelegatedProxyRenewalTime(ClassAd *jobAd)
{
	GetDelegatedProxyRenewalTime(GetDesiredDelegatedJobCredentialExpiration(jobAd));
}

bool
FileTransfer::outputFileIsSpooled(char const *fname) {
	if(fname) {
		if( !fullpath(fname) ) {
			if( Iwd && SpoolSpace && strcmp(Iwd,SpoolSpace)==0 ) {
				return true;
			}
		}
		else if( SpoolSpace && strncmp(fname,SpoolSpace,strlen(SpoolSpace))==0 ) {
			return true;
		}
	}
	return false;
}

ClassAd*
FileTransfer::GetJobAd() {
	return &jobAd;
}

void
FileTransfer::setMaxUploadBytes(filesize_t _MaxUploadBytes)
{
	MaxUploadBytes = _MaxUploadBytes;
}

void
FileTransfer::setMaxDownloadBytes(filesize_t _MaxDownloadBytes)
{
	MaxDownloadBytes = _MaxDownloadBytes;
}
