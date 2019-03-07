#include "condor_common.h"
#include "condor_classad.h"
#include "../condor_utils/file_transfer_stats.h"
#include "multifile_curl_plugin.h"
#include "utc_time.h"
#include <iostream>
#include <chrono>
#include <thread>

#define MAX_RETRY_ATTEMPTS 20

namespace {

bool
ShouldRetryTransfer(int rval) {
    switch (rval) {
        case CURLE_COULDNT_CONNECT:
        case CURLE_PARTIAL_FILE:
        case CURLE_READ_ERROR:
        case CURLE_OPERATION_TIMEDOUT:
        case CURLE_SEND_ERROR:
        case CURLE_RECV_ERROR:
            return true;
        default:
            return false;
    };
}

extern "C"
size_t
CurlReadCallback(char *buffer, size_t size, size_t nitems, void *userdata) {
    if (userdata == nullptr) {
        return size*nitems;
    }
    return fread(buffer, size, nitems, static_cast<FILE*>(userdata));
}


extern "C"
size_t
CurlWriteCallback(char *buffer, size_t size, size_t nitems, void *userdata) {
    if (userdata == nullptr) {
        return size*nitems;
    }
    return fwrite(buffer, size, nitems, static_cast<FILE*>(userdata));
}

}

MultiFileCurlPlugin::MultiFileCurlPlugin( bool diagnostic ) :
    _diagnostic ( diagnostic )
{}

MultiFileCurlPlugin::~MultiFileCurlPlugin() {
    curl_easy_cleanup( _handle );
    curl_global_cleanup();
}

int
MultiFileCurlPlugin::InitializeCurl() {
    // Initialize win32 + SSL socket libraries.
    // Do not initialize these separately! Doing so causes https:// transfers
    // to segfault.
    int init = curl_global_init( CURL_GLOBAL_DEFAULT );
    if ( init != 0 ) {
        fprintf( stderr, "Error: curl_plugin initialization failed with error code %d\n", init );
    }
    if ( ( _handle = curl_easy_init() ) == NULL ) {
        fprintf( stderr, "Error: failed to initialize MultiFileCurlPlugin._handle\n" );
    }
    return init;
}


void
MultiFileCurlPlugin::InitializeCurlHandle(const std::string &url) {
    curl_easy_setopt( _handle, CURLOPT_URL, url.c_str() );
    curl_easy_setopt( _handle, CURLOPT_CONNECTTIMEOUT, 60 );

    // Provide default read / write callback functions; note these
    // don't segfault if a nullptr is given as the read/write data.
    curl_easy_setopt( _handle, CURLOPT_READFUNCTION, &CurlReadCallback );
    curl_easy_setopt( _handle, CURLOPT_WRITEFUNCTION, &CurlWriteCallback );

    // Prevent curl from spewing to stdout / in by default.
    curl_easy_setopt( _handle, CURLOPT_READDATA, NULL );
    curl_easy_setopt( _handle, CURLOPT_WRITEDATA, NULL );

    // Libcurl options for HTTP, HTTPS and FILE
    if( !strncasecmp( url.c_str(), "http://", 7 ) ||
            !strncasecmp( url.c_str(), "https://", 8 ) ||
            !strncasecmp( url.c_str(), "file://", 7 ) ) {
        curl_easy_setopt( _handle, CURLOPT_FOLLOWLOCATION, 1 );
        curl_easy_setopt( _handle, CURLOPT_HEADERFUNCTION, &HeaderCallback );
    }
    // Libcurl options for FTP
    else if( !strncasecmp( url.c_str(), "ftp://", 6 ) ) {
        curl_easy_setopt( _handle, CURLOPT_WRITEFUNCTION, &FtpWriteCallback );
    }

    // * If the following option is set to 0, then curl_easy_perform()
    // returns 0 even on errors (404, 500, etc.) So we can't identify
    // some failures. I don't think it's supposed to do that?
    // * If the following option is set to 1, then something else bad
    // happens? 500 errors fail before we see HTTP headers but I don't
    // think that's a big deal.
    // * Let's keep it set to 1 for now.
    curl_easy_setopt( _handle, CURLOPT_FAILONERROR, 1 );

    if( _diagnostic ) {
        curl_easy_setopt( _handle, CURLOPT_VERBOSE, 1 );
    }

    // Setup a buffer to store error messages. For debug use.
    _error_buffer[0] = '\0';
    curl_easy_setopt( _handle, CURLOPT_ERRORBUFFER, _error_buffer );
}

FILE *
MultiFileCurlPlugin::OpenLocalFile(const std::string &local_file, const char *mode) const {
    FILE *file = nullptr;
    if ( !strcmp( local_file.c_str(), "-" ) ) {
        int fd = dup(1);
        if ( -1 != fd ) {
            if ( _diagnostic ) { fprintf( stderr, "Fetching %s to stdout\n", local_file.c_str() ); }
            file = fdopen(fd, mode);
        }
    }
    else {
        if ( _diagnostic ) { fprintf( stderr, "Fetching to %s\n", local_file.c_str() ); }
        file = fopen( local_file.c_str(), mode );
    }

    if( !file ) {
        fprintf( stderr, "ERROR: could not open local file %s, error %d (%s)\n", local_file.c_str(), errno, strerror(errno) );
    }

    return file;
}


void
MultiFileCurlPlugin::FinishCurlTransfer( int rval, FILE *file ) {

    // Gather more statistics
    double bytes_downloaded;
    double transfer_connection_time;
    double transfer_total_time;
    long return_code;
    curl_easy_getinfo( _handle, CURLINFO_SIZE_DOWNLOAD, &bytes_downloaded );
    curl_easy_getinfo( _handle, CURLINFO_CONNECT_TIME, &transfer_connection_time );
    curl_easy_getinfo( _handle, CURLINFO_TOTAL_TIME, &transfer_total_time );
    curl_easy_getinfo( _handle, CURLINFO_RESPONSE_CODE, &return_code );

    _this_file_stats->TransferTotalBytes += ( long ) bytes_downloaded;
    _this_file_stats->ConnectionTimeSeconds +=  ( transfer_total_time - transfer_connection_time );
    _this_file_stats->TransferReturnCode = return_code;

    if( rval == CURLE_OK ) {
        _this_file_stats->TransferSuccess = true;
        _this_file_stats->TransferError = "";
        _this_file_stats->TransferFileBytes = ftell( file );
    }
    else {
        _this_file_stats->TransferSuccess = false;
        _this_file_stats->TransferError = _error_buffer;
    }
}

int
MultiFileCurlPlugin::UploadFile( const std::string &url, const std::string &local_file_name ) {
    FILE *file = nullptr;
    int rval = -1;

    if( !(file=OpenLocalFile(local_file_name, "r")) ) {
        return rval;
    }
    InitializeCurlHandle( url );

    int fd = fileno(file);
    struct stat stat_buf;
    if (-1 == fstat(fd, &stat_buf)) {
        if ( _diagnostic ) { fprintf(stderr, "Failed to stat the local file for upload: %s (errno=%d).\n", strerror(errno), errno); }
        fclose( file );
        return rval;
    }

    curl_easy_setopt( _handle, CURLOPT_READDATA, file );
    curl_easy_setopt( _handle, CURLOPT_UPLOAD, 1L);
    curl_easy_setopt( _handle, CURLOPT_INFILESIZE_LARGE, (curl_off_t)stat_buf.st_size );

    // Update some statistics
    _this_file_stats->TransferType = "upload";
    _this_file_stats->TransferTries += 1;

    // Perform the curl request
    rval = curl_easy_perform( _handle );

    FinishCurlTransfer( rval, file );

        // Error handling and cleanup
    if( _diagnostic && rval ) {
        fprintf(stderr, "curl_easy_perform returned CURLcode %d: %s\n",
                rval, curl_easy_strerror( ( CURLcode ) rval ) );
    }

    fclose( file );

    return rval;
}


int 
MultiFileCurlPlugin::DownloadFile( const std::string &url, const std::string &local_file_name, long &partial_bytes ) {

    char partial_range[20];
    FILE *file = NULL;
    int rval = -1;

    if ( !(file=OpenLocalFile(local_file_name, partial_bytes ? "a+" : "w")) ) {
        return rval;
    }
    InitializeCurlHandle( url );

    // Libcurl options that apply to all transfer protocols
    curl_easy_setopt( _handle, CURLOPT_WRITEDATA, file );

    // If we are attempting to resume a download, set additional flags
    if( partial_bytes ) {
        sprintf( partial_range, "%lu-", partial_bytes );
        curl_easy_setopt( _handle, CURLOPT_RANGE, partial_range );
    }

    // Update some statistics
    _this_file_stats->TransferType = "download";
    _this_file_stats->TransferTries += 1;

    // Perform the curl request
    rval = curl_easy_perform( _handle );

    // Check if the request completed partially. If so, set some
    // variables so we can attempt a resume on the next try.
    if( ( rval == CURLE_PARTIAL_FILE ) && ServerSupportsResume( url ) ) {
        partial_bytes = ftell( file );
    }

    FinishCurlTransfer( rval, file );

        // Error handling and cleanup
    if( _diagnostic && rval ) {
        fprintf(stderr, "curl_easy_perform returned CURLcode %d: %s\n", 
                rval, curl_easy_strerror( ( CURLcode ) rval ) ); 
    }

    fclose( file ); 

    return rval;
}


int
MultiFileCurlPlugin::BuildTransferRequests(const std::string &input_filename, std::vector<std::pair<std::string, transfer_request>> &requested_files) const {
    CondorClassAdFileIterator adFileIter;
    FILE* input_file;

    // Read input file containing data about files we want to transfer. Input
    // data is formatted as a series of classads, each with an arbitrary number
    // of inputs.
    input_file = safe_fopen_wrapper( input_filename.c_str(), "r" );
    if( input_file == NULL ) {
        fprintf( stderr, "Unable to open curl_plugin input file %s.\n", 
            input_filename.c_str() );
        return 1;
    }

    if( !adFileIter.begin( input_file, false, CondorClassAdFileParseHelper::Parse_new )) {
        fprintf( stderr, "Failed to start parsing classad input.\n" );
        return 1;
    }
    else {
        // Iterate over the classads in the file, and insert each one into our
        // requested_files map, with the key: url, value: additional details 
        // about the transfer.
        ClassAd transfer_file_ad;
        std::string local_file_name;
        std::string url;
        transfer_request request_details;
        std::pair< std::string, transfer_request > this_request;

        int count = 0;
        while ( adFileIter.next( transfer_file_ad ) > 0 ) {
            transfer_file_ad.EvaluateAttrString( "LocalFileName", local_file_name );
            transfer_file_ad.EvaluateAttrString( "Url", url );
            request_details.local_file_name = local_file_name;

            if (url.substr(0, 7) == "davs://") {
                url = std::string("https://") + url.substr(7);
            } else if (url.substr(0, 6) == "dav://") {
                url = std::string("http://") + url.substr(6);
            }

            this_request = std::make_pair( url, request_details );
            requested_files.push_back( this_request );
            count ++;
            if ( _diagnostic ) {
                fprintf( stderr, "Will transfer between URL %s and local file %s.\n", url.c_str(), local_file_name.c_str() );
            }
        }
        if ( _diagnostic ) {
            fprintf( stderr, "There are a total of %d files to transfer.\n", count );
        }
    }
    fclose(input_file);

    return 0;
}


int
MultiFileCurlPlugin::UploadMultipleFiles( const std::string &input_filename ) {
    std::vector<std::pair<std::string, transfer_request>> requested_files;
    auto rval = BuildTransferRequests(input_filename, requested_files);
    if (rval) {return rval;}

    classad::ClassAdUnParser unparser;
    if ( _diagnostic ) { fprintf( stderr, "Uploading multiple files.\n" ); }

    for (const auto &file_pair : requested_files) {

        const auto &local_file_name = file_pair.second.local_file_name;
        const auto &url = file_pair.first;

        int retry_count = 0;
        int file_rval = -1;

        // Initialize the stats structure for this transfer.
        _this_file_stats.reset(new FileTransferStats());
        InitializeStats( url );
        _this_file_stats->TransferStartTime = time(NULL);
	_this_file_stats->TransferFileName = local_file_name;

        // Enter the loop that will attempt/retry the curl request
        for ( ;; ) {

            std::this_thread::sleep_for(std::chrono::seconds(retry_count++));

            file_rval = UploadFile( url, local_file_name );

            // If curl request is successful, break out of the loop
            if( file_rval == CURLE_OK ) {
                break;
            }
            // If we have not exceeded the maximum number of retries, and we encounter
            // a non-fatal error, stay in the loop and try again
            else if( retry_count <= MAX_RETRY_ATTEMPTS &&
                     ShouldRetryTransfer(retry_count) ) {
                continue;
            }
            // On fatal errors, break out of the loop
            else {
                break;
            }
        }

        _this_file_stats->TransferEndTime = time(NULL);

        // Regardless of success/failure, update the stats
        classad::ClassAd stats_ad;
        _this_file_stats->Publish( stats_ad );
        std::string stats_string;
        unparser.Unparse( stats_string, &stats_ad );
        _all_files_stats += stats_string;
        stats_ad.Clear();

        // Note that we attempt to upload all files, even if one fails!
        // The upload protocol demands that all attempted files have a corresponding ad.
        if ( ( file_rval != CURLE_OK ) && ( rval != -1 ) ) {
            rval = file_rval;
        }
    }
    return rval;
}


int
MultiFileCurlPlugin::DownloadMultipleFiles( const std::string &input_filename ) {
    int rval = 0;

    std::vector<std::pair<std::string, transfer_request>> requested_files;
    rval = BuildTransferRequests(input_filename, requested_files);
    classad::ClassAdUnParser unparser;

    // Iterate over the map of files to transfer.
    for ( const auto &file_pair : requested_files ) {

        const auto &local_file_name = file_pair.second.local_file_name;
        const auto &url = file_pair.first;
        if ( _diagnostic ) {
            fprintf( stderr, "Will download %s to %s.\n", url.c_str(), local_file_name.c_str() );
        }
        int retry_count = 0;

        // Initialize the stats structure for this transfer.
        _this_file_stats.reset( new FileTransferStats() );
        InitializeStats( url );
        _this_file_stats->TransferStartTime = time(NULL);
	_this_file_stats->TransferFileName = local_file_name;

        long partial_bytes = 0;
        // Enter the loop that will attempt/retry the curl request
        for ( ;; ) {
            if ( _diagnostic && retry_count ) { fprintf( stderr, "Retry count #%d\n", retry_count ); }

            std::this_thread::sleep_for(std::chrono::seconds(retry_count++));

            // partial_bytes are updated if the file downloaded partially.
            rval = DownloadFile( url.c_str(), local_file_name.c_str(), partial_bytes );

            // If curl request is successful, break out of the loop
            if( rval == CURLE_OK ) {
                break;
            }
            // If we have not exceeded the maximum number of retries, and we encounter
            // a non-fatal error, stay in the loop and try again
            else if( retry_count <= MAX_RETRY_ATTEMPTS && 
                     ShouldRetryTransfer(retry_count) ) {
                continue;
            }
            // On fatal errors, break out of the loop
            else {
                break;
            }
        }

        _this_file_stats->TransferEndTime = time(NULL);

        // Regardless of success/failure, update the stats
        classad::ClassAd stats_ad;
        _this_file_stats->Publish( stats_ad );
	std::string stats_string;
        unparser.Unparse( stats_string, &stats_ad );
        _all_files_stats += stats_string;
        stats_ad.Clear();

        // If the transfer did fail, break out of the loop immediately
        if ( rval > 0 ) break;
    }

    return rval;
}

/*
    Check if this server supports resume requests using the HTTP "Range" header
    by sending a Range request and checking the return code. Code 206 means
    resume is supported, code 200 means not supported. 
    Return: 1 if resume is supported, 0 if not.
*/
int 
MultiFileCurlPlugin::ServerSupportsResume( const std::string &url ) {

    int rval = -1;

    // Send a basic request, with Range set to a null range
    curl_easy_setopt( _handle, CURLOPT_URL, url.c_str() );
    curl_easy_setopt( _handle, CURLOPT_CONNECTTIMEOUT, 60 );
    curl_easy_setopt( _handle, CURLOPT_RANGE, "0-0" );

    rval = curl_easy_perform(_handle);

    // Check the HTTP status code that was returned
    if( rval == 0 ) {
        char* finalURL = NULL;
        rval = curl_easy_getinfo( _handle, CURLINFO_EFFECTIVE_URL, &finalURL );

        if( rval == 0 ) {
            if( strstr( finalURL, "http" ) == finalURL ) {
                long httpCode = 0;
                rval = curl_easy_getinfo( _handle, CURLINFO_RESPONSE_CODE, &httpCode );

                // A 206 status code indicates resume is supported. Return true!
                if( httpCode == 206 ) {
                    return 1;
                }
            }
        }
    }

    // If we've gotten this far the server does not support resume. Clear the
    // HTTP "Range" header and return false.
    curl_easy_setopt( _handle, CURLOPT_RANGE, NULL );
    return 0;
}

void
MultiFileCurlPlugin::InitializeStats( std::string request_url ) {

    char* url = strdup( request_url.c_str() );
    char* url_token;

    // Set the transfer protocol. If it's not http, ftp and file, then just
    // leave it blank because this transfer will fail quickly.
    if ( !strncasecmp( url, "http://", 7 ) ) {
        _this_file_stats->TransferProtocol = "http";
    }
    else if ( !strncasecmp( url, "https://", 8 ) ) {
        _this_file_stats->TransferProtocol = "https";
    }
    else if ( !strncasecmp( url, "ftp://", 6 ) ) {
        _this_file_stats->TransferProtocol = "ftp";
    }
    else if ( !strncasecmp( url, "file://", 7 ) ) {
        _this_file_stats->TransferProtocol = "file";
    }

    // Set the request host name by parsing it out of the URL
    _this_file_stats->TransferUrl = url;
    url_token = strtok( url, ":/" );
    url_token = strtok( NULL, "/" );
    _this_file_stats->TransferHostName = url_token;

    // Set the host name of the local machine using getaddrinfo().
    struct addrinfo hints, *info;
    int addrinfo_result;

    char hostname[1024];
    hostname[1023] = '\0';
    gethostname(hostname, 1023);

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_CANONNAME;

    // Look up the host name. If this fails for any reason, do not include
    // it with the stats.
    if ( ( addrinfo_result = getaddrinfo( hostname, "http", &hints, &info ) ) == 0 ) {
        _this_file_stats->TransferLocalMachineName = info->ai_canonname;
    }

    // Cleanup and exit
    free( url );
    freeaddrinfo( info );
}

size_t
MultiFileCurlPlugin::HeaderCallback( char* buffer, size_t size, size_t nitems, void *userdata ) {
    auto ft_stats = static_cast<FileTransferStats*>(userdata);

    const char* delimiters = " \r\n";
    size_t numBytes = nitems * size;

    // Parse this HTTP header
    // We should probably add more error checking to this parse method...
    char* token = strtok( buffer, delimiters );
    while( token ) {
        // X-Cache header provides details about cache hits
        if( strcmp ( token, "X-Cache:" ) == 0 ) {
            token = strtok( NULL, delimiters );
            ft_stats->HttpCacheHitOrMiss = token;
        }
        // Via header provides details about cache host
        else if( strcmp ( token, "Via:" ) == 0 ) {
            // The next token is a version number. We can ignore it.
            token = strtok( NULL, delimiters );
            // Next comes the actual cache host
            if( token != NULL ) {
                token = strtok( NULL, delimiters );
                ft_stats->HttpCacheHost = token;
            }
        }
        token = strtok( NULL, delimiters );
    }
    return numBytes;
}

size_t
MultiFileCurlPlugin::FtpWriteCallback( void* buffer, size_t size, size_t nmemb, void* stream ) {
    FILE* outfile = ( FILE* ) stream;
    return fwrite( buffer, size, nmemb, outfile); 
}


int
main( int argc, char **argv ) {

    bool valid_inputs = true;
    FILE* output_file;
    bool diagnostic = false;
    bool upload = false;
    int rval = 0;
    std::string input_filename;
    std::string output_filename;
    std::string transfer_files;

    // Check if this is a -classad request
    if ( argc == 2 ) {
        if ( strcmp( argv[1], "-classad" ) == 0 ) {
            printf( "%s",
                "MultipleFileSupport = true\n"
                "PluginVersion = \"0.2\"\n"
                "PluginType = \"FileTransfer\"\n"
                "SupportedMethods = \"dav,davs\"\n"
            );
            return 0;
        }
    }
    // If not, iterate over command-line arguments and set variables appropriately
    else {
        for( int i = 1; i < argc; i ++ ) {
            if ( strcmp( argv[i], "-infile" ) == 0 ) {
                if ( i < ( argc - 1 ) ) {
                    input_filename = argv[i+1];
                }
                else {
                    valid_inputs = false;
                }
            }
            if ( strcmp( argv[i], "-outfile" ) == 0 ) {
                if ( i < ( argc - 1 ) ) {
                    output_filename = argv[i+1];
                }
                else {
                    valid_inputs = false;
                }
            }
            if ( strcmp( argv[i], "-diagnostic" ) == 0 ) {
                diagnostic = true;
            }
            if ( strcmp( argv[i], "-upload" ) == 0 ) {
                upload = true;
            }
        }
    }

    if ( !valid_inputs || input_filename.empty() ) {
        fprintf( stderr, "Error: invalid arguments\n" );
        fprintf( stderr, "Usage: %s -infile <input-filename> -outfile <output-filename> [general-opts]\n\n", argv[0] );
        fprintf( stderr, "[general-opts] are:\n" );
        fprintf( stderr, "\t-diagnostic\t\tRun the plugin in diagnostic (verbose) mode\n\n" );
        fprintf( stderr, "\t-upload\t\tRun the plugin in upload mode, copying files to a remote location\n\n" );
        return 1;
    }

    // Instantiate a MultiFileCurlPlugin object and handle the request
    MultiFileCurlPlugin curl_plugin( diagnostic );
    if( curl_plugin.InitializeCurl() != 0 ) {
        fprintf( stderr, "ERROR: curl_plugin failed to initialize. Aborting.\n" );
        return 1;
    }

    // Do the transfer(s)
    rval = upload ?
             curl_plugin.UploadMultipleFiles( input_filename )
           : curl_plugin.DownloadMultipleFiles( input_filename );

    // Now that we've finished all transfers, write statistics to output file
    if( !output_filename.empty() ) {
        output_file = safe_fopen_wrapper( output_filename.c_str(), "w" );
        if( output_file == NULL ) {
            fprintf( stderr, "Unable to open curl_plugin output file: %s\n", output_filename.c_str() );
            return 1;
        }
        fprintf( output_file, "%s", curl_plugin.GetStats().c_str() );
        fclose( output_file );
    }
    else {
        printf( "%s\n", curl_plugin.GetStats().c_str() );
    }

    // 0 on success, error code >= 1 on failure
    return rval;
}


