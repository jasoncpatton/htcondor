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
#include "condor_classad.h"
#include "condor_config.h"
#include "condor_attributes.h"
#include "condor_version.h"
#include "condor_ver_info.h"
#include "condor_distribution.h"

void PREFAST_NORETURN
usage( char name[], int rval )
{
	fprintf( stderr, "Usage: %s [options]\n", name );
    fprintf( stderr, "   If no options are specified, print the "
			 "version and platform strings\n   where the tool was built." );
    fprintf( stderr, "  Valid options are:\n" );
    fprintf( stderr, "   -help\t(this message)\n" );
    fprintf( stderr, 
			 "   -arch\t(print the ARCH string)\n" );
    fprintf( stderr, 
			 "   -opsys\t(print the OPSYS string)\n" );
    fprintf( stderr, "   -syscall\t(get info from the libcondorsyscall.a "
			 "this Condor pool is\n        \t configured to use, not the "
			 "values where the tool was built)\n" );

	exit( rval );
}


int
main(int argc, char *argv[])
{

	myDistro->Init( argc, argv );
	CondorVersionInfo *version;

	bool use_syscall_lib = false;
	bool print_arch = false;
	bool print_opsys = false;
	bool opsys_first = false;		// stupid flag for maintaining the
									// order we saw the args in...

	for(int i = 1; i < argc; i++ ) {
		if( argv[i][0] != '-' ) {
			fprintf( stderr, "ERROR: invalid argument: '%s'\n", argv[i] );
			usage( argv[0], 1 );
		}
		switch( argv[i][1] ) {
		case 's':
			use_syscall_lib = true;
			break;
		case 'a':
			print_arch = true;
			break;
		case 'o':
			print_opsys = true;
			if( ! print_arch ) {
				opsys_first = true;
			}
			break;
		case 'h':
			usage( argv[0], 0 );
			break;
		default:
			fprintf( stderr, "ERROR: unrecognized argument: '%s'\n", argv[i] );
			usage( argv[0], 1 );
		}
	}

	char *path=NULL, *fullpath=NULL, *vername=NULL, *platform=NULL;
	if( use_syscall_lib ) {
		config();
		path = param( "LIB" );
		if( path == NULL ) {
			fprintf( stderr, "ERROR: -syscall_lib specified but 'LIB' not "
					 "defined in configuration!\n" );
			usage( argv[0], 1 );
		}
		fullpath = (char *)malloc(strlen(path) + 24);
		ASSERT( fullpath != NULL );
		strcpy(fullpath, path);
		strcat(fullpath, "/libcondorsyscall.a");
				
		vername = NULL;
		vername = CondorVersionInfo::get_version_from_file(fullpath, vername);
		platform = NULL;
		platform = CondorVersionInfo::get_platform_from_file(fullpath, platform);

		version = new CondorVersionInfo(vername, NULL, platform);
		free(path);
		free(fullpath);
	} else {
		version = new CondorVersionInfo;
	}

	if( opsys_first ) {
		assert( print_opsys );
		printf("%s\n", version->getOpSysVer() );
	}
	if( print_arch ) {
		printf("%s\n", version->getArchVer() );
	}
	if( ! opsys_first && print_opsys ) {
		printf("%s\n", version->getOpSysVer() );
	}

	if( print_arch || print_opsys ) {
		return 0;
	}

	if( use_syscall_lib ) {
		printf( "%s\n%s\n", vername, platform );
	} else { 
		printf( "%s\n%s\n", CondorVersion(), CondorPlatform() );
	}

	delete( version );

	return 0;
}
