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


/* 
   This is some wisdom from Cygnus's web page.  If you just try to use
   the "stringify" operator on a preprocessor directive, you'd get
   "PLATFORM", not "Intel Linux" (or whatever the value of PLATFORM
   is).  That's because the stringify operator is a special case, and
   the preprocessor isn't allowed to expand things that are passed to
   it.  However, by defining two layers of macros, you get the right
   behavior, since the first pass converts:

   xstr(PLATFORM) -> str(Intel Linux)

   and the next pass gives:

   str(Intel Linux) -> "Intel Linux"

   This is exactly what we want, so we use it.  -Derek Wright and Jeff
   Ballard, 12/2/99 

   Also, because the NT build system is totally different, we have to
   define the correct platform string right in here. :( -Derek 12/3/99 
*/

/*
 * WARNING! Don't include any Condor header files in this file!
 *   This file is linked into programs that aren't linked with the Condor
 *   libraries.
 */

#define xstr(s) str(s)
#define str(s) #s

#if defined(WIN32) && ! defined(PLATFORM)
#define PLATFORM "INTEL-WINNT50"
#endif

/* Via configure, one may have specified a particular buildid string to use
	in the version string. So honor that request here. */
#if defined(BUILDID)
#define BUILDIDSTR " BuildID: " xstr(BUILDID)
#else
#define BUILDIDSTR ""
#endif

#if !defined(BUILD_DATE)
#  define BUILD_DATE __DATE__
#endif

#if !defined(PRE_RELEASE_STR)
#  define PRE_RELEASE_STR ""
#endif

/* Here is the version string - update before a public release */
/* --- IMPORTANT!  THE FORMAT OF THE VERSION STRING IS VERY STRICT
   BECAUSE IT IS PARSED AT RUNTIME AND COMPILE-TIME.  DO NOT ALTER THE
   FORMAT OR ENTER ANYTHING EXTRA BEFORE THE DATE.  IF YOU WISH TO ADD
   EXTRA INFORMATION, DO SO _AFTER_ THE BUILDIDSTR AND BEFORE THE TRAILING
   '$' CHARACTER.
   EXAMPLES:
       $CondorVersion: 6.9.5 " __DATE__ BUILDIDSTR " WinNTPreview $ [OK]
	   $CondorVersion: 6.9.5 WinNTPreview " __DATE__ BUILDIDSTR " $ [WRONG!!!]
   Any questions?  See Todd or Derek.  Note: if you mess it up, DaemonCore
   will EXCEPT at startup time.  

   You generally change this in the top level CMakeLists.txt, NOT HERE.
*/


static const char* CondorVersionString =
"$CondorVersion: " CONDOR_VERSION " " BUILD_DATE BUILDIDSTR  PRE_RELEASE_STR " $";

/* Here is the platform string.  You don't need to edit this */
static const char* CondorPlatformString = "$CondorPlatform: " PLATFORM " $";

extern "C" {

const char*
CondorVersion( void )
{
	return CondorVersionString;
}

const char*
CondorPlatform( void )
{
	return CondorPlatformString;
}

} /* extern "C" */

