/***************************Copyright-DO-NOT-REMOVE-THIS-LINE**
 * CONDOR Copyright Notice
 *
 * See LICENSE.TXT for additional notices and disclaimers.
 *
 * Copyright (c)1990-1998 CONDOR Team, Computer Sciences Department, 
 * University of Wisconsin-Madison, Madison, WI.  All Rights Reserved.  
 * No use of the CONDOR Software Program Source Code is authorized 
 * without the express consent of the CONDOR Team.  For more information 
 * contact: CONDOR Team, Attention: Professor Miron Livny, 
 * 7367 Computer Sciences, 1210 W. Dayton St., Madison, WI 53706-1685, 
 * (608) 262-0856 or miron@cs.wisc.edu.
 *
 * U.S. Government Rights Restrictions: Use, duplication, or disclosure 
 * by the U.S. Government is subject to restrictions as set forth in 
 * subparagraph (c)(1)(ii) of The Rights in Technical Data and Computer 
 * Software clause at DFARS 252.227-7013 or subparagraphs (c)(1) and 
 * (2) of Commercial Computer Software-Restricted Rights at 48 CFR 
 * 52.227-19, as applicable, CONDOR Team, Attention: Professor Miron 
 * Livny, 7367 Computer Sciences, 1210 W. Dayton St., Madison, 
 * WI 53706-1685, (608) 262-0856 or miron@cs.wisc.edu.
****************************Copyright-DO-NOT-REMOVE-THIS-LINE**/

#ifndef CEDAR_IO
#define CEDAR_IO

#include "classad_io.h"
#include "condor_io.h"

BEGIN_NAMESPACE( classad )

class CedarSource : public ByteSource {
	public:
		CedarSource( );
		virtual ~CedarSource( );

		void Initialize( Stream *s, int maxlen=-1 );
		bool _GetChar( int &ch );

	private:
		Stream *strm;
};


class CedarSink : public ByteSink {
	public:
		CedarSink( );
		virtual ~CedarSink( );	

		void Initialize( Stream *s, int maxlen=-1 );
		bool _PutBytes( const void *, int );
		bool _Flush( );
	private:
		Stream *strm;
};

///
class CedarStream : public ByteStream {
  public:
	///
	CedarStream () {
		m_src = new CedarSource;
		m_snk = new CedarSink;
	}
	///
	virtual ~CedarStream () {}
	///
	inline void Initialize (Stream * s, int maxlen = -1) {
		((CedarSource*)m_src)->Initialize (s,maxlen);
		((CedarSink*)m_snk)->Initialize (s,maxlen);
	}

  protected:

    /** @param url sinful string
        @return true if connection successful
     */
    virtual bool _Connect (string url);

    ///
    virtual bool _Close ();
};

END_NAMESPACE // classad

#endif//CEDAR_IO
