#include <sys/types.h>
#include "typedefs2.h"
#include "network2.h"


void StripPrefix(const char* pathname,
		 char        filename[MAX_CONDOR_FILENAME_LENGTH]);


int ConnectToServer(request_type type);


int IsLocal(const char* path);

int FileExists(const char *path, const char *filename);

int RequestStore(const char*     owner,
				 const char*     filename,
				 u_lint          len,
				 struct in_addr* server_IP,
				 u_short*        port);


int RequestRestore(const char*     owner,
				   const char*     filename,
				   u_lint*         len,
				   struct in_addr* server_IP,
				   u_short*        port);


int RequestService(const char*     owner,
				   const char*     filename,
				   const char*     new_filename,
				   service_type    type,
				   struct in_addr* server_IP,
				   u_short*        port,
				   u_lint*         num_files,
				   char*           cap_free);


int FileOnServer(const char* owner,
				 const char* filename);


int RemoveRemoteFile(const char* owner,
					 const char* filename);


int RenameRemoteFile(const char* owner,
					 const char* filename,
					 const char* new_filename);


