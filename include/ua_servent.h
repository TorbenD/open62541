/*
 * ua_servent.h
 *
 *  Created on: 15.06.2016
 *      Author: root
 */

#ifndef INCLUDE_UA_SERVENT_H_
#define INCLUDE_UA_SERVENT_H_


#include "ua_job.h"

struct UA_Client;
typedef struct UA_Client UA_Client;

struct UA_Servent;
typedef struct UA_Servent UA_Servent;

typedef struct
	{
	UA_Job *serverjobs;
	size_t serverJobsSize;
	UA_Job *clientjobs;
	size_t clientJobsSize;
	}UA_NetworklayerJobs;

struct UA_Servent
	{
	UA_NetworklayerJobs *networklayerjobs;
	UA_Server *server;
	UA_Int32 servernumber;
	UA_Client *client;
	UA_Int32 clientnumber;
	UA_Boolean transfer;
	UA_Boolean transfer2;
	};

UA_Servent * UA_Servent_new(void);
void UA_Servent_delete(UA_Servent* servent);
UA_StatusCode GetWorkFromNetworklayerServent (UA_Servent *servent, UA_UInt16 timeout);

#endif /* INCLUDE_UA_SERVENT_H_ */
