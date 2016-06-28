/*
 * ua_servent.h
 *
 *  Created on: 15.06.2016
 *      Author: root
 */

#ifndef INCLUDE_UA_SERVENT_H_
#define INCLUDE_UA_SERVENT_H_


#include "ua_job.h"
#include "ua_client.h"
#include "ua_server.h"

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

typedef struct
	{
	UA_Client *client;
	UA_Boolean transferdone;
	UA_ServerNetworkLayer *NetworklayerListener;
	}ClientMapping;

typedef struct
	{
	UA_String endpointUrl;
	UA_UInt16 serverport;
	UA_UInt16 clientport;
	UA_Int32  socket;
	}ClientServerRelation;

struct UA_Servent
	{
	UA_NetworklayerJobs *networklayerjobs;
	UA_Server *server;
	ClientMapping *clientmapping;
	size_t clientmappingSize;
	ClientServerRelation *clientserverrelation;
	size_t clientserverrelationSize;
	};

UA_Servent * UA_Servent_new(UA_ServerConfig config);
void UA_Servent_delete(UA_Servent* servent);
UA_Client * UA_Servent_connect_username(UA_Servent *servent, UA_ClientConfig clientconfig, const char *endpointUrl,
                           const char *username, const char *password, UA_ServerNetworkLayer *NetworklayerListener);
UA_Client * UA_Servent_connect(UA_Servent *servent, UA_ClientConfig clientconfig, const char *endpointUrl, UA_ServerNetworkLayer *NetworklayerListener);
UA_StatusCode UA_Servent_disconnect(UA_Servent *servent, UA_Client *client);
UA_StatusCode GetWorkFromNetworklayerServent (UA_Servent *servent, UA_UInt16 timeout);

#endif /* INCLUDE_UA_SERVENT_H_ */
