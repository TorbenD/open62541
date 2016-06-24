/*
 * ua_servent.c
 *
 *  Created on: 16.06.2016
 *      Author: root
 */

#include "ua_servent.h"
#include "ua_types.h"
#include "ua_util.h"
#include "ua_connection_internal.h"
#include "ua_constants.h"
#include "..//src_generated//ua_transport_generated_encoding_binary.h"
#include "..//src//server//ua_server_internal.h"
#include "..//src//client//ua_client_internal.h"
#include "..//plugins//networklayer_tcp.h"
#include "..//src//server//ua_services.h"
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "ua_log.h"
#include "..//plugins//logger_stdout.h"
#include "ua_client_highlevel.h"




static UA_StatusCode
ClientServerTransferMethod(void *handle, const UA_NodeId objectId, size_t inputSize, const UA_Variant *input,
                 size_t outputSize, UA_Variant *output)
	{
	UA_ServentClientServerTransferDataType *data_tmp = (UA_ServentClientServerTransferDataType*)(input->data);
	UA_Servent *servent = (UA_Servent*)handle;

	UA_LOG_INFO(servent->server->config.logger, UA_LOGCATEGORY_SERVER, "ClientServerTransfer was called");

	for (size_t i = 0; i < servent->clientserverrelationSize; i++)
		{
		if (UA_String_equal(&(servent->clientserverrelation[servent->clientserverrelationSize].endpointUrl), &data_tmp->url) &&
			servent->clientserverrelation[servent->clientserverrelationSize].clientport == data_tmp->clientPort &&
			servent->clientserverrelation[servent->clientserverrelationSize].serverport == data_tmp->serverPort)
			return UA_STATUSCODE_GOOD;
		}

	ServerNetworkLayerTCP *layer = NULL;
	UA_String url_tmp = UA_STRING_NULL;
	UA_Int32 socket_tmp = 0;
	UA_UInt16 clientport_tmp = 0;
	struct sockaddr_in addr;
	socklen_t addrlen = sizeof(struct sockaddr_in);


	for (size_t i = 0; i < servent->server->config.networkLayersSize;i++)
		{
		layer = servent->server->config.networkLayers[i].handle;
		for (size_t j = 0; j < layer->mappingsSize; j++)
			{
			getpeername(layer->mappings[j].sockfd, (struct sockaddr*)&addr, &addrlen);
			url_tmp = UA_String_fromChars(inet_ntoa(addr.sin_addr));
			clientport_tmp = ntohs(addr.sin_port);
			if (UA_String_equal(&url_tmp, &data_tmp->url) && clientport_tmp == data_tmp->clientPort)
				{
				socket_tmp = layer->mappings[j].sockfd;
				break;
				}
			}
		if (socket_tmp != 0)
			break;
		}


	ClientServerRelation *clientserverrelation_tmp = NULL;
	clientserverrelation_tmp = UA_realloc (servent->clientserverrelation, sizeof(ClientServerRelation) * (servent->clientserverrelationSize + 1));
	if(!clientserverrelation_tmp)
		{
		UA_LOG_ERROR(servent->server->config.logger, UA_LOGCATEGORY_NETWORK, "No memory for a new ClientServerRelation");
		return UA_STATUSCODE_BADOUTOFMEMORY;
		}
	servent->clientserverrelation = clientserverrelation_tmp;
	servent->clientserverrelation[servent->clientserverrelationSize].clientport = data_tmp->clientPort;
	servent->clientserverrelation[servent->clientserverrelationSize].serverport = data_tmp->serverPort;
	UA_String_copy(&data_tmp->url,&servent->clientserverrelation[servent->clientserverrelationSize].endpointUrl);
	servent->clientserverrelation[servent->clientserverrelationSize].socket = socket_tmp;
	servent->clientserverrelationSize++;

	UA_StatusCode tmp =  UA_STATUSCODE_GOOD;
	UA_Variant_setScalarCopy(output, &tmp, &UA_TYPES[UA_TYPES_UINT32]);

	return UA_STATUSCODE_GOOD;
	}

UA_Client * UA_Servent_TransferFunction (UA_Servent *servent, UA_ClientConfig clientconfig, const char *endpointUrl, UA_ServerNetworkLayer NetworklayerListener, UA_Int32 socket);

UA_Servent * UA_Servent_new(UA_ServerConfig config)
	{
    UA_Servent *servent = UA_calloc(1, sizeof(UA_Servent));
    if(!servent)
        return NULL;

    servent->server = UA_Server_new(config);
    servent->server->servent = servent;

	// Method for Client-Server-Relation
    UA_Argument inputArguments;
	UA_Argument_init(&inputArguments);
	inputArguments.arrayDimensionsSize = 0;
	inputArguments.arrayDimensions = NULL;
	inputArguments.dataType = UA_TYPES[UA_TYPES_SERVENTCLIENTSERVERTRANSFERDATATYPE].typeId;
	inputArguments.description = UA_LOCALIZEDTEXT("en_US", "A String");
	inputArguments.name = UA_STRING("MyInput");
	inputArguments.valueRank = -1;

	// define output arguments
	UA_Argument outputArguments;
	UA_Argument_init(&outputArguments);
	outputArguments.arrayDimensionsSize = 0;
	outputArguments.arrayDimensions = NULL;
	outputArguments.dataType = UA_TYPES[UA_TYPES_UINT32].typeId;
	outputArguments.description = UA_LOCALIZEDTEXT("en_US", "A String");
	outputArguments.name = UA_STRING("StatusCode");
	outputArguments.valueRank = -1;

	UA_MethodAttributes CSTAttr;
	UA_MethodAttributes_init(&CSTAttr);
	CSTAttr.description = UA_LOCALIZEDTEXT("en_US","1dArrayExample");
	CSTAttr.displayName = UA_LOCALIZEDTEXT("en_US","1dArrayExample");
	CSTAttr.executable = true;
	CSTAttr.userExecutable = true;
	UA_Server_addMethodNode(servent->server, UA_NODEID_STRING(1, "ClientServerTransferMethod"),
							UA_NODEID_NUMERIC(0, UA_NS0ID_OBJECTSFOLDER),
							UA_NODEID_NUMERIC(0, UA_NS0ID_HASCOMPONENT),
							UA_QUALIFIEDNAME(1, "ClientServerTransferMethod"),
							CSTAttr, &ClientServerTransferMethod, servent,
							1, &inputArguments, 1, &outputArguments, NULL);


    UA_NetworklayerJobs *networklayerjobs = UA_calloc (config.networkLayersSize, sizeof(UA_ServerNetworkLayer));
	servent->networklayerjobs = networklayerjobs;
	for(size_t i = 0; i < config.networkLayersSize; i++)
		{
		servent->networklayerjobs[i].clientJobsSize = 0;
		servent->networklayerjobs[i].clientjobs = NULL;
		servent->networklayerjobs[i].serverJobsSize = 0;
		servent->networklayerjobs[i].serverjobs = NULL;
		}


    servent->clientmapping = NULL;
    servent->clientSize = 0;
    servent->clientserverrelation = NULL;
    servent->clientserverrelationSize = 0;
    return servent;
	}

void UA_Servent_delete(UA_Servent* servent)
	{
	for (size_t i = 0; i < servent->clientSize; i++)
		{
		UA_Client_disconnect(servent->clientmapping[i].client);
		UA_Client_delete(servent->clientmapping[i].client);
		}
	UA_free(servent->clientmapping);
	servent->clientmapping = NULL;
	UA_Server_delete(servent->server);
	servent->server = NULL;
	UA_free(servent->networklayerjobs);
	servent->networklayerjobs = NULL;
    UA_free(servent);
    servent = NULL;
	}

UA_Client * UA_Servent_connect_username(UA_Servent *servent, UA_ClientConfig clientconfig, const char *endpointUrl,
                           const char *username, const char *password, UA_ServerNetworkLayer NetworklayerListener)
	{
	UA_Client *new_client = NULL;
	UA_String endpointUrl_tmp = UA_String_fromChars(endpointUrl);
	UA_String username_tmp = UA_String_fromChars(username);
	UA_String password_tmp = UA_String_fromChars(password);

	for (size_t i = 0; i < servent->clientSize; i++)
		{
		if (UA_String_equal(&(servent->clientmapping[i].client->endpointUrl),&endpointUrl_tmp) &&
			UA_String_equal(&(servent->clientmapping[i].client->username), &username_tmp) &&
			UA_String_equal(&(servent->clientmapping[i].client->password), &password_tmp))
			return servent->clientmapping[i].client;
		}

	size_t urlLength = strlen(endpointUrl);
	UA_UInt16 portpos = 9;
	UA_UInt16 port;
	for(port = 0; portpos < urlLength-1; portpos++)
		{
		if(endpointUrl[portpos] == ':')
			{
			char *endPtr = NULL;
			unsigned long int tempulong = strtoul(&endpointUrl[portpos+1], &endPtr, 10);
			if (ERANGE != errno && tempulong < UINT16_MAX && endPtr != &endpointUrl[portpos+1])
				port = (UA_UInt16)tempulong;
			break;
		}
	}
	if(port == 0)
		{
		UA_LOG_WARNING((servent->server->config.logger), UA_LOGCATEGORY_NETWORK, "Port invalid");
		return NULL;
		}

	char hostname[512];
	for(int i=10; i < portpos; i++)
		hostname[i-10] = endpointUrl[i];
	hostname[portpos-10] = 0;

	UA_String hostname_tmp = UA_String_fromChars(hostname);

	for (size_t i = 0; i < servent->clientserverrelationSize; i++)
		{
		if (UA_String_equal(&(servent->clientserverrelation[i].endpointUrl), &hostname_tmp) &&
			servent->clientserverrelation[i].serverport == port)
			{
			new_client = UA_Servent_TransferFunction (servent, clientconfig, endpointUrl, NetworklayerListener, servent->clientserverrelation[i].socket);

			return new_client;
			}
		}

	UA_StatusCode retval;
	new_client = UA_Client_new(clientconfig);
	if(!new_client)
		return NULL;
	new_client->servent = servent;

	ClientMapping *clientmapping_tmp = NULL;
	clientmapping_tmp = UA_realloc (servent->clientmapping, sizeof(ClientMapping) * (servent->clientSize + 1));
	if(!clientmapping_tmp)
		{
		UA_LOG_ERROR(new_client->config.logger, UA_LOGCATEGORY_NETWORK, "No memory for a new ClientMapping");
		return NULL;
		}
	servent->clientmapping = clientmapping_tmp;
	servent->clientmapping[servent->clientSize].client = new_client;
	servent->clientmapping[servent->clientSize].transferdone = UA_FALSE;
	servent->clientSize++;

	retval = UA_Client_connect_username(new_client, endpointUrl, username, password);
	if(retval != UA_STATUSCODE_GOOD)
		{
		UA_Client_delete(new_client);
		clientmapping_tmp = NULL;
		servent->clientmapping[servent->clientSize].client = NULL;
		servent->clientmapping[servent->clientSize].transferdone = UA_FALSE;
		clientmapping_tmp = UA_realloc (servent->clientmapping, sizeof(ClientMapping) * (servent->clientSize - 1));
		if(!clientmapping_tmp)
			{
			UA_LOG_ERROR(new_client->config.logger, UA_LOGCATEGORY_NETWORK, "No memory for a new ClientMapping");
			return NULL;
			}
		servent->clientmapping = clientmapping_tmp;
		servent->clientSize--;
		return NULL;
		}

	ServerNetworkLayerTCP *layer = NetworklayerListener.handle;
	retval = ServerNetworkLayerTCP_add(layer, new_client->connection.sockfd);
	if (retval != UA_STATUSCODE_GOOD)
		{
		UA_LOG_ERROR(new_client->config.logger, UA_LOGCATEGORY_NETWORK, "Problem in function ServerNetworkLayerTCP_add");
		UA_Client_delete(new_client);
		clientmapping_tmp = UA_realloc (servent->clientmapping, sizeof(ClientMapping) * (servent->clientSize));
		servent->clientSize--;
		return NULL;
		}

	layer->mappings[layer->mappingsSize-1].connection = &new_client->connection;
	layer->mappings[layer->mappingsSize-1].connection->channel = &new_client->channel;

	UA_OpenSecureChannelRequest opnSecRq;
	UA_OpenSecureChannelRequest_init(&opnSecRq);
	opnSecRq.requestHeader.timestamp = UA_DateTime_now();
	opnSecRq.requestHeader.authenticationToken = new_client->authenticationToken;
	opnSecRq.requestedLifetime = new_client->config.secureChannelLifeTime;
	opnSecRq.requestType = UA_SECURITYTOKENREQUESTTYPE_ISSUE;
	UA_ByteString_copy(&new_client->channel.clientNonce, &opnSecRq.clientNonce);
	opnSecRq.securityMode = UA_MESSAGESECURITYMODE_NONE;

	UA_OpenSecureChannelResponse openSecRe;
	UA_OpenSecureChannelResponse_init(&openSecRe);
	UA_Connection *connection = layer->mappings[layer->mappingsSize-1].connection;
	Service_OpenSecureChannel(servent->server, connection, &opnSecRq, &openSecRe);
	servent->clientmapping[servent->clientSize-1].transferdone = UA_TRUE;

	UA_Variant input;
	UA_ServentClientServerTransferDataType arg;
	struct sockaddr_in addr;
	socklen_t addrlen = sizeof(struct sockaddr_in);
	getsockname(new_client->connection.sockfd, (struct sockaddr*)&addr, &addrlen);

	arg.url = UA_String_fromChars(inet_ntoa(addr.sin_addr));
	arg.clientPort = ntohs(addr.sin_port);
	arg.serverPort = layer->port;

	UA_Variant_init(&input);
	UA_Variant_setScalarCopy(&input, &arg, &UA_TYPES[UA_TYPES_SERVENTCLIENTSERVERTRANSFERDATATYPE]);
	size_t outputSize;
	UA_Variant *output;
	retval = UA_Client_call(new_client, UA_NODEID_NUMERIC(0, UA_NS0ID_OBJECTSFOLDER),
					UA_NODEID_STRING(1, "ClientServerTransferMethod"), 1, &input, &outputSize, &output);
	if(retval == UA_STATUSCODE_GOOD)
		{
		UA_LOG_INFO(servent->server->config.logger, UA_LOGCATEGORY_SERVER, "Method call was successfull, and %lu returned values available.\n",
			   (unsigned long)outputSize);
		UA_Array_delete(output, outputSize, &UA_TYPES[UA_TYPES_VARIANT]);
		}
	else
		{
		UA_LOG_INFO(servent->server->config.logger, UA_LOGCATEGORY_SERVER, "Method call was unsuccessfull, and %x returned values available.\n", retval);
		}
	if (((UA_StatusCode*)output->data) != UA_STATUSCODE_GOOD)
		{
		UA_LOG_ERROR(servent->server->config.logger, UA_LOGCATEGORY_NETWORK, "Method call response was bad");
		}

	UA_Variant_deleteMembers(&input);

    return servent->clientmapping[servent->clientSize-1].client;
	}

UA_Client * UA_Servent_connect(UA_Servent *servent, UA_ClientConfig clientconfig, const char *endpointUrl, UA_ServerNetworkLayer NetworklayerListener)
	{
	UA_Client *new_client = NULL;

	UA_String endpointUrl_tmp = UA_STRING_NULL;
	endpointUrl_tmp = UA_String_fromChars(endpointUrl);

	for (size_t i = 0; i < servent->clientSize; i++)
		{
		if (UA_String_equal(&(servent->clientmapping[i].client->endpointUrl),&endpointUrl_tmp))
			return servent->clientmapping[i].client;
		}

	size_t urlLength = strlen(endpointUrl);
	UA_UInt16 portpos = 9;
	UA_UInt16 port;
	for(port = 0; portpos < urlLength-1; portpos++)
		{
		if(endpointUrl[portpos] == ':')
			{
			char *endPtr = NULL;
			unsigned long int tempulong = strtoul(&endpointUrl[portpos+1], &endPtr, 10);
			if (ERANGE != errno && tempulong < UINT16_MAX && endPtr != &endpointUrl[portpos+1])
				port = (UA_UInt16)tempulong;
			break;
		}
	}
	if(port == 0)
		{
		UA_LOG_WARNING((servent->server->config.logger), UA_LOGCATEGORY_NETWORK, "Port invalid");
		return NULL;
		}

	char hostname[512];
	for(int i=10; i < portpos; i++)
		hostname[i-10] = endpointUrl[i];
	hostname[portpos-10] = 0;

	UA_String hostname_tmp = UA_String_fromChars(hostname);

	for (size_t i = 0; i < servent->clientserverrelationSize; i++)
		{
		if (UA_String_equal(&(servent->clientserverrelation[i].endpointUrl), &hostname_tmp) &&
			servent->clientserverrelation[i].serverport == port)
			{
			new_client = UA_Servent_TransferFunction (servent, clientconfig, endpointUrl, NetworklayerListener, servent->clientserverrelation[i].socket);

			return new_client;
			}
		}

	UA_StatusCode retval;
	new_client = UA_Client_new(clientconfig);
	if(!new_client)
		return NULL;

	new_client->servent = servent;
	ClientMapping *clientmapping_tmp = NULL;
	clientmapping_tmp = UA_realloc (servent->clientmapping, sizeof(ClientMapping) * (servent->clientSize + 1));
	if(!clientmapping_tmp)
		{
		UA_LOG_ERROR(new_client->config.logger, UA_LOGCATEGORY_NETWORK, "No memory for a new ClientMapping");
		return NULL;
		}
	servent->clientmapping = clientmapping_tmp;
	servent->clientmapping[servent->clientSize].client = new_client;
	servent->clientmapping[servent->clientSize].transferdone = UA_FALSE;
	servent->clientSize++;

	retval = UA_Client_connect(new_client, endpointUrl);
	if(retval != UA_STATUSCODE_GOOD)
		{
		UA_Client_delete(new_client);
		clientmapping_tmp = NULL;
		servent->clientmapping[servent->clientSize].client = NULL;
		servent->clientmapping[servent->clientSize].transferdone = UA_FALSE;
		clientmapping_tmp = UA_realloc (servent->clientmapping, sizeof(ClientMapping) * (servent->clientSize - 1));
		if(!clientmapping_tmp)
			{
			UA_LOG_ERROR(new_client->config.logger, UA_LOGCATEGORY_NETWORK, "No memory for a new ClientMapping");
			return NULL;
			}
		servent->clientmapping = clientmapping_tmp;
		servent->clientSize--;
		return NULL;
		}

	ServerNetworkLayerTCP *layer = NetworklayerListener.handle;
	retval = ServerNetworkLayerTCP_add(layer, new_client->connection.sockfd);
	if (retval != UA_STATUSCODE_GOOD)
		{
		UA_LOG_ERROR(new_client->config.logger, UA_LOGCATEGORY_NETWORK, "Problem in function ServerNetworkLayerTCP_add");
		UA_Client_delete(new_client);
		clientmapping_tmp = UA_realloc (servent->clientmapping, sizeof(ClientMapping) * (servent->clientSize));
		servent->clientSize--;
		return NULL;
		}

	layer->mappings[layer->mappingsSize-1].connection = &new_client->connection;
	layer->mappings[layer->mappingsSize-1].connection->channel = &new_client->channel;

	UA_OpenSecureChannelRequest opnSecRq;
	UA_OpenSecureChannelRequest_init(&opnSecRq);
	opnSecRq.requestHeader.timestamp = UA_DateTime_now();
	opnSecRq.requestHeader.authenticationToken = new_client->authenticationToken;
	opnSecRq.requestedLifetime = new_client->config.secureChannelLifeTime;
	opnSecRq.requestType = UA_SECURITYTOKENREQUESTTYPE_ISSUE;
	UA_ByteString_copy(&new_client->channel.clientNonce, &opnSecRq.clientNonce);
	opnSecRq.securityMode = UA_MESSAGESECURITYMODE_NONE;

	UA_OpenSecureChannelResponse openSecRe;
	UA_OpenSecureChannelResponse_init(&openSecRe);
	UA_Connection *connection = layer->mappings[layer->mappingsSize-1].connection;
	Service_OpenSecureChannel(servent->server, connection, &opnSecRq, &openSecRe);
	servent->clientmapping[servent->clientSize-1].transferdone = UA_TRUE;

	UA_Variant input;
	UA_ServentClientServerTransferDataType arg;
	struct sockaddr_in addr;
	socklen_t addrlen = sizeof(struct sockaddr_in);
	getsockname(new_client->connection.sockfd, (struct sockaddr*)&addr, &addrlen);

	arg.url = UA_String_fromChars(inet_ntoa(addr.sin_addr));
	arg.clientPort = ntohs(addr.sin_port);
	arg.serverPort = layer->port;

	UA_Variant_init(&input);
	UA_Variant_setScalarCopy(&input, &arg, &UA_TYPES[UA_TYPES_SERVENTCLIENTSERVERTRANSFERDATATYPE]);
	size_t outputSize;
	UA_Variant *output;
	retval = UA_Client_call(new_client, UA_NODEID_NUMERIC(0, UA_NS0ID_OBJECTSFOLDER),
					UA_NODEID_STRING(1, "ClientServerTransferMethod"), 1, &input, &outputSize, &output);
	if(retval == UA_STATUSCODE_GOOD)
		{
		UA_LOG_INFO(servent->server->config.logger, UA_LOGCATEGORY_SERVER, "Method call was successfull, and %lu returned values available.\n",
			   (unsigned long)outputSize);
		if (((UA_StatusCode*)output->data)[0] != UA_STATUSCODE_GOOD)
			{
			UA_LOG_ERROR(servent->server->config.logger, UA_LOGCATEGORY_NETWORK, "Method call response was bad");
			}
		UA_Array_delete(output, outputSize, &UA_TYPES[UA_TYPES_VARIANT]);
		}
	else
		{
		UA_LOG_INFO(servent->server->config.logger, UA_LOGCATEGORY_SERVER, "Method call was unsuccessfull, and %x returned values available.\n", retval);
		}
	UA_Variant_deleteMembers(&input);

	return servent->clientmapping[servent->clientSize-1].client;
	}

UA_Client * UA_Servent_TransferFunction (UA_Servent *servent, UA_ClientConfig clientconfig, const char *endpointUrl, UA_ServerNetworkLayer NetworklayerListener, UA_Int32 socket)
	{
	ServerNetworkLayerTCP *layer = NetworklayerListener.handle;

	UA_Client *new_client = UA_Client_new(clientconfig);
	if(!new_client)
		return NULL;
	new_client->servent = servent;

	ClientMapping *clientmapping_tmp = NULL;
	clientmapping_tmp = UA_realloc (servent->clientmapping, sizeof(ClientMapping) * (servent->clientSize + 1));
	if(!clientmapping_tmp)
		{
		UA_LOG_ERROR(new_client->config.logger, UA_LOGCATEGORY_NETWORK, "No memory for a new ClientMapping");
		return NULL;
		}
	servent->clientmapping = clientmapping_tmp;
	servent->clientmapping[servent->clientSize].client = new_client;
	servent->clientmapping[servent->clientSize].transferdone = UA_FALSE;
	servent->clientSize++;

	for (size_t i = 0; i < layer->mappingsSize; i++)
		{
		if (layer->mappings[i].connection->sockfd == socket)
			{
			new_client->connection = *(layer->mappings[i].connection);
			new_client->channel = *(layer->mappings[i].connection->channel);
			new_client->scRenewAt = UA_DateTime_now() + (UA_DateTime)(layer->mappings[i].connection->channel->securityToken.revisedLifetime * (UA_Double)UA_MSEC_TO_DATETIME * 0.75);
			new_client->channel.sendSequenceNumber = 0;
			new_client->channel.receiveSequenceNumber = 1;
			servent->clientmapping[servent->clientSize-1].transferdone = UA_TRUE;
			UA_StatusCode retval = UA_Client_connect_Session(new_client, endpointUrl);
			if(retval != UA_STATUSCODE_GOOD)
				{
				UA_Client_delete(new_client);
				clientmapping_tmp = NULL;
				servent->clientmapping[servent->clientSize].client = NULL;
				servent->clientmapping[servent->clientSize].transferdone = UA_FALSE;
				clientmapping_tmp = UA_realloc (servent->clientmapping, sizeof(ClientMapping) * (servent->clientSize - 1));
				if(!clientmapping_tmp)
					{
					UA_LOG_ERROR(new_client->config.logger, UA_LOGCATEGORY_NETWORK, "No memory for a new ClientMapping");
					return NULL;
					}
				servent->clientmapping = clientmapping_tmp;
				servent->clientSize--;
				return NULL;
				}
			return new_client;
			}
		}

	return NULL;
	}

static void completeMessagesServent(UA_Servent *servent, UA_Job *job)
	{
    UA_Boolean realloced = UA_FALSE;
    UA_StatusCode retval = UA_Connection_completeMessages(job->job.binaryMessage.connection,
                                                          &job->job.binaryMessage.message, &realloced);
    if(retval != UA_STATUSCODE_GOOD)
    	{
        if(retval == UA_STATUSCODE_BADOUTOFMEMORY)
            UA_LOG_WARNING(servent->server->config.logger, UA_LOGCATEGORY_NETWORK,
                       "Lost message(s) from Connection %i as memory could not be allocated",
                       job->job.binaryMessage.connection->sockfd);
        else if(retval != UA_STATUSCODE_GOOD)
            UA_LOG_INFO(servent->server->config.logger, UA_LOGCATEGORY_NETWORK,
                        "Could not merge half-received messages on Connection %i with error 0x%08x",
                        job->job.binaryMessage.connection->sockfd, retval);
        job->type = UA_JOBTYPE_NOTHING;
        return;
    	}
    if(realloced)
        job->type = UA_JOBTYPE_BINARYMESSAGE_ALLOCATED;
	}

/* Get work from the networklayer */
UA_StatusCode GetWorkFromNetworklayerServent (UA_Servent *servent, UA_UInt16 timeout)
	{
	//ToDo: Check pos and targetpos, if there are more than one messages in a job?
	size_t jobsSize;
	UA_Job *jobs = NULL;
	UA_Job *sj = NULL;


	for(size_t i = 0; i < servent->server->config.networkLayersSize; i++)
		{
		// For each Networklayer check if there is work
		UA_ServerNetworkLayer *nl = &servent->server->config.networkLayers[i];
		/* only the last networklayer waits on the timeout */
		if(i == servent->server->config.networkLayersSize-1)
			jobsSize = nl->getJobs(nl, &jobs, timeout);
		else
			jobsSize = nl->getJobs(nl, &jobs, 0);

		// If there are Jobs then they have to be completed and sorted by Request/Responses
		for(size_t k = 0; k < jobsSize; k++)
			{
			if(jobs[k].type == UA_JOBTYPE_BINARYMESSAGE_NETWORKLAYER)
				completeMessagesServent(servent, &jobs[k]);
			switch (jobs[k].type)
				{
				case UA_JOBTYPE_NOTHING: ///< Guess what?
				break;
				case UA_JOBTYPE_DETACHCONNECTION: ///< Detach the connection from the secure channel (but don't delete it)
					sj = NULL;
					sj = UA_realloc (servent->networklayerjobs[i].serverjobs, sizeof(UA_Job) * (servent->networklayerjobs[i].serverJobsSize + 1));
					if(!sj)
						{
						UA_LOG_ERROR(servent->server->config.logger, UA_LOGCATEGORY_NETWORK, "No memory for a new Job");
						return UA_STATUSCODE_BADINTERNALERROR;
						}
					servent->networklayerjobs[i].serverjobs = sj;
					servent->networklayerjobs[i].serverjobs[servent->networklayerjobs[i].serverJobsSize] = jobs[k];
					servent->networklayerjobs[i].serverJobsSize++;
				break;
				case UA_JOBTYPE_BINARYMESSAGE_NETWORKLAYER: ///< The binary message is memory managed by the networklayer
				case UA_JOBTYPE_BINARYMESSAGE_ALLOCATED: ///< The binary message was relocated away from the networklayer
					;
					size_t pos = 0;
					UA_TcpMessageHeader tcpMessageHeader;
					const UA_ByteString *msg = &jobs[k].job.binaryMessage.message;
					UA_Connection *connection = jobs[k].job.binaryMessage.connection;

					/* Decode the message header */
					UA_StatusCode retval = UA_TcpMessageHeader_decodeBinary(msg, &pos, &tcpMessageHeader);
					if(retval != UA_STATUSCODE_GOOD)
						{
						UA_LOG_INFO(servent->server->config.logger, UA_LOGCATEGORY_NETWORK,
									"Decoding of message header failed on Connection %i", connection->sockfd);
						connection->close(connection);
						break;
						}
					if(tcpMessageHeader.messageSize < 16)
						{
						UA_LOG_INFO(servent->server->config.logger, UA_LOGCATEGORY_NETWORK,
									"The message is suspiciously small on Connection %i", connection->sockfd);
						connection->close(connection);
						break;
						}

					/* Check the message if it is a request or a response */
					switch(tcpMessageHeader.messageTypeAndChunkType & 0x30000000)
						{
						case UA_RORTYPE_REQUEST:
							sj = NULL;
							sj = UA_realloc (servent->networklayerjobs[i].serverjobs, sizeof(UA_Job) * (servent->networklayerjobs[i].serverJobsSize + 1));
							if(!sj)
								{
								UA_LOG_ERROR(servent->server->config.logger, UA_LOGCATEGORY_NETWORK, "No memory for a new Job");
								return UA_STATUSCODE_BADINTERNALERROR;
								}
							servent->networklayerjobs[i].serverjobs = sj;
							servent->networklayerjobs[i].serverjobs[servent->networklayerjobs[i].serverJobsSize] = jobs[k];
							servent->networklayerjobs[i].serverJobsSize++;
						break;
						case UA_RORTYPE_RESPONSE:
							sj = NULL;
							sj = UA_realloc (servent->networklayerjobs[i].clientjobs, sizeof(UA_Job) * (servent->networklayerjobs[i].clientJobsSize + 1));
							if(!sj)
								{
								UA_LOG_ERROR(servent->server->config.logger, UA_LOGCATEGORY_NETWORK, "No memory for a new Job");
								return UA_STATUSCODE_BADINTERNALERROR;
								}
							servent->networklayerjobs[i].clientjobs = sj;
							servent->networklayerjobs[i].clientjobs[servent->networklayerjobs[i].clientJobsSize] = jobs[k];
							servent->networklayerjobs[i].clientJobsSize++;
						break;
						default:
							sj = NULL;
							sj = UA_realloc (servent->networklayerjobs[i].serverjobs, sizeof(UA_Job) * (servent->networklayerjobs[i].serverJobsSize + 1));
							if(!sj)
								{
								UA_LOG_ERROR(servent->server->config.logger, UA_LOGCATEGORY_NETWORK, "No memory for a new Job");
								return UA_STATUSCODE_BADINTERNALERROR;
								}
							servent->networklayerjobs[i].serverjobs = sj;
							servent->networklayerjobs[i].serverjobs[servent->networklayerjobs[i].serverJobsSize] = jobs[k];
							servent->networklayerjobs[i].serverJobsSize++;
						break;
						}

				break;
				case UA_JOBTYPE_METHODCALL: ///< Call the method as soon as possible
					sj = NULL;
					sj = UA_realloc (servent->networklayerjobs[i].serverjobs, sizeof(UA_Job) * (servent->networklayerjobs[i].serverJobsSize + 1));
					if(!sj)
						{
						UA_LOG_ERROR(servent->server->config.logger, UA_LOGCATEGORY_NETWORK, "No memory for a new Job");
						return UA_STATUSCODE_BADINTERNALERROR;
						}
					servent->networklayerjobs[i].serverjobs = sj;
					servent->networklayerjobs[i].serverjobs[servent->networklayerjobs[i].serverJobsSize] = jobs[k];
					servent->networklayerjobs[i].serverJobsSize++;
				break;
				case UA_JOBTYPE_METHODCALL_DELAYED: ///< Call the method as soon as all previous jobs have finished
					sj = NULL;
					sj = UA_realloc (servent->networklayerjobs[i].serverjobs, sizeof(UA_Job) * (servent->networklayerjobs[i].serverJobsSize + 1));
					if(!sj)
						{
						UA_LOG_ERROR(servent->server->config.logger, UA_LOGCATEGORY_NETWORK, "No memory for a new Job");
						return UA_STATUSCODE_BADINTERNALERROR;
						}
					servent->networklayerjobs[i].serverjobs = sj;
					servent->networklayerjobs[i].serverjobs[servent->networklayerjobs[i].serverJobsSize] = jobs[k];
					servent->networklayerjobs[i].serverJobsSize++;
				break;
				default:
				break;
				}
			}
		}
	return UA_STATUSCODE_GOOD;
	}
