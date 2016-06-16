/* This work is licensed under a Creative Commons CCZero 1.0 Universal License.
 * See http://creativecommons.org/publicdomain/zero/1.0/ for more information. */

#include <stdio.h>
#include <inttypes.h>

#ifdef UA_NO_AMALGAMATION
# include "ua_client.h"
# include "ua_config_standard.h"
# include "ua_network_tcp.h"
#else
# include "open62541.h"
#endif
#include "networklayer_tcp.h"
#include "..//src//client//ua_client_internal.h"
#include "..//src//server//ua_services.h"
#include "ua_server.h"
#include "..//src//server//ua_server_internal.h"

#ifdef UA_ENABLE_SERVENT
	#include "ua_servent.h"
#endif


UA_Boolean running = true;
int a0 = 1;
int a1 = 1;
int a2 = 0;
int a3 = 0;
int count = 0;
static void stopHandler(int sig) {
    running = false;
}

int main(void) {

#ifdef UA_ENABLE_SERVENT
	UA_Servent *servent = UA_Servent_new();
	servent->client = UA_Client_new(UA_ClientConfig_standard);
	servent->client->servent = servent;

    UA_ServerConfig config = UA_ServerConfig_standard;
	UA_ServerNetworkLayer nl = UA_ServerNetworkLayerTCP(UA_ConnectionConfig_standard, 16665);
	config.networkLayers = &nl;
	config.networkLayersSize = 1;
	servent->server = UA_Server_new(config);
	servent->server->servent = servent;

	UA_NetworklayerJobs networklayerjobs[config.networkLayersSize];
	servent->networklayerjobs = networklayerjobs;
	for(size_t i = 0; i < config.networkLayersSize; i++)
		{
		servent->networklayerjobs[i].clientJobsSize = 0;
		servent->networklayerjobs[i].clientjobs = NULL;
		servent->networklayerjobs[i].serverJobsSize = 0;
		servent->networklayerjobs[i].serverjobs = NULL;
		}
	UA_StatusCode retval = UA_Server_run_startup(servent->server);
	ServerNetworkLayerTCP *layer = nl.handle;

    while (running)
		{
    	retval = UA_Server_run_iterate(servent->server, true);
    	if (a0 == 1)
    		{
    		retval = UA_Client_connect(servent->client, "opc.tcp://localhost:16664");
			if(retval != UA_STATUSCODE_GOOD)
				{
				UA_Client_delete(servent->client);
				return (int)retval;
				}
			printf("\nServerSocket: %d", layer->serversockfd);
			for(size_t i = 0; i < layer->mappingsSize; i++)
				printf("\n Layer [%lu] Socket: %d", i , layer->mappings[i].sockfd);
			printf("\nClientSocket: %d", servent->client->connection.sockfd);
			a0 = 0;
    		}
    	if (a1 == 1)
			{
			retval = ServerNetworkLayerTCP_add(layer, servent->client->connection.sockfd);
			layer->mappings[0].connection = &servent->client->connection;
			layer->mappings[0].connection->channel = &servent->client->channel;

			UA_OpenSecureChannelRequest opnSecRq;
			UA_OpenSecureChannelRequest_init(&opnSecRq);
			opnSecRq.requestHeader.timestamp = UA_DateTime_now();
			opnSecRq.requestHeader.authenticationToken = servent->client->authenticationToken;
			opnSecRq.requestedLifetime = servent->client->config.secureChannelLifeTime;
			opnSecRq.requestType = UA_SECURITYTOKENREQUESTTYPE_ISSUE;
			UA_ByteString_copy(&servent->client->channel.clientNonce, &opnSecRq.clientNonce);
			opnSecRq.securityMode = UA_MESSAGESECURITYMODE_NONE;

			UA_OpenSecureChannelResponse openSecRe;
			UA_OpenSecureChannelResponse_init(&openSecRe);
			UA_Connection *connection = layer->mappings[0].connection;
			Service_OpenSecureChannel(servent->server, connection, &opnSecRq, &openSecRe);

			servent->transfer = UA_TRUE;
			printf("\nServerSocket: %d", layer->serversockfd);
			for(size_t i = 0; i < layer->mappingsSize; i++)
				printf("\n Layer [%lu] Socket: %d", i , layer->mappings[i].sockfd);
			printf("\nClientSocket: %d", servent->client->connection.sockfd);
			a1 = 0;
			}
    	if (a2 == 1)
    		{
    		count++;
    		if (count % 100000000)
    			{
			//variables to store data
			UA_DateTime raw_date = 0;
			UA_String string_date;

			UA_ReadRequest rReq;
			UA_ReadRequest_init(&rReq);
			rReq.nodesToRead = UA_Array_new(1, &UA_TYPES[UA_TYPES_READVALUEID]);
			rReq.nodesToReadSize = 1;
			rReq.nodesToRead[0].nodeId = UA_NODEID_NUMERIC(0, 2258);
			rReq.nodesToRead[0].attributeId = UA_ATTRIBUTEID_VALUE;

			UA_ReadResponse rResp = UA_Client_Service_read(servent->client, rReq);
			if(rResp.responseHeader.serviceResult == UA_STATUSCODE_GOOD && rResp.resultsSize > 0 &&
			   rResp.results[0].hasValue && UA_Variant_isScalar(&rResp.results[0].value) &&
			   rResp.results[0].value.type == &UA_TYPES[UA_TYPES_DATETIME])
				{
				raw_date = *(UA_DateTime*)rResp.results[0].value.data;
				printf("raw date is: %" PRId64 "\n", raw_date);
				string_date = UA_DateTime_toString(raw_date);
				printf("string date is: %.*s\n", (int)string_date.length, string_date.data);
				}
			UA_ReadRequest_deleteMembers(&rReq);
			UA_ReadResponse_deleteMembers(&rResp);
			UA_String_deleteMembers(&string_date);
			printf("\nServerSocket: %d", layer->serversockfd);
			for(size_t i = 0; i < layer->mappingsSize; i++)
				printf("\n Layer [%lu] Socket: %d", i , layer->mappings[i].sockfd);
			printf("\nClientSocket: %d", servent->client->connection.sockfd);
    		}
    		}
		};

    UA_Client_disconnect(servent->client);
    UA_Client_delete(servent->client);
    UA_Server_delete(servent->server);
	UA_Servent_delete(servent);
#endif
    return (int) UA_STATUSCODE_GOOD;
}
