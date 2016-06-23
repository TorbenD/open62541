//This file contains source-code that is discussed in a tutorial located here:
//http://open62541.org/doc/sphinx/tutorial_firstStepsClient.html

#include <stdio.h>
#include <inttypes.h>

#ifdef UA_NO_AMALGAMATION
# include "ua_client.h"
# include "ua_config_standard.h"
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
int a1 = 0;
int count = 0;
static void stopHandler(int sig) {
    running = false;
}

int main(void) {

#ifdef UA_ENABLE_SERVENT

    UA_ServerConfig config = UA_ServerConfig_standard;
	UA_ServerNetworkLayer nl = UA_ServerNetworkLayerTCP(UA_ConnectionConfig_standard, 16665);
	config.networkLayers = &nl;
	config.networkLayersSize = 1;

	UA_Servent *servent = UA_Servent_new(config);
	UA_Client *client = NULL;

	UA_StatusCode retval = UA_Server_run_startup(servent->server);

    while (running)
		{
    	retval = UA_Server_run_iterate(servent->server, true);
    	if (a0 == 1)
    		{
    		client = UA_Servent_connect(servent, UA_ClientConfig_standard, "opc.tcp://127.0.0.1:16664", nl);
			if(!client)
				{
				printf("\nClient could not connect");
				return (int)retval;
				}
			a0 = 0;
    		}
    	if (a1 == 1)
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

			UA_ReadResponse rResp = UA_Client_Service_read(client, rReq);
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
    		}
    		}
		};
	UA_Servent_delete(servent);
	nl.deleteMembers(&nl);
#endif
    return (int) UA_STATUSCODE_GOOD;
}
