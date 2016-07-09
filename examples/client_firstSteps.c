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

int main(void) {
    UA_Client *client = UA_Client_new(UA_ClientConfig_standard);
    UA_StatusCode retval = UA_Client_connect(client, "opc.tcp://127.0.0.1:16664");
    if(retval != UA_STATUSCODE_GOOD) {
        UA_Client_delete(client);
        return (int)retval;
    }
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
       rResp.results[0].value.type == &UA_TYPES[UA_TYPES_DATETIME]) {
        raw_date = *(UA_DateTime*)rResp.results[0].value.data;
        printf("raw date is: %" PRId64 "\n", raw_date);
        string_date = UA_DateTime_toString(raw_date);
        printf("string date is: %.*s\n", (int)string_date.length, string_date.data);
    }

    UA_ReadRequest_deleteMembers(&rReq);
    UA_ReadResponse_deleteMembers(&rResp);
    UA_String_deleteMembers(&string_date);

    UA_Client_disconnect(client);
    UA_Client_delete(client);

    UA_Client *client2 = UA_Client_new(UA_ClientConfig_standard);
    retval = UA_Client_connect(client2, "opc.tcp://127.0.0.1:16664");
    if(retval != UA_STATUSCODE_GOOD) {
        UA_Client_delete(client2);
        return (int)retval;
    }
    //variables to store data
    UA_DateTime raw_date2 = 0;
    UA_String string_date2;

    UA_ReadRequest rReq2;
    UA_ReadRequest_init(&rReq2);
    rReq2.nodesToRead = UA_Array_new(1, &UA_TYPES[UA_TYPES_READVALUEID]);
    rReq2.nodesToReadSize = 1;
    rReq2.nodesToRead[0].nodeId = UA_NODEID_NUMERIC(0, 2258);
    rReq2.nodesToRead[0].attributeId = UA_ATTRIBUTEID_VALUE;

    UA_ReadResponse rResp2 = UA_Client_Service_read(client2, rReq2);
    if(rResp2.responseHeader.serviceResult == UA_STATUSCODE_GOOD && rResp2.resultsSize > 0 &&
       rResp2.results[0].hasValue && UA_Variant_isScalar(&rResp2.results[0].value) &&
       rResp2.results[0].value.type == &UA_TYPES[UA_TYPES_DATETIME]) {
        raw_date2 = *(UA_DateTime*)rResp2.results[0].value.data;
        printf("raw date is: %" PRId64 "\n", raw_date2);
        string_date2 = UA_DateTime_toString(raw_date2);
        printf("string date is: %.*s\n", (int)string_date2.length, string_date2.data);
    }

    UA_ReadRequest_deleteMembers(&rReq2);
    UA_ReadResponse_deleteMembers(&rResp2);
    UA_String_deleteMembers(&string_date2);

    UA_Client_disconnect(client2);
    UA_Client_delete(client2);
    return (int) UA_STATUSCODE_GOOD;
}
