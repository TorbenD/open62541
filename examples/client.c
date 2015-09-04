#ifdef UA_NO_AMALGAMATION
# include "ua_types.h"
# include "ua_client.h"
# include "ua_nodeids.h"
# include "networklayer_tcp.h"
# include "logger_stdout.h"
# include "ua_types_encoding_binary.h"
#include "server/ua_nodes.h"
#else
# include "open62541.h"
# include <string.h>
# include <stdlib.h>
#endif
#include <stdio.h>

void handler_TheAnswerChanged(UA_UInt32 handle, UA_DataValue *value);
void handler_TheAnswerChanged(UA_UInt32 handle, UA_DataValue *value) {
    printf("The Answer has changed!\n");
    return;
}

UA_StatusCode nodeIter(UA_NodeId childId, UA_Boolean isInverse, UA_NodeId referenceTypeId, void *handle);
UA_StatusCode nodeIter(UA_NodeId childId, UA_Boolean isInverse, UA_NodeId referenceTypeId, void *handle) {  
  UA_Client *client = (UA_Client *) handle;
  
  if(childId.identifierType == UA_NODEIDTYPE_STRING)
    printf("%-9d %-16.*s ", childId.namespaceIndex, childId.identifier.string.length, childId.identifier.string.data);
  else
    printf("%-9d %-16d ", childId.namespaceIndex, childId.identifier.numeric);
  
  if (client != NULL) {
    UA_QualifiedName *browseName  = NULL;
    UA_LocalizedText *displayName = NULL;
    UA_Client_getAttribute_browseName(client, childId, &browseName);
    UA_Client_getAttribute_displayName(client, childId, &displayName);
    printf("%-16.*s %-16.*s", browseName->name.length, browseName->name.data, displayName->text.length, displayName->text.data);
  }
  if (isInverse == UA_TRUE) {
    printf(" (inverse)");
  }
  printf("\n");
  
  return UA_STATUSCODE_GOOD;
}

int main(int argc, char *argv[]) {
    UA_Client *client = UA_Client_new(UA_ClientConfig_standard, Logger_Stdout_new());
    UA_StatusCode retval = UA_Client_connect(client, ClientNetworkLayerTCP_connect,
                                             "opc.tcp://localhost:16664");

    if(retval != UA_STATUSCODE_GOOD) {
        UA_Client_delete(client);
        return retval;
    }
    // Browse some objects
    printf("Browsing nodes in objects folder:\n");

    UA_BrowseRequest bReq;
    UA_BrowseRequest_init(&bReq);
    bReq.requestedMaxReferencesPerNode = 0;
    bReq.nodesToBrowse = UA_BrowseDescription_new();
    bReq.nodesToBrowseSize = 1;
    bReq.nodesToBrowse[0].nodeId = UA_NODEID_NUMERIC(0, UA_NS0ID_OBJECTSFOLDER); //browse objects folder
    bReq.nodesToBrowse[0].resultMask = UA_BROWSERESULTMASK_ALL; //return everything

    UA_BrowseResponse bResp = UA_Client_browse(client, &bReq);
    printf("%-9s %-16s %-16s %-16s\n", "NAMESPACE", "NODEID", "BROWSE NAME", "DISPLAY NAME");
    for (int i = 0; i < bResp.resultsSize; ++i) {
        for (int j = 0; j < bResp.results[i].referencesSize; ++j) {
            UA_ReferenceDescription *ref = &(bResp.results[i].references[j]);
            if(ref->nodeId.nodeId.identifierType == UA_NODEIDTYPE_NUMERIC) {
                printf("%-9d %-16d %-16.*s %-16.*s\n", ref->browseName.namespaceIndex,
                       ref->nodeId.nodeId.identifier.numeric, ref->browseName.name.length,
                       ref->browseName.name.data, ref->displayName.text.length, ref->displayName.text.data);
            } else if(ref->nodeId.nodeId.identifierType == UA_NODEIDTYPE_STRING) {
                printf("%-9d %-16.*s %-16.*s %-16.*s\n", ref->browseName.namespaceIndex,
                       ref->nodeId.nodeId.identifier.string.length, ref->nodeId.nodeId.identifier.string.data,
                       ref->browseName.name.length, ref->browseName.name.data, ref->displayName.text.length,
                       ref->displayName.text.data);
            }
            //TODO: distinguish further types
        }
    }
    UA_BrowseRequest_deleteMembers(&bReq);
    UA_BrowseResponse_deleteMembers(&bResp);
    
#ifdef ENABLE_SUBSCRIPTIONS
    // Create a subscription with interval 0 (immediate)...
    UA_Int32 subId = UA_Client_newSubscription(client, 0);
    if (subId)
        printf("Create subscription succeeded, id %u\n", subId);
    
    // .. and monitor TheAnswer
    UA_NodeId monitorThis;
    monitorThis = UA_NODEID_STRING_ALLOC(1, "the.answer");
    UA_UInt32 monId = UA_Client_monitorItemChanges(client, subId, monitorThis, UA_ATTRIBUTEID_VALUE, &handler_TheAnswerChanged );
    if (monId)
        printf("Monitoring 'the.answer', id %u\n", subId);
    UA_NodeId_deleteMembers(&monitorThis);
    
    // First Publish always generates data (current value) and call out handler.
    UA_Client_doPublish(client);
    
    // This should not generate anything
    UA_Client_doPublish(client);
#endif
    
    UA_Int32 value = 0;
    // Read node's value
    printf("\nReading the value of node (1, \"the.answer\"):\n");
    UA_ReadRequest rReq;
    UA_ReadRequest_init(&rReq);
    rReq.nodesToRead = UA_ReadValueId_new();
    rReq.nodesToReadSize = 1;
    rReq.nodesToRead[0].nodeId = UA_NODEID_STRING_ALLOC(1, "the.answer"); /* assume this node exists */
    rReq.nodesToRead[0].attributeId = UA_ATTRIBUTEID_VALUE;

    UA_ReadResponse rResp = UA_Client_read(client, &rReq);
    if(rResp.responseHeader.serviceResult == UA_STATUSCODE_GOOD &&
       rResp.resultsSize > 0 && rResp.results[0].hasValue &&
       UA_Variant_isScalar(&rResp.results[0].value) &&
       rResp.results[0].value.type == &UA_TYPES[UA_TYPES_INT32]) {
        value = *(UA_Int32*)rResp.results[0].value.data;
        printf("the value is: %i\n", value);
    }

    UA_ReadRequest_deleteMembers(&rReq);
    UA_ReadResponse_deleteMembers(&rResp);

    value++;
    // Write node's value
    printf("\nWriting a value of node (1, \"the.answer\"):\n");
    UA_WriteRequest wReq;
    UA_WriteRequest_init(&wReq);
    wReq.nodesToWrite = UA_WriteValue_new();
    wReq.nodesToWriteSize = 1;
    wReq.nodesToWrite[0].nodeId = UA_NODEID_STRING_ALLOC(1, "the.answer"); /* assume this node exists */
    wReq.nodesToWrite[0].attributeId = UA_ATTRIBUTEID_VALUE;
    wReq.nodesToWrite[0].value.hasValue = UA_TRUE;
    wReq.nodesToWrite[0].value.value.type = &UA_TYPES[UA_TYPES_INT32];
    wReq.nodesToWrite[0].value.value.storageType = UA_VARIANT_DATA_NODELETE; //do not free the integer on deletion
    wReq.nodesToWrite[0].value.value.data = &value;
    
    UA_WriteResponse wResp = UA_Client_write(client, &wReq);
    if(wResp.responseHeader.serviceResult == UA_STATUSCODE_GOOD)
            printf("the new value is: %i\n", value);
    UA_WriteRequest_deleteMembers(&wReq);
    UA_WriteResponse_deleteMembers(&wResp);

#ifdef ENABLE_SUBSCRIPTIONS
    // Take another look at the.answer... this should call the handler.
    UA_Client_doPublish(client);
    
    // Delete our subscription (which also unmonitors all items)
    if(!UA_Client_removeSubscription(client, subId))
        printf("Subscription removed\n");
#endif
    
#ifdef ENABLE_METHODCALLS
    /* Note:  This example requires Namespace 0 Node 11489 (ServerType -> GetMonitoredItems) 
       FIXME: Provide a namespace 0 independant example on the server side
     */
    UA_Variant input;
    
    UA_String argString = UA_STRING("Hello Server");
    UA_Variant_init(&input);
    UA_Variant_setScalarCopy(&input, &argString, &UA_TYPES[UA_TYPES_STRING]);
    
    UA_Int32 outputSize;
    UA_Variant *output;
    
    retval = UA_Client_callServerMethod(client, UA_NODEID_NUMERIC(0, UA_NS0ID_OBJECTSFOLDER),
                                        UA_NODEID_NUMERIC(1, 62541), 1, &input, &outputSize, &output);
    if(retval == UA_STATUSCODE_GOOD) {
        printf("Method call was successfull, and %i returned values available.\n", outputSize);
        UA_Array_delete(output, &UA_TYPES[UA_TYPES_VARIANT], outputSize);
    } else {
        printf("Method call was unsuccessfull, and %x returned values available.\n", retval);
    }
    UA_Variant_deleteMembers(&input);

#endif

#ifdef ENABLE_ADDNODES 
    /* Create a new object type node */
    // New ReferenceType
    UA_StatusCode addRes;
    UA_NodeId retNodeId;
    addRes = UA_Client_addReferenceTypeNode(client,
        UA_NODEID_NUMERIC(1, 12133), // Assign this NodeId (will fail if client is called multiple times)
        UA_QUALIFIEDNAME(0, "NewReference"),
        UA_LOCALIZEDTEXT("en_US", "TheNewReference"),
        UA_LOCALIZEDTEXT("en_US", "References something that might or might not exist."),
        UA_EXPANDEDNODEID_NUMERIC(0, UA_NS0ID_OBJECTSFOLDER),
        UA_NODEID_NUMERIC(0, UA_NS0ID_ORGANIZES),
        (UA_UInt32) 0, (UA_UInt32) 0, 
        UA_EXPANDEDNODEID_NUMERIC(0, UA_NS0ID_OBJECTSFOLDER),
        UA_LOCALIZEDTEXT("en_US", "IsNewlyReferencedBy"),
        &retNodeId);
    if (addRes == UA_STATUSCODE_GOOD ) {
      printf("Created 'NewReference' with numeric NodeID %u\n", retNodeId.identifier.numeric );
    }
    
    // New ObjectType
    addRes = UA_Client_addObjectTypeNode(client,    
        UA_NODEID_NUMERIC(1, 12134), // Assign this NodeId (will fail if client is called multiple times)
        UA_QUALIFIEDNAME(0, "NewObjectType"),
        UA_LOCALIZEDTEXT("en_US", "TheNewObjectType"),
        UA_LOCALIZEDTEXT("en_US", "Put innovative description here."),
        UA_EXPANDEDNODEID_NUMERIC(0, UA_NS0ID_OBJECTSFOLDER),
        UA_NODEID_NUMERIC(0, UA_NS0ID_ORGANIZES),
        (UA_UInt32) 0, (UA_UInt32) 0, 
        UA_EXPANDEDNODEID_NUMERIC(0, UA_NS0ID_OBJECTSFOLDER), 
        UA_FALSE,
        &retNodeId);
    if (addRes == UA_STATUSCODE_GOOD ) {
      printf("Created 'NewObjectType' with numeric NodeID %u\n", retNodeId.identifier.numeric );
    }
    
    // New Object
    addRes = UA_Client_addObjectNode(client,    
        UA_NODEID_NUMERIC(1, 0), // Assign new/random NodeID  
        UA_QUALIFIEDNAME(0, "TheNewGreatNodeBrowseName"),
        UA_LOCALIZEDTEXT("en_US", "TheNewGreatNode"),
        UA_LOCALIZEDTEXT("de_DE", "Hier koennte Ihre Webung stehen!"),
        UA_EXPANDEDNODEID_NUMERIC(0, UA_NS0ID_OBJECTSFOLDER),
        UA_NODEID_NUMERIC(0, UA_NS0ID_ORGANIZES),
        (UA_UInt32) 0, (UA_UInt32) 0, 
        UA_EXPANDEDNODEID_NUMERIC(0, UA_NS0ID_OBJECTSFOLDER), 
        &retNodeId);
    if (addRes == UA_STATUSCODE_GOOD ) {
      printf("Created 'NewObject' with numeric NodeID %u\n", retNodeId.identifier.numeric );
    }
    
    // New Integer Variable
    UA_Variant *theValue = UA_Variant_new();
    UA_Int32 *theValueDate = UA_Int32_new();
    *theValueDate = 1234;
    theValue->type = &UA_TYPES[UA_TYPES_INT32];
    theValue->data = theValueDate;
    
    addRes = UA_Client_addVariableNode(client,
        UA_NODEID_NUMERIC(1, 0), // Assign new/random NodeID  
        UA_QUALIFIEDNAME(0, "VariableNode"),
        UA_LOCALIZEDTEXT("en_US", "TheNewVariableNode"),
        UA_LOCALIZEDTEXT("en_US", "This integer is just amazing - it has digits and everything."),
        UA_EXPANDEDNODEID_NUMERIC(0, UA_NS0ID_OBJECTSFOLDER),
        UA_NODEID_NUMERIC(0, UA_NS0ID_ORGANIZES),
        (UA_UInt32) 0, (UA_UInt32) 0, 
        theValue, 
        &retNodeId);
    if (addRes == UA_STATUSCODE_GOOD ) {
      printf("Created 'NewVariable' with numeric NodeID %u\n", retNodeId.identifier.numeric );
    }

    free(theValue);
    /* Done creating a new node*/
#else
  // retNodeId is needed for the next test
  UA_NodeId retNodeId = UA_NODEID_STRING(1, "the.answer");
#endif
  // Iterate over all nodes in 'Objects'
  UA_Client_forEachChildNodeCall(client, UA_NODEID_NUMERIC(0, UA_NS0ID_OBJECTSFOLDER), nodeIter, (void *) client);
    
  // Get a copy of the node 'TheNewVariableNode' and delete it
  void *theCopy;
  UA_Client_getNodeCopy(client, retNodeId, (void*) &theCopy);
  UA_Client_deleteNodeCopy(client, &theCopy);
  
  // Delete a serverside node
  UA_Client_deleteMethodNode(client, UA_NODEID_NUMERIC(1,62541));
  
  // Set a localized string version of "Objects"
  UA_LocalizedText objectsLocale = UA_LOCALIZEDTEXT("de_DE", "Die Objekte");
  UA_Client_setAttributeValue(client, UA_NODEID_NUMERIC(0, UA_NS0ID_OBJECTSFOLDER), UA_ATTRIBUTEID_WRITEMASK, (void *) &objectsLocale);
  
  UA_Client_disconnect(client);
  UA_Client_delete(client);
  return UA_STATUSCODE_GOOD;
}

