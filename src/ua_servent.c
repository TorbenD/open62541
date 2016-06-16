/*
 * ua_servent.c
 *
 *  Created on: 16.06.2016
 *      Author: root
 */

#include "ua_servent.h"
#include "ua_types.h"
#include "ua_client.h"
#include "ua_util.h"
#include "ua_connection_internal.h"
#include "ua_server.h"
#include "ua_constants.h"
#include "..//src_generated//ua_transport_generated_encoding_binary.h"
#include "..//src//server//ua_server_internal.h"

UA_Servent * UA_Servent_new(void)
	{
    UA_Servent *servent = UA_calloc(1, sizeof(UA_Servent));
    if(!servent)
        return NULL;
    servent->transfer = UA_FALSE;
    return servent;
	}

void UA_Servent_delete(UA_Servent* servent)
	{
    UA_free(servent);
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
					if (servent->networklayerjobs[i].serverJobsSize > 0)
						sj = UA_realloc (servent->networklayerjobs[i].serverjobs, sizeof(UA_Job) * (servent->networklayerjobs[i].serverJobsSize + 1));
					else
						sj = UA_malloc(sizeof(UA_Job) * (servent->networklayerjobs[i].serverJobsSize + 1));
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
							if (servent->networklayerjobs[i].serverJobsSize > 0)
								sj = UA_realloc (servent->networklayerjobs[i].serverjobs, sizeof(UA_Job) * (servent->networklayerjobs[i].serverJobsSize + 1));
							else
								sj = UA_malloc(sizeof(UA_Job) * (servent->networklayerjobs[i].serverJobsSize + 1));
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
							if (servent->networklayerjobs[i].clientJobsSize > 0)
								sj = UA_realloc (servent->networklayerjobs[i].clientjobs, sizeof(UA_Job) * (servent->networklayerjobs[i].clientJobsSize + 1));
							else
								sj = UA_malloc(sizeof(UA_Job) * (servent->networklayerjobs[i].clientJobsSize + 1));
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
							if (servent->networklayerjobs[i].serverJobsSize > 0)
								sj = UA_realloc (servent->networklayerjobs[i].serverjobs, sizeof(UA_Job) * (servent->networklayerjobs[i].serverJobsSize + 1));
							else
								sj = UA_malloc(sizeof(UA_Job) * (servent->networklayerjobs[i].serverJobsSize + 1));
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
					if (servent->networklayerjobs[i].serverJobsSize > 0)
						sj = UA_realloc (servent->networklayerjobs[i].serverjobs, sizeof(UA_Job) * (servent->networklayerjobs[i].serverJobsSize + 1));
					else
						sj = UA_malloc(sizeof(UA_Job) * (servent->networklayerjobs[i].serverJobsSize + 1));
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
					if (servent->networklayerjobs[i].serverJobsSize > 0)
						sj = UA_realloc (servent->networklayerjobs[i].serverjobs, sizeof(UA_Job) * (servent->networklayerjobs[i].serverJobsSize + 1));
					else
						sj = UA_malloc(sizeof(UA_Job) * (servent->networklayerjobs[i].serverJobsSize + 1));
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
