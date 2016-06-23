/*
 * ua_services_servent.c
 *
 *  Created on: 23.06.2016
 *      Author: root
 */

#include "ua_services.h"
#include "ua_server_internal.h"
#include <netinet/in.h>
#include <arpa/inet.h>
#include "ua_servent.h"

void Service_ClientServerTransfer(UA_Server *server, UA_SecureChannel *channel, UA_Session *session, const UA_ServentClientServerTransferRequest *request,
		UA_ServentClientServerTransferResponse *response)
	{
    UA_LOG_DEBUG_SESSION(server->config.logger, session, "Processing ClientServerTransfer");

    // Only for TCP
    struct sockaddr_in addr;
	socklen_t addrlen = sizeof(struct sockaddr_in);
	getpeername(channel->connection->sockfd, (struct sockaddr*)&addr, &addrlen);

	UA_String add_tmp = UA_String_fromChars(inet_ntoa(addr.sin_addr));
	UA_UInt16 clientport_tmp = ntohs(addr.sin_port);
	// End TCP

	for (size_t i = 0; i < server->servent->clientserverrelationSize; i++)
		{
		if (UA_String_equal(&(server->servent->clientserverrelation[server->servent->clientserverrelationSize].endpointUrl), &add_tmp) &&
			server->servent->clientserverrelation[server->servent->clientserverrelationSize].clientport == clientport_tmp &&
			server->servent->clientserverrelation[server->servent->clientserverrelationSize].serverport == request->serverPort)
			return;
		}

	ClientServerRelation *clientserverrelation_tmp = NULL;
	clientserverrelation_tmp = UA_realloc (server->servent->clientserverrelation, sizeof(ClientServerRelation) * (server->servent->clientserverrelationSize + 1));
	if(!clientserverrelation_tmp)
		{
		UA_LOG_ERROR(server->config.logger, UA_LOGCATEGORY_NETWORK, "No memory for a new ClientServerRelation");
		return;
		}
	server->servent->clientserverrelation = clientserverrelation_tmp;
	server->servent->clientserverrelation[server->servent->clientserverrelationSize].clientport = clientport_tmp;
	server->servent->clientserverrelation[server->servent->clientserverrelationSize].serverport = request->serverPort;
	server->servent->clientserverrelation[server->servent->clientserverrelationSize].endpointUrl = add_tmp;
	server->servent->clientserverrelation[server->servent->clientserverrelationSize].socket = channel->connection->sockfd;
	server->servent->clientserverrelationSize++;

	return;
	}
