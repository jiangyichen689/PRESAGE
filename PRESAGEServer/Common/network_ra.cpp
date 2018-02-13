/**
*   Copyright(C) 2011-2015 Intel Corporation All Rights Reserved.
*
*   The source code, information  and  material ("Material") contained herein is
*   owned  by Intel Corporation or its suppliers or licensors, and title to such
*   Material remains  with Intel Corporation  or its suppliers or licensors. The
*   Material  contains proprietary information  of  Intel or  its  suppliers and
*   licensors. The  Material is protected by worldwide copyright laws and treaty
*   provisions. No  part  of  the  Material  may  be  used,  copied, reproduced,
*   modified, published, uploaded, posted, transmitted, distributed or disclosed
*   in any way  without Intel's  prior  express written  permission. No  license
*   under  any patent, copyright  or  other intellectual property rights  in the
*   Material  is  granted  to  or  conferred  upon  you,  either  expressly,  by
*   implication, inducement,  estoppel or  otherwise.  Any  license  under  such
*   intellectual  property  rights must  be express  and  approved  by  Intel in
*   writing.
*
*   *Third Party trademarks are the property of their respective owners.
*
*   Unless otherwise  agreed  by Intel  in writing, you may not remove  or alter
*   this  notice or  any other notice embedded  in Materials by Intel or Intel's
*   suppliers or licensors in any way.
*/


#include <stdint.h>
#ifdef _MSC_VER
#endif
#include <stdlib.h>
#include <stdio.h>
#include "network_ra.h"
#include "Socket.h"
#include "service_provider.h"
#include <winsock2.h> 
#include <ws2tcpip.h>

// Used to send requests to the service provider sample.  It
// simulates network communication between the ISV app and the
// ISV service provider.  This would be modified in a real
// product to use the proper IP communication.
//
// @param server_url String name of the server URL
// @param p_req Pointer to the message to be sent.
// @param p_resp Pointer to a pointer of the response message.

// @return int

int ra_network_send_receive(Socket *S, int socket_fd,
    const ra_samp_request_header_t *p_req,
    ra_samp_response_header_t **p_resp)
{
	int ret = 0;
    ra_samp_response_header_t* p_resp_msg;

    switch(p_req->type)
    {

        case TYPE_RA_MSG1:
        /*ret = sp_ra_proc_msg1_req((const sample_ra_msg1_t*)((uint8_t*)p_req
            + sizeof(ra_samp_request_header_t)),
            p_req->size,
            &p_resp_msg);*/

		//send msg1
		int size = sizeof(sample_ra_msg1_t);
#if defined ATTESTATION_DEBUG
		printf( "sent size:%d\n", size);
#endif
		S->Send(socket_fd, (char *)(&size), sizeof(int));
		S->Send(socket_fd, (char *)(p_req->body), size);

#if defined ATTESTATION_DEBUG
		printf("msg1 sent! \n");
#endif		
		
		//receive msg2
		char *msg2;
		int length = 0;
		int pos = 0;
		int recvLength;
		while(true)
		{
			if (!length)
			{
				if(S->Recv(socket_fd,(char*)&length,4)!=4) 
				{
					printf("CLIENT: Recv Error! Error code: %i\n", GetLastError());
					return 0;
				}
				msg2 = new char[length];
			}
			else
			{
				while (pos < length)
				{
					recvLength = S->Recv(socket_fd, msg2+pos,length-pos);
					if (recvLength < 0)
					{
						printf("CLIENT: Recv Error! Error code: %i\n", GetLastError());
						return 0;
					}
					pos += recvLength;
				}
				break;
			}
		}
		
		if (length >= 0)
		{
			*p_resp = (ra_samp_response_header_t*) msg2;
		}
#if defined ATTESTATION_DEBUG
		printf( "msg2 received!\n");
#endif
        if(0 != ret)
        {
            fprintf(stderr, "\nError, call sp_ra_proc_msg1_req fail [%s].",
                __FUNCTION__);
        }
      
        break;

        
		case TYPE_RA_MSG3:
        
		//send msg3
		size = 1452;

#if defined ATTESTATION_DEBUG
		printf("sent size: %d\n", size);
#endif

		S->Send(socket_fd, (char *)(&size), sizeof(int));
		S->Send(socket_fd, (char *)(p_req->body), size);
#if defined ATTESTATION_DEBUG
		printf("msg3 sent! \n");
#endif

		
        break;

        default:
        ret = -1;
        fprintf(stderr, "\nError, unknown ra message type. Type = %d [%s].",
            p_req->type, __FUNCTION__);
        break;
    }

    return ret;
}

// Used to free the response messages.  In the sample code, the
// response messages are allocated by the SP code.
//
//
// @param resp Pointer to the response buffer to be freed.

void ra_free_network_response_buffer(ra_samp_response_header_t *resp)
{
    if(resp!=NULL)
    {
        free(resp);
    }
}
