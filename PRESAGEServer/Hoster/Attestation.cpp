#include <stdio.h>
#include <limits.h>
#include <ctime>
// Needed for definition of remote attestation messages.
#include "remote_attestation_result.h"

// Needed to call untrusted key exchange library APIs, i.e. sgx_ra_proc_msg2.
#include "sgx_ukey_exchange.h"

// Needed to create enclave and do ecall.
#include "sgx_urts.h"
#include "network_ra.h"
#include "Debug_Flags.h"

#include "Basic.h";

#ifndef SAFE_FREE
#define SAFE_FREE(ptr) {if (NULL != (ptr)) {free(ptr); (ptr) = NULL;}}
#endif

void PRINT_BYTE_ARRAY(
	FILE *file, void *mem, uint32_t len)
{
	if(!mem || !len)
	{
		fprintf(file, "\n( null )\n");
		return;
	}
	uint8_t *array = (uint8_t *)mem;
	fprintf(file, "%u bytes:\n{\n", len);
	uint32_t i = 0;
	for(i = 0; i < len - 1; i++)
	{
		fprintf(file, "0x%x, ", array[i]);
		if(i % 8 == 7) fprintf(file, "\n");
	}
	fprintf(file, "0x%x ", array[i]);
	fprintf(file, "\n}\n");
}


void PRINT_ATTESTATION_SERVICE_RESPONSE(
	FILE *file,
	ra_samp_response_header_t *response)
{
	if(!response)
	{
		fprintf(file, "\t\n( null )\n");
		return;
	}

	fprintf(file, "RESPONSE TYPE:   0x%x\n", response->type);
	fprintf(file, "RESPONSE STATUS: 0x%x 0x%x\n", response->status[0],
		response->status[1]);
	fprintf(file, "RESPONSE BODY SIZE: %u\n", response->size);

	if(response->type == TYPE_RA_MSG2)
	{
		sgx_ra_msg2_t* p_msg2_body = (sgx_ra_msg2_t*)(response->body);

		fprintf(file, "MSG2 gb - ");
		PRINT_BYTE_ARRAY(file, &(p_msg2_body->g_b), sizeof(p_msg2_body->g_b));

		fprintf(file, "MSG2 spid - ");
		PRINT_BYTE_ARRAY(file, &(p_msg2_body->spid), sizeof(p_msg2_body->spid));

		fprintf(file, "MSG2 sign_gb_ga - ");
		PRINT_BYTE_ARRAY(file, &(p_msg2_body->sign_gb_ga),
			sizeof(p_msg2_body->sign_gb_ga));

		fprintf(file, "MSG2 mac - ");
		PRINT_BYTE_ARRAY(file, &(p_msg2_body->mac), sizeof(p_msg2_body->mac));

		fprintf(file, "MSG2 sig_rl - ");
		PRINT_BYTE_ARRAY(file, &(p_msg2_body->sig_rl),
			p_msg2_body->sig_rl_size);
	}
	else if(response->type == TYPE_RA_ATT_RESULT)
	{
		sample_ra_att_result_msg_t *p_att_result =
			(sample_ra_att_result_msg_t *)(response->body);
		fprintf(file, "ATTESTATION RESULT MSG platform_info_blob - ");
		PRINT_BYTE_ARRAY(file, &(p_att_result->platform_info_blob),
			sizeof(p_att_result->platform_info_blob));

		fprintf(file, "ATTESTATION RESULT MSG mac - ");
		PRINT_BYTE_ARRAY(file, &(p_att_result->mac), sizeof(p_att_result->mac));

		fprintf(file, "ATTESTATION RESULT MSG secret.payload_tag - %u bytes\n",
			p_att_result->secret.payload_size);

		fprintf(file, "ATTESTATION RESULT MSG secret.payload - ");
		PRINT_BYTE_ARRAY(file, p_att_result->secret.payload,
			p_att_result->secret.payload_size);
	}
	else
	{
		fprintf(file, "\nERROR in printing out the response. "
			"Response of type not supported %d\n", response->type);
	}
}


#if defined ATTESTATION_PROFILE
typedef struct attestion_profile {
	double initial_ra;
	double pro_msg2_gen_msg3;
} a_p;
#endif


// This sample code doesn't have any recovery/retry mechanisms for the remote
// attestation. Since the enclave can be lost due S3 transitions, apps
// susceptible to S3 transtions should have logic to restart attestation in
// these scenenarios.
int attestation(sgx_enclave_id_t enclave_id, sgx_ra_context_t *context, sgx_status_t status, Socket *S, int socket_fd, int client_id)
{


#if defined ATTESTATION_PROFILE
	a_p duration;
	std::clock_t start;
#endif

	int ret = 0;
	ra_samp_request_header_t *p_msg1_full = NULL;
	ra_samp_response_header_t *p_msg2_full = NULL;
	sgx_ra_msg3_t *p_msg3 = NULL;
	ra_samp_response_header_t* p_att_result_msg_full = NULL;
	int busy_retry_time = 2;
	int enclave_lost_retry_time = 1;
	ra_samp_request_header_t* p_msg3_full = NULL;

	FILE* OUTPUT = stdout;

	// Remote attestaton will be initiated the ISV server challenges the ISV
	// app or if the ISV app detects it doesn't have the credentials
	// (shared secret) from a previous attestation required for secure
	// communication with the server.

#if defined ATTESTATION_PROFILE
	start = std::clock();
#endif
	do
	{
		ret = enclave_init_ra(enclave_id,
			&status,
			false,
			client_id,
			context);
#if defined ATTESTATION_DEBUG
		printf("context_id:%d", *context);
#endif
		//Ideally, this check would be around the full attestation flow.
	} while (SGX_ERROR_ENCLAVE_LOST == ret && enclave_lost_retry_time--);
#if defined ATTESTATION_PROFILE
	duration.initial_ra = ( std::clock() - start ) / (double) CLOCKS_PER_SEC;
#endif
	if(SGX_SUCCESS != ret || status)
	{
		ret = -1;
		fprintf(OUTPUT, "\nError, call enclave_init_ra fail [%s].",
			__FUNCTION__);
		return -1;
	}
#if defined ATTESTATION_DEBUG
	fprintf(OUTPUT, "\nSERVER: Call enclave_init_ra success. For client_id: %d", client_id);
#endif
	// isv application call uke sgx_ra_get_msg1
	p_msg1_full = (ra_samp_request_header_t*)
		malloc(sizeof(ra_samp_request_header_t)
		+ sizeof(sgx_ra_msg1_t));
	if(NULL == p_msg1_full)
	{
		ret = -1;
		goto CLEANUP;
	}
	p_msg1_full->type = TYPE_RA_MSG1;
	p_msg1_full->size = sizeof(sgx_ra_msg1_t);
	do
	{
		ret = sgx_ra_get_msg1(*context, enclave_id, sgx_ra_get_ga,
			(sgx_ra_msg1_t*)((uint8_t*)p_msg1_full
			+ sizeof(ra_samp_request_header_t)));
	} while (SGX_ERROR_BUSY == ret && busy_retry_time--);
	if(SGX_SUCCESS != ret)
	{
		ret = -1;
		fprintf(OUTPUT, "\nError, call sgx_ra_get_msg1 fail [%s].",
			__FUNCTION__);
		goto CLEANUP;
	}
	else
	{
#if defined ATTESTATION_DEBUG
		fprintf(OUTPUT, "\nSERVER: Call sgx_ra_get_msg1 success. From client_id: %d\n", client_id);
#endif
#if defined DUMP_LOG
		fprintf(OUTPUT, "\nMSG1 body generated -\n");
		PRINT_BYTE_ARRAY(OUTPUT, p_msg1_full->body, p_msg1_full->size);
#endif
		//PRINT_BYTE_ARRAY(OUTPUT, p_msg1, sizeof(sgx_ra_msg1_t));

	}


	// The ISV application sends msg1 to the SP to get msg2,
	// msg2 needs to be freed when no longer needed.
	// The ISV decides whether to use linkable or unlinkable signatures.

#if defined ATTESTATION_DEBUG
	fprintf(OUTPUT, "\nSending msg1 to remote attestation service provider."
		"Expecting msg2 back.\n");
#endif


	ret = ra_network_send_receive(S, socket_fd,
		p_msg1_full,
		&p_msg2_full);

	if(ret != 0 || !p_msg2_full)
	{
		fprintf(OUTPUT, "\nError, ra_network_send_receive for msg1 failed "
			"[%s].", __FUNCTION__);

		goto CLEANUP;
	}
	else
	{
		// Successfully sent msg1 and received a msg2 back.
		// Time now to check msg2.
		if(TYPE_RA_MSG2 != p_msg2_full->type)
		{

			fprintf(OUTPUT, "\nError, didn't get MSG2 in response to MSG1. "
				"[%s].", __FUNCTION__);

			goto CLEANUP;
		}

#if defined ATTESTATION_DEBUG
		fprintf(OUTPUT, "\nSent MSG1 to remote attestation service "
			"provider. Received the MSG2 from client_id:%d\n", client_id);
#endif

#if defined DUMP_LOG
		PRINT_BYTE_ARRAY(OUTPUT, p_msg2_full,
			sizeof(ra_samp_response_header_t)
			+ p_msg2_full->size);

		fprintf(OUTPUT, "\nA more descriptive representation of MSG2:\n");
		PRINT_ATTESTATION_SERVICE_RESPONSE(OUTPUT, p_msg2_full);

	}
#endif

	sgx_ra_msg2_t* p_msg2_body = (sgx_ra_msg2_t*)((uint8_t*)p_msg2_full
		+ sizeof(ra_samp_response_header_t));


	uint32_t msg3_size = 0;

	busy_retry_time = 2;
	// The ISV app now calls uKE sgx_ra_proc_msg2,
	// The ISV app is responsible for freeing the returned p_msg3!!

#if defined ATTESTATION_PROFILE
	start = std::clock();
#endif
	do
	{
		ret = sgx_ra_proc_msg2(*context,
			enclave_id,
			sgx_ra_proc_msg2_trusted,
			sgx_ra_get_msg3_trusted,
			p_msg2_body,
			p_msg2_full->size,
			&p_msg3,
			&msg3_size);
	} while (SGX_ERROR_BUSY == ret && busy_retry_time--);
#if defined ATTESTATION_PROFILE
	duration.pro_msg2_gen_msg3 =  ( std::clock() - start ) / (double) CLOCKS_PER_SEC;
#endif

#if defined ATTESTATION_DEBUG
	if(!p_msg3)
	{
		fprintf(OUTPUT, "\nError, call sgx_ra_proc_msg2 fail. "
			"p_msg3 = 0x%p [%s].", p_msg3, __FUNCTION__);
		ret = -1;
		goto CLEANUP;
	}
#endif
	if(SGX_SUCCESS != (sgx_status_t)ret)
	{
		fprintf(OUTPUT, "\nError, call sgx_ra_proc_msg2 fail. "
			"ret = 0x%08x [%s].", ret, __FUNCTION__);
		ret = -1;
		goto CLEANUP;
	}
#if defined ATTESTATION_DEBUG
	else
	{
		fprintf(OUTPUT, "\nCall sgx_ra_proc_msg2 success. For client_id:%d\n", client_id);
	}
#endif

#if defined DUMP_LOG
	PRINT_BYTE_ARRAY(OUTPUT, p_msg3, msg3_size);
#endif
	p_msg3_full = (ra_samp_request_header_t*)malloc(
		sizeof(ra_samp_request_header_t) + msg3_size);
	if(NULL == p_msg3_full)
	{
		ret = -1;
		goto CLEANUP;
	}
	p_msg3_full->type = TYPE_RA_MSG3;
	p_msg3_full->size = msg3_size;
	if(memcpy_s(p_msg3_full->body, msg3_size, p_msg3, msg3_size))
	{
		fprintf(OUTPUT,"\nError: INTERNAL ERROR - memcpy failed in [%s].",
			__FUNCTION__);
		ret = -1;
		goto CLEANUP;
	}

	// The ISV application sends msg3 to the SP to get the attestation
	// result message, attestation result message needs to be freed when
	// no longer needed. The ISV service provider decides whether to use
	// linkable or unlinkable signatures. The format of the attestation
	// result is up to the service provider. This format is used for
	// demonstration.  Note that the attestation result message makes use
	// of both the MK for the MAC and the SK for the secret. These keys are
	// established from the SIGMA secure channel binding.

#if defined ATTESTATION_DEBUG
	fprintf(OUTPUT, "\nSending msg3 to remote attestation client_id%d."
		"Expecting att_result_msg (msg4) back.\n", client_id);
#endif

	ret = ra_network_send_receive(S, socket_fd,
		p_msg3_full,
		&p_att_result_msg_full);



	if(ret)
	{
		ret = -1;
		fprintf(OUTPUT, "\nError, sending msg3 failed [%s].", __FUNCTION__);
		goto CLEANUP;
	}


#if defined ATTESTATION_PROFILE
	printf( "\n**********************************************************\n");
	printf( "Attestation with client_id:%d summary:\n", client_id);
	printf( "initial_ra:%f\n", duration.initial_ra);
	printf( "proc2_get3:%f\n", duration.pro_msg2_gen_msg3);
	printf( "\n**********************************************************\n");
#endif


	return 1;

	/*if(attestation_passed)
	{
	return 1;
	}*/
}

CLEANUP:
// Clean-up
// Need to close the RA key state.
	if(INT_MAX != *context)
	{
		int ret_save = ret;
		ret = enclave_ra_close(enclave_id, &status, *context);
		if(SGX_SUCCESS != ret || status)
		{
			ret = -1;
			fprintf(OUTPUT, "\nError, call enclave_ra_close fail [%s].",
				__FUNCTION__);
		}
		else
		{
			// enclave_ra_close was successful, let's restore the value that
			// led us to this point in the code.
			ret = ret_save;
		}
		fprintf(OUTPUT, "\nCall enclave_ra_close success.");
	}
	
	sgx_destroy_enclave(enclave_id);
	
	
	ra_free_network_response_buffer(p_msg2_full);
	ra_free_network_response_buffer(p_att_result_msg_full);
	
	// p_msg3 is malloc'd by the untrused KE library. App needs to free.
	SAFE_FREE(p_msg3);
	SAFE_FREE(p_msg3_full);
	SAFE_FREE(p_msg1_full);
	printf("\nEnter a character before exit ...\n");
	getchar();
	return ret;
}
