#include "service_provider.h"
#include "Socket.h"

#include "Attestation_client.h"

#include "ecp.h"

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <time.h>
#include <string.h>

#include "crypto_API.h"

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning ( disable:4127 )
#endif
#include "ias_ra.h"

#ifndef SAFE_FREE
#define SAFE_FREE(ptr) {if (NULL != (ptr)) {free(ptr); (ptr) = NULL;}}
#endif

#define SAMPLE_RA_KEY_SMK 0

int iv_counter = 0;

int data_decryption(  char* data, char* decrypted_data, int data_size);
int assemble_msg4_V1( ra_samp_response_header_t** pp_msg4, int* msg4_full_size);

// Some utility functions to output some of the data structures passed between
// the ISV app and the remote attestation service provider.
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


// This is a context data structure used on SP side
typedef struct _sp_db_item_t
{
	sample_ec_pub_t             g_a;
	sample_ec_pub_t             g_b;
	sample_ec_key_128bit_t      vk_key;// Shared secret key for the REPORT_DATA
	sample_ec_key_128bit_t      mk_key;// Shared secret key for generating MAC's
	sample_ec_key_128bit_t      sk_key;// Shared secret key for encryption
	sample_ec_key_128bit_t      smk_key;// Used only for SIGMA protocol
	sample_ec_priv_t            b;
	sample_ps_sec_prop_desc_t   ps_sec_prop;
}sp_db_item_t;
static sp_db_item_t g_sp_db;

static bool g_is_sp_registered = false;
static int g_sp_credentials = 0;
static int g_authentication_token = 0;

static ias_att_report_t attestation_report = {0};

uint8_t g_secret[8] = {0,1,2,3,4,5,6,7};

sample_spid_t g_spid;

//@param [input] sample_ec256_private_t g_sp_priv_key
// used to create signature at client side
//@param [output] sp_db_ietm_t g_sp_db shared secret keys
//@param [output] int* encrypted_size

int attestation_client(Socket *S, sample_ec256_private_t g_sp_priv_key)
{

	FILE* OUTPUT = stdout;

	//receive msg1
	char *msg1;
	int length = 0;
	int pos = 0;
	while(true)
	{
		if (!length)
		{
			if(S->Recv((char*)&length,4)!=4) 
			{
				printf("CLIENT: Error! length=%d\n", length);

				return 0;
			}
			msg1 = new char[length];
		}

		else
		{	
			while (pos < length)
			{
				pos += S->Recv(msg1+pos,length-pos);
			}
			break;
		}
	}
	uint32_t msg1_size;
	sample_ra_msg1_t *p_msg1;
	if (length >= 0)
	{
		msg1_size = length;
		p_msg1 = (sample_ra_msg1_t *)msg1;
	}


	if(!p_msg1 ||
		(msg1_size != sizeof(sample_ra_msg1_t)))
	{
		return -1;
	}

#if defined DUMP_LOG
	fprintf(OUTPUT, "\nMSG1 body received -\n");
	PRINT_BYTE_ARRAY(OUTPUT, msg1, length);
#endif

	int ret = 0;
	ra_samp_response_header_t* p_msg2_full = NULL;
	sample_ra_msg2_t *p_msg2 = NULL;
//	sample_status_t sample_ret = SAMPLE_SUCCESS;
#ifdef SAMPLE_CRYPTO_LIB
	sample_ecc_state_handle_t ecc_state = NULL;
#endif
#ifdef TRUST_CRYPTO_LIB
	trust_status_t trust_ret = TRUST_SUCCESS;
#endif
	bool derive_ret = false;

	do
	{
		// Check to see if we have registered with the IAS yet?
		if(!g_is_sp_registered)
		{
			do
			{
				// @IAS_Q: What are the sp credentials?
				// @IAS_Q: What is in the authentication token
				// In the product, the SP will establish a mutually
				// authenticated SSL channel. The authentication token is
				// based on this channel.
				// @TODO: Convert this call to a 'network' send/receive
				// once the IAS server is a vaialable.
				ret = ias_enroll(g_sp_credentials, &g_spid,
					&g_authentication_token);
				if(0 != ret)
				{
					ret = SP_IAS_FAILED;
					break;
				}

				// IAS may support registering the Enclave Trust Policy.
				// Just leave a place holder here
				// @IAS_Q: What needs to be sent to the IAS with the policy
				// that identifies the SP?
				// ret = ias_register_enclave_policy(g_enclave_policy,
				// g_authentication_token);
				// if(0 != ret)
				// {
				//     break;
				// }

				g_is_sp_registered = true;
				break;
			} while(0);
		}
		// Get the sig_rl from IAS using GID.
		// GID is Base-16 encoded of EPID GID in little-endian format.
		// @IAS_Q: Does the SP need to supply any authentication info to the
		// IAS?  SPID?
		// In the product, the SP and IAS will use an established channel for
		// communication.
		uint8_t* sig_rl;
		uint32_t sig_rl_size = 0;

		// @TODO: Convert this call to a 'network' send/receive
		// once the IAS server is a vaialable.
		ret = ias_get_sigrl(p_msg1->gid, &sig_rl_size, &sig_rl);
		if(0 != ret)
		{
			fprintf(stderr, "\nError, ias_get_sigrl [%s].", __FUNCTION__);
			ret = SP_IAS_FAILED;
			break;
		}

		// Need to save the client's public ECCDH key to local storage
		if (memcpy_s(&g_sp_db.g_a, sizeof(g_sp_db.g_a), &p_msg1->g_a,
			sizeof(p_msg1->g_a)))
		{
			fprintf(stderr, "\nError, cannot do memcpy in [%s].", __FUNCTION__);
			ret = SP_INTERNAL_ERROR;
			break;
		}
#ifdef SAMPLE_CRYPTO_LIB
		// Generate the Service providers ECCDH key pair.
		sample_ret = sample_ecc256_open_context(&ecc_state);
		if(SAMPLE_SUCCESS != sample_ret)
		{
			fprintf(stderr, "\nError, cannot get ECC cotext in [%s].",
				__FUNCTION__);
			ret = -1;
			break;
		}
		sample_ec256_public_t pub_key = {{0},{0}};
		sample_ec256_private_t priv_key = {{0}};
		sample_ret = sample_ecc256_create_key_pair(&priv_key, &pub_key,
			ecc_state);
		if(SAMPLE_SUCCESS != sample_ret)
		{
			fprintf(stderr, "\nError, cannot generate key pair in [%s].",
				__FUNCTION__);
			ret = SP_INTERNAL_ERROR;
			break;
		}

		// Need to save the SP ECCDH key pair to local storage.
		if(memcpy_s(&g_sp_db.b, sizeof(g_sp_db.b), &priv_key,sizeof(priv_key))
			|| memcpy_s(&g_sp_db.g_b, sizeof(g_sp_db.g_b),
			&pub_key,sizeof(pub_key)))
		{
			fprintf(stderr, "\nError, cannot do memcpy in [%s].", __FUNCTION__);
			ret = SP_INTERNAL_ERROR;
			break;
		}

		// Generate the client/SP shared secret
		sample_ec_dh_shared_t dh_key = {{0}};
		sample_ret = sample_ecc256_compute_shared_dhkey(&priv_key,
			(sample_ec256_public_t *)&p_msg1->g_a,
			(sample_ec256_dh_shared_t *)&dh_key,
			ecc_state);
		if(SAMPLE_SUCCESS != sample_ret)
		{
			fprintf(stderr, "\nError, compute share key fail in [%s].",
				__FUNCTION__);
			ret = SP_INTERNAL_ERROR;
			break;
		}

		// smk is only needed for msg2 generation.
		derive_ret = derive_key(&dh_key, SAMPLE_RA_KEY_SMK,
			&(g_sp_db.smk_key));
		if(derive_ret != true)
		{
			fprintf(stderr, "\nError, derive key fail in [%s].", __FUNCTION__);
			ret = SP_INTERNAL_ERROR;
			break;
		}

		// The rest of the keys are the shared secrets for future communication.
		derive_ret = derive_key(&dh_key, SAMPLE_RA_KEY_MK,
			&(g_sp_db.mk_key));
		if(derive_ret != true)
		{
			fprintf(stderr, "\nError, derive key fail in [%s].", __FUNCTION__);
			ret = SP_INTERNAL_ERROR;
			break;
		}

		derive_ret = derive_key(&dh_key, SAMPLE_RA_KEY_SK,
			&(g_sp_db.sk_key));
		if(derive_ret != true)
		{
			fprintf(stderr, "\nError, derive key fail in [%s].", __FUNCTION__);
			ret = SP_INTERNAL_ERROR;
			break;
		}

		derive_ret = derive_key(&dh_key, SAMPLE_RA_KEY_VK,
			&(g_sp_db.vk_key));
		if(derive_ret != true)
		{
			fprintf(stderr, "\nError, derive key fail in [%s].", __FUNCTION__);
			ret = SP_INTERNAL_ERROR;
			break;
		}
#endif

#ifdef TRUST_CRYPTO_LIB
		trust_ret = trust_ecc256_open_context();
        if(TRUST_SUCCESS != trust_ret)
        {
            fprintf(stderr, "\nError, cannot get ECC cotext in [%s].",
                             __FUNCTION__);
            ret = -1;
            break;
        }
		trust_ec256_ECDH_public_t trust_pub_dh_key;
        trust_ec256_ECDH_private_t trust_priv_dh_key;
        trust_ret = trust_ecc256_create_key_pair_ECDH(&trust_priv_dh_key, &trust_pub_dh_key);
        if(TRUST_SUCCESS != trust_ret)
        {
            fprintf(stderr, "\nError, cannot generate key pair in [%s].",
                    __FUNCTION__);
            ret = SP_INTERNAL_ERROR;
            break;
        }
		 // Need to save the SP ECCDH key pair to local storage.
        if(memcpy_s(&g_sp_db.b, sizeof(g_sp_db.b), &trust_priv_dh_key,sizeof(trust_priv_dh_key.r))
           || memcpy_s(&g_sp_db.g_b, sizeof(g_sp_db.g_b), &trust_pub_dh_key,sizeof(trust_pub_dh_key.gx)+sizeof(trust_pub_dh_key.gy)))
        {
            fprintf(stderr, "\nError, cannot do memcpy in [%s].", __FUNCTION__);
            ret = SP_INTERNAL_ERROR;
            break;
        }
		// Generate the client/SP shared secret
        trust_ec256_dh_shared_t trust_dh_key = {{0}};
        trust_ret = trust_ecc256_compute_shared_dhkey(&trust_priv_dh_key,
            (trust_ec256_ECDH_public_t *) &p_msg1->g_a, &trust_dh_key);
        if(TRUST_SUCCESS != trust_ret)
        {
            fprintf(stderr, "\nError, compute share key fail in [%s].",
                    __FUNCTION__);
            ret = SP_INTERNAL_ERROR;
            break;
        }
		 // smk is only needed for msg2 generation.
        derive_ret = derive_key((sample_ec_dh_shared_t *)&trust_dh_key, SAMPLE_RA_KEY_SMK, &(g_sp_db.smk_key));
        if(derive_ret != true)
        {
            fprintf(stderr, "\nError, derive key fail in [%s].", __FUNCTION__);
            ret = SP_INTERNAL_ERROR;
            break;
        }


		// The rest of the keys are the shared secrets for future communication.
        derive_ret = derive_key((sample_ec_dh_shared_t *)&trust_dh_key, SAMPLE_RA_KEY_MK,
                                &(g_sp_db.mk_key));
        if(derive_ret != true)
        {
            fprintf(stderr, "\nError, derive key fail in [%s].", __FUNCTION__);
            ret = SP_INTERNAL_ERROR;
            break;
        }

        derive_ret = derive_key((sample_ec_dh_shared_t *)&trust_dh_key, SAMPLE_RA_KEY_SK,
                               &(g_sp_db.sk_key));
        if(derive_ret != true)
        {
            fprintf(stderr, "\nError, derive key fail in [%s].", __FUNCTION__);
            ret = SP_INTERNAL_ERROR;
            break;
        }

        derive_ret = derive_key((sample_ec_dh_shared_t *)&trust_dh_key, SAMPLE_RA_KEY_VK,
                               &(g_sp_db.vk_key));
        if(derive_ret != true)
        {
            fprintf(stderr, "\nError, derive key fail in [%s].", __FUNCTION__);
            ret = SP_INTERNAL_ERROR;
            break;
        }
#endif  

		uint32_t msg2_size = sizeof(sample_ra_msg2_t) + sig_rl_size;
		p_msg2_full = (ra_samp_response_header_t*)malloc(msg2_size
			+ sizeof(ra_samp_response_header_t));
		if(!p_msg2_full)
		{
			fprintf(stderr, "\nError, out of memory in [%s].", __FUNCTION__);
			ret = SP_INTERNAL_ERROR;
			break;
		}
		memset(p_msg2_full, 0, msg2_size + sizeof(ra_samp_response_header_t));
		p_msg2_full->type = TYPE_RA_MSG2;
		p_msg2_full->size = msg2_size;
		// @TODO: Set the status properly based on real protocol communication.
		p_msg2_full->status[0] = 0;
		p_msg2_full->status[1] = 0;
		p_msg2 = (sample_ra_msg2_t *)p_msg2_full->body;

		// Assemble MSG2
		if(memcpy_s(&p_msg2->g_b, sizeof(p_msg2->g_b), &g_sp_db.g_b,
			sizeof(g_sp_db.g_b)) ||
			memcpy_s(&p_msg2->spid, sizeof(sample_spid_t),
			&g_spid, sizeof(g_spid)))
		{
			fprintf(stderr,"\nError, memcpy failed in [%s].", __FUNCTION__);
			ret = SP_INTERNAL_ERROR;
			break;
		}

		// The service provider is responsible for selecting the proper EPID
		// signature type and to understand the implications of the choice!
		p_msg2->quote_type = SAMPLE_LINKABLE_SIGNATURE;

		p_msg2->kdf_id = SAMPLE_AES_CMAC_KDF_ID;

		// Create gb_ga
		sample_ec_pub_t gb_ga[2];
		if(memcpy_s(&gb_ga[0], sizeof(gb_ga[0]), &g_sp_db.g_b,
			sizeof(g_sp_db.g_b))
			|| memcpy_s(&gb_ga[1], sizeof(gb_ga[1]), &g_sp_db.g_a,
			sizeof(g_sp_db.g_a)))
		{
			fprintf(stderr,"\nError, memcpy failed in [%s].", __FUNCTION__);
			ret = SP_INTERNAL_ERROR;
			break;
		}
#ifdef SAMPLE_CRYPTO_LIB
		// Sign gb_ga
		sample_ret = sample_ecdsa_sign((uint8_t *)&gb_ga, sizeof(gb_ga),
			(sample_ec256_private_t *)&g_sp_priv_key,
			(sample_ec256_signature_t *)&p_msg2->sign_gb_ga,
			ecc_state);
		if(SAMPLE_SUCCESS != sample_ret)
		{
			fprintf(stderr, "\nError, sign ga_gb fail in [%s].", __FUNCTION__);
			ret = SP_INTERNAL_ERROR;
			break;
		}
#endif

#ifdef TRUST_CRYPTO_LIB
		// Sign gb_ga
		//sample_ec_pub_t gb_ga_tmp[2];
		/*for(int i = 0; i < 2; i++){
		trust_covert_endian(gb_ga[i].gx, gb_ga_tmp[i].gx, SAMPLE_ECP_KEY_SIZE);
		trust_covert_endian(gb_ga[i].gy, gb_ga_tmp[i].gy, SAMPLE_ECP_KEY_SIZE);
		}*/
		//trust_covert_endian((uint8_t *)&gb_ga, (uint8_t *)&gb_ga_tmp, 4*SAMPLE_ECP_KEY_SIZE);

		trust_ret = trust_ecdsa_sign((uint8_t *)&gb_ga, sizeof(gb_ga),
			(trust_ec256_ECDSA_private_t *)&g_sp_priv_key,
			(trust_ec256_signature_t *)&p_msg2->sign_gb_ga);
		
		if(TRUST_SUCCESS != trust_ret)
		{
			fprintf(stderr, "\nError, sign ga_gb fail in [%s].", __FUNCTION__);
			ret = SP_INTERNAL_ERROR;
			break;
		} 
#endif
		// Generate the CMACsmk for gb||SPID||TYPE||Sigsp(gb,ga)
		uint8_t mac[SAMPLE_EC_MAC_SIZE] = {0};
		uint32_t cmac_size = offsetof(sample_ra_msg2_t, mac);

		trust_ret = trust_rijndael128_cmac_msg((uint8_t *)&g_sp_db.smk_key,
			(uint8_t *)&p_msg2->g_b, cmac_size, (uint8_t *)&mac);

		if(TRUST_SUCCESS != trust_ret)
		{
			fprintf(stderr, "\nError, cmac fail in [%s].", __FUNCTION__);
			ret = SP_INTERNAL_ERROR;
			break;
		}
		if(memcpy_s(&p_msg2->mac, sizeof(p_msg2->mac), mac, sizeof(mac)))
		{
			fprintf(stderr,"\nError, memcpy failed in [%s].", __FUNCTION__);
			ret = SP_INTERNAL_ERROR;
			break;
		}

		if(memcpy_s(&p_msg2->sig_rl[0], sig_rl_size, sig_rl, sig_rl_size))
		{
			fprintf(stderr,"\nError, memcpy failed in [%s].", __FUNCTION__);
			ret = SP_INTERNAL_ERROR;
			break;
		}
		p_msg2->sig_rl_size = sig_rl_size;
		

	}while(0);

#ifdef CLIENT_DEBUG_FLAG
	fprintf(OUTPUT, "\nMSG2 body generated -\n");
	PRINT_BYTE_ARRAY(OUTPUT, p_msg2_full, p_msg2_full->size + sizeof(ra_samp_response_header_t));
#endif   


	if(ret)
	{
		SAFE_FREE(p_msg2_full);
	}
	else
	{
		// Freed by the network simulator in ra_free_network_response_buffer

		//send msg2
		int size = p_msg2_full->size + sizeof(ra_samp_response_header_t);
		S->Send((char *)(&size), sizeof(int));
		S->Send((char *)p_msg2_full, size);

		SAFE_FREE(p_msg2_full);
	}
#ifdef SAMPLE_CRYPTO_LIB
	if(ecc_state)
	{
		sample_ecc256_close_context(ecc_state);
	}
#endif

	char *msg3;
	length = 0;
	pos = 0;
	while(true)
	{
		if (!length)
		{
			if(S->Recv((char*)&length,4)!=4) 
			{
				
				printf( "as;ldkjf;alsdkj\n");
				printf("CLIENT: Error!\n");
				return 0;
			}
			msg3 = new char[length];
		}
		else
		{
			while (pos < length)
			{
				pos += S->Recv(msg3+pos,length-pos);
			}
			break;
		}
	}

	uint32_t msg3_size;
	sample_ra_msg3_t *p_msg3;
	if (length >= 0)
	{
		msg3_size = length;
		p_msg3 = (sample_ra_msg3_t *)msg3;
	}


	/*if(!p_msg3 ||
	(msg3_size != sizeof(sample_ra_msg3_t)))
	{
	return -1;
	}*/


#ifdef CLIENT_DEBUG_FLAG
	fprintf(OUTPUT, "\nMSG3 body received -\n");
	PRINT_BYTE_ARRAY(OUTPUT, msg3, length);
#endif

	ret = 0;
	//sample_ret = SAMPLE_SUCCESS;
	const uint8_t *p_msg3_cmaced = NULL;
	sample_quote_t *p_quote = NULL;
	//sample_sha_state_handle_t sha_handle = NULL;
	sample_report_data_t report_data = {0};

	uint32_t i;


	if((!p_msg3) ||
		(msg3_size < sizeof(sample_ra_msg3_t)))
	{
		return SP_INTERNAL_ERROR;
	}


	do
	{
		// Compare g_a in message 3 with local g_a.
		ret = memcmp(&g_sp_db.g_a, &p_msg3->g_a, sizeof(sample_ec_pub_t));
		if(ret)
		{
			fprintf(stderr, "\nError, g_a is not same [%s].", __FUNCTION__);
			ret = SP_PROTOCOL_ERROR;
			break;
		}
		//Make sure that msg3_size is bigger than sample_mac_t.
		uint32_t mac_size = msg3_size - sizeof(sample_mac_t);
		p_msg3_cmaced = reinterpret_cast<const uint8_t*>(p_msg3);
		p_msg3_cmaced += sizeof(sample_mac_t);

		// Verify the message mac using SMK
		uint8_t mac[SAMPLE_EC_MAC_SIZE] = {0};
		trust_ret = trust_rijndael128_cmac_msg((uint8_t *)&g_sp_db.smk_key,
			(uint8_t *)p_msg3_cmaced,
			mac_size,
			(uint8_t *)&mac);
		if(TRUST_SUCCESS != trust_ret)
		{
			fprintf(stderr, "\nError, cmac fail in [%s].", __FUNCTION__);
			ret = SP_INTERNAL_ERROR;
			break;
		}

		// In real implementation, should use a time safe version of memcmp here,
		// in order to avoid side channel attack.
		ret = memcmp(&p_msg3->mac, mac, sizeof(mac));
		if(ret)
		{
			fprintf(stderr, "\nError, verify cmac fail [%s].", __FUNCTION__);
			ret = SP_INTEGRITY_FAILED;
			break;
		}

		if(memcpy_s(&g_sp_db.ps_sec_prop, sizeof(g_sp_db.ps_sec_prop),
			&p_msg3->ps_sec_prop, sizeof(p_msg3->ps_sec_prop)))
		{
			fprintf(stderr,"\nError, memcpy failed in [%s].", __FUNCTION__);
			ret = SP_INTERNAL_ERROR;
			break;
		}

		p_quote = (sample_quote_t *)p_msg3->quote;

		// Verify the the report_data in the Quote matches the expected value.
		// The first 32 bytes of report_data are SHA256 HASH of {ga|gb|vk}.
		// The second 32 bytes of report_data are set to zero.

		CryptoPP::SHA256 hash;

		hash.Update((const byte *)&g_sp_db.g_a, sizeof(g_sp_db.g_a));
		hash.Update((const byte *)&g_sp_db.g_b, sizeof(g_sp_db.g_b));
		hash.Update((const byte *)&g_sp_db.vk_key, sizeof(g_sp_db.vk_key));

		hash.Final(report_data);

		/*sample_ret = sample_sha256_init(&sha_handle);
		if(sample_ret != SAMPLE_SUCCESS)
		{
			fprintf(stderr,"\nError, init hash failed in [%s].", __FUNCTION__);
			ret = SP_INTERNAL_ERROR;
			break;
		}
		sample_ret = sample_sha256_update((uint8_t *)&(g_sp_db.g_a),
			sizeof(g_sp_db.g_a), sha_handle);
		if(sample_ret != SAMPLE_SUCCESS)
		{
			fprintf(stderr,"\nError, udpate hash failed in [%s].",
				__FUNCTION__);
			ret = SP_INTERNAL_ERROR;
			break;
		}
		sample_ret = sample_sha256_update((uint8_t *)&(g_sp_db.g_b),
			sizeof(g_sp_db.g_b), sha_handle);
		if(sample_ret != SAMPLE_SUCCESS)
		{
			fprintf(stderr,"\nError, udpate hash failed in [%s].",
				__FUNCTION__);
			ret = SP_INTERNAL_ERROR;
			break;
		}
		sample_ret = sample_sha256_update((uint8_t *)&(g_sp_db.vk_key),
			sizeof(g_sp_db.vk_key), sha_handle);
		if(sample_ret != SAMPLE_SUCCESS)
		{
			fprintf(stderr,"\nError, udpate hash failed in [%s].",
				__FUNCTION__);
			ret = SP_INTERNAL_ERROR;
			break;
		}
		sample_ret = sample_sha256_get_hash(sha_handle,
			(sample_sha256_hash_t *)&report_data);
		if(sample_ret != SAMPLE_SUCCESS)
		{
			fprintf(stderr,"\nError, Get hash failed in [%s].", __FUNCTION__);
			ret = SP_INTERNAL_ERROR;
			break;
		}*/


		ret = memcmp((uint8_t *)&report_data,
			(uint8_t *)&(p_quote->report_body.report_data),
			sizeof(report_data));
		if(ret)
		{
			fprintf(stderr, "\nError, verify hash fail [%s].", __FUNCTION__);
			ret = SP_INTEGRITY_FAILED;
			break;
		}

		// Verify Enclave policy (IAS may provide an API for this if we
		// registered an Enclave policy)

		// Verify quote with IAS.
		// @IAS_Q: What is the proper JSON format for attestation evidence?

		// @TODO: Convert this call to a 'network' send/receive
		// once the IAS server is a vaialable.
		ret = ias_verify_attestation_evidence(p_quote, NULL,
			&attestation_report);
		if(0 != ret)
		{
			ret = SP_IAS_FAILED;
			break;
		}
		FILE* OUTPUT = stdout;
		fprintf(OUTPUT, "\n\n\tAtestation Report:");
		fprintf(OUTPUT, "\n\tid: 0x%0x.", attestation_report.id);
		fprintf(OUTPUT, "\n\tstatus: %d.", attestation_report.status);
		fprintf(OUTPUT, "\n\trevocation_reason: %u.",
			attestation_report.revocation_reason);
		// attestation_report.info_blob;
		fprintf(OUTPUT, "\n\tpse_status: %d.",  attestation_report.pse_status);
		// Check if Platform_Info_Blob is available.
		// @TODO: Currenlty, the IAS spec says this will not be available if
		// no info blob status flags are set. For now, assume it is always
		// there until we have the full message format definition.

		// Respond the client with the results of the attestation.
		// need encrypted data when assembling
		// so, move this part out of Attestation_client.cpp

	}while(0);



	// @TODO: In the product, the HTTP response header itself will have
	// an RK based signature that the service provider needs to check here.

	// The platform_info_blob signature will be verified by the client
	// if needed. No need to have the Service Provider to check it.

	// @TODO: Verify the enlcave policy report if they are to be supported
	// by IAS. Otherwise, the SP will need to check the ISV enclave report
	// itself.
	fprintf(OUTPUT, "\n\n\tEnclave Report:");
	fprintf(OUTPUT, "\n\tSignature Type: 0x%x", p_quote->sign_type);
	fprintf(OUTPUT, "\n\tSignature Basename: ");
	for(int i=0; i<sizeof(p_quote->basename.name) && p_quote->basename.name[i];
		i++)
	{
		fprintf(OUTPUT, "%c", p_quote->basename.name[i]);
	}
#ifdef __x86_64__
	fprintf(OUTPUT, "\n\tattributes.flags: 0x%0lx",
		p_quote->report_body.attributes.flags);
	fprintf(OUTPUT, "\n\tattributes.xfrm: 0x%0lx",
		p_quote->report_body.attributes.xfrm);
#else
	fprintf(OUTPUT, "\n\tattributes.flags: 0x%0llx",
		p_quote->report_body.attributes.flags);
	fprintf(OUTPUT, "\n\tattributes.xfrm: 0x%0llx",
		p_quote->report_body.attributes.xfrm);
#endif
	fprintf(OUTPUT, "\n\tmr_enclave: ");
	for(i=0;i<sizeof(sample_measurement_t);i++)
	{

		fprintf(OUTPUT, "%02x",p_quote->report_body.mr_enclave[i]);

		//fprintf(stderr, "%02x",p_quote->report_body.mr_enclave.m[i]);

	}
	fprintf(OUTPUT, "\n\tmr_signer: ");
	for(i=0;i<sizeof(sample_measurement_t);i++)
	{

		fprintf(OUTPUT, "%02x",p_quote->report_body.mr_signer[i]);

		//fprintf(stderr, "%02x",p_quote->report_body.mr_signer.m[i]);

	}
	fprintf(OUTPUT, "\n\tisv_prod_id: 0x%0x",
		p_quote->report_body.isv_prod_id);
	fprintf(OUTPUT, "\n\tisv_svn: 0x%0x",p_quote->report_body.isv_svn);
	fprintf(OUTPUT, "\n");
	// @TODO do a real check here.
	bool isv_policy_passed = true;

	ra_samp_response_header_t* p_msg4 = NULL;
	int msg4_full_size = 0;

	assemble_msg4_V1(&p_msg4, &msg4_full_size);
	S->Send((char*)(&msg4_full_size), sizeof(int));
	S->Send((char*)p_msg4, msg4_full_size);

	return ret;
}



//@param data:input data buffer
//@param data_size:input data size
//@para data_encrypted: output buffer of encrypted data(size equal to the input data) followed by a 16 bytes mac
//note that memory for the output buffer should be allocated before the function call

int data_encryption(  char* data, int data_size, char* data_encrypted) {
	

	int sample_ret = 0;	
	// Generate shared secret and encrypt it with SK, if attestation passed.
		uint8_t aes_gcm_iv[SAMPLE_SP_IV_SIZE] = {0};

#ifdef TRUST_CRYPTO_LIB
		memcpy( aes_gcm_iv, &iv_counter, sizeof(int));
		iv_counter ++;
		trust_rijndael128GCM_encrypt(&g_sp_db.sk_key,
				//&g_secret[0],
				(uint8_t*)data,
				data_size,
				(uint8_t*)data_encrypted,
				aes_gcm_iv,
				SAMPLE_SP_IV_SIZE,
				NULL,
				0,
				(uint8_t*)
				(data_encrypted + data_size));
		//printf( "function return!\n");

#endif


#ifdef SAMPLE_CRYPTO_LIB
	memcpy( aes_gcm_iv, &iv_counter, sizeof(int));
		iv_counter ++;
	sample_ret = sample_rijndael128GCM_encrypt(&g_sp_db.sk_key,
		//&g_secret[0],
		(const uint8_t*)data,
		data_size,
		(uint8_t*)data_encrypted,
		&aes_gcm_iv[0],
		SAMPLE_SP_IV_SIZE,
		NULL,
		0,
		(sample_aes_gcm_128bit_tag_t*)
		(data_encrypted + data_size));
#endif
    

	return sample_ret;
}



int assemble_msg4( ra_samp_response_header_t** pp_msg4, int* msg4_full_size, char* data, int data_size) {
	FILE* OUTPUT = stdout;
	//fprintf( OUTPUT, "CLIENT: Encrypting Data///\n");
	sample_ra_att_result_msg_t *p_att_result_msg = NULL;
	ra_samp_response_header_t* p_msg4 = NULL;

	int ret = 0;
	uint32_t att_result_msg_size = sizeof(sample_ra_att_result_msg_t)
			+ attestation_report.policy_report_size;

	p_msg4 =
		(ra_samp_response_header_t*)malloc(att_result_msg_size
		+ sizeof(ra_samp_response_header_t) + data_size);

	if(!p_msg4)
	{
		fprintf(stderr, "\nError, out of memory in [%s].", __FUNCTION__);
		ret = SP_INTERNAL_ERROR;
	}
	
	memset(p_msg4, 0, att_result_msg_size
		+ sizeof(ra_samp_response_header_t) + data_size);
		
	*msg4_full_size = att_result_msg_size + sizeof(ra_samp_response_header_t) + data_size;
	p_msg4->type = TYPE_RA_ATT_RESULT;
	p_msg4->size = att_result_msg_size;


	// Assemble Attestation Result Message
	// Note, this is a structure copy.  We don't copy the policy reports
	// right now.
	if(IAS_QUOTE_OK != attestation_report.status)
	{
		p_msg4->status[0] = 0xFF;
	}
	if(IAS_PSE_OK != attestation_report.pse_status)
	{
		p_msg4->status[1] = 0xFF;
	}

	p_att_result_msg =
		(sample_ra_att_result_msg_t *)p_msg4->body;
	p_att_result_msg->platform_info_blob = attestation_report.info_blob;



	// Generate mac based on the mk key.
	int mac_size = sizeof(ias_platform_info_blob_t);
	int trust_ret = trust_rijndael128_cmac_msg((uint8_t *)&g_sp_db.mk_key,
			(uint8_t *)&p_att_result_msg->platform_info_blob,
			mac_size,
			(uint8_t *)&p_att_result_msg->mac);

	if(TRUST_SUCCESS != trust_ret)
	{
		fprintf(stderr, "\nError, cmac fail in [%s].", __FUNCTION__);
		ret = SP_INTERNAL_ERROR;
	}

	/*int sample_ret = sample_rijndael128_cmac_msg(&g_sp_db.mk_key,
		(const uint8_t*)&p_att_result_msg->platform_info_blob,
		mac_size,
		&p_att_result_msg->mac);
	if(SAMPLE_SUCCESS != sample_ret)
	{
		fprintf(stderr, "\nError, cmac fail in [%s].", __FUNCTION__);
		ret = SP_INTERNAL_ERROR;
	}*/


	p_att_result_msg->secret.payload_size = data_size;//16020
	memcpy( (char*)p_att_result_msg->secret.payload, data, data_size);

	if(!trust_ret)
	{
		*pp_msg4 = NULL;
		SAFE_FREE(pp_msg4);
	}
	else
	{
		//printf("================here!!!!!\n");
		*pp_msg4 = p_msg4;
	}

	/*
	if(sample_ret)
		{
			*pp_msg4 = NULL;
			SAFE_FREE(pp_msg4);
		}
		else
		{
			//printf("================here!!!!!\n");
			*pp_msg4 = p_msg4;
		}
		*/

	return ret;
}

int assemble_msg4_V1( ra_samp_response_header_t** pp_msg4, int* msg4_full_size) {
	FILE* OUTPUT = stdout;
	//fprintf( OUTPUT, "CLIENT: Encrypting Data///\n");
	sample_ra_att_result_msg_t *p_att_result_msg = NULL;
	ra_samp_response_header_t* p_msg4 = NULL;

	int ret = 0;
	uint32_t att_result_msg_size = sizeof(sample_ra_att_result_msg_t)
			+ attestation_report.policy_report_size;

	p_msg4 =
		(ra_samp_response_header_t*)malloc(att_result_msg_size
		+ sizeof(ra_samp_response_header_t));

	if(!p_msg4)
	{
		fprintf(stderr, "\nError, out of memory in [%s].", __FUNCTION__);
		ret = SP_INTERNAL_ERROR;
	}
	
	memset(p_msg4, 0, att_result_msg_size
		+ sizeof(ra_samp_response_header_t));
		
	*msg4_full_size = att_result_msg_size + sizeof(ra_samp_response_header_t);
	p_msg4->type = TYPE_RA_ATT_RESULT;
	p_msg4->size = att_result_msg_size;


	// Assemble Attestation Result Message
	// Note, this is a structure copy.  We don't copy the policy reports
	// right now.
	if(IAS_QUOTE_OK != attestation_report.status)
	{
		p_msg4->status[0] = 0xFF;
	}
	if(IAS_PSE_OK != attestation_report.pse_status)
	{
		p_msg4->status[1] = 0xFF;
	}

	p_att_result_msg =
		(sample_ra_att_result_msg_t *)p_msg4->body;
	p_att_result_msg->platform_info_blob = attestation_report.info_blob;



	// Generate mac based on the mk key.
	int mac_size = sizeof(ias_platform_info_blob_t);
	int trust_ret = trust_rijndael128_cmac_msg((uint8_t *)&g_sp_db.mk_key,
			(uint8_t *)&p_att_result_msg->platform_info_blob,
			mac_size,
			(uint8_t *)&p_att_result_msg->mac);

	if(TRUST_SUCCESS != trust_ret)
	{
		fprintf(stderr, "\nError, cmac fail in [%s].", __FUNCTION__);
		ret = SP_INTERNAL_ERROR;
	}


	if(!trust_ret)
	{
		*pp_msg4 = NULL;
		SAFE_FREE(pp_msg4);
	}
	else
	{
		*pp_msg4 = p_msg4;
	}

	return ret;
}



int data_decryption(  char* data, char* decrypted_data, int data_size){
	uint8_t aes_gcm_iv[12] = {0};
	memcpy( aes_gcm_iv, &iv_counter, sizeof(int));
		iv_counter ++;
			bool test_ret = trust_rijndael128GCM_decrypt(&g_sp_db.sk_key,
                                 (uint8_t *)data,
								 data_size,
                                 (uint8_t *)decrypted_data,
                                 aes_gcm_iv,
                                 SAMPLE_SP_IV_SIZE,
                                 NULL,
                                 0,
                                 (const uint8_t *)
								 data + data_size);
	return 0;
}


int data_decryption1(  char* data, char* decrypted_data, int data_size){
	iv_counter --;
	uint8_t aes_gcm_iv[12] = {0};
	memcpy( aes_gcm_iv, &iv_counter, sizeof(int));
		iv_counter ++;
			bool test_ret = trust_rijndael128GCM_decrypt(&g_sp_db.sk_key,
                                 (uint8_t *)data,
								 data_size,
                                 (uint8_t *)decrypted_data,
                                 aes_gcm_iv,
                                 SAMPLE_SP_IV_SIZE,
                                 NULL,
                                 0,
                                 (const uint8_t *)
								 data + data_size);
	return 0;
}




#ifdef _MSC_VER
#pragma warning(pop)
#endif
