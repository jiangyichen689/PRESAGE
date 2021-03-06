#include "PresageEnclave_t.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sgx_tkey_exchange.h"
#include "sgx_tcrypto.h"
#include "sgx_trts.h"
#include "vector"

#include "DataSealing.h"
#include "Util.h"
#include "PerfectHash.h"

using namespace std;

#define FETCH_SEALED_FILE_SUCESS 0
#define FETCH_SEALED_FILE_BUFFER_FAILED 1


#define MAXIMUM_SEALED_SIZE 1024 * 1024 * 1
#define ENCRYPTED_ADD_SIZE 16
#define HASH_KEY_LEN 20

int answerQuery(uint64_t* query0, int *res, int num_of_query);
void encryptData(sgx_ra_context_t context, 
				 uint8_t *p_src, uint32_t src_len,
				 uint8_t *p_dst, uint32_t dst_len);

int g_max_client_num = 0;
int g_num_data_file = 0;
int g_num_hash_file = 0;
int *iv_counter = NULL;
uint8_t *sealed_buffer = NULL;
bool iv_initialize_paras_flag = false;

vector<int> g_hash_file_size;
vector<int> g_data_file_size;
vector<int> g_hash_secrect_size;
vector<int> g_data_secret_size;

static const sgx_ec256_public_t g_sp_pub_key[] = {
	//pub_key No1  (the original)
	{
		{
			0x72, 0x12, 0x8a, 0x7a, 0x17, 0x52, 0x6e, 0xbf,
				0x85, 0xd0, 0x3a, 0x62, 0x37, 0x30, 0xae, 0xad,
				0x3e, 0x3d, 0xaa, 0xee, 0x9c, 0x60, 0x73, 0x1d,
				0xb0, 0x5b, 0xe8, 0x62, 0x1c, 0x4b, 0xeb, 0x38
		},
		{
			0xd4, 0x81, 0x40, 0xd9, 0x50, 0xe2, 0x57, 0x7b,
				0x26, 0xee, 0xb7, 0x41, 0xe7, 0xc6, 0x14, 0xe2,
				0x24, 0xb7, 0xbd, 0xc9, 0x03, 0xf2, 0x9a, 0x28,
				0xa8, 0x3c, 0xc8, 0x10, 0x11, 0x14, 0x5e, 0x06
			}
	},

		//pub_key No2
	{
		{
			0xd1, 0x1e, 0x95, 0x94, 0xec, 0xa0, 0x1d, 0xaa, 
				0x8a, 0x79, 0x39, 0xe9, 0x46, 0xb0, 0x33, 0xc2, 
				0xf3, 0x23, 0xc5, 0x27, 0x34, 0x8e, 0x40, 0xb5, 
				0xcd, 0x23, 0xa5, 0xcc, 0xea, 0x16, 0x1a, 0xa0
		},
		{
			0x44, 0xb3, 0x4a, 0xa1, 0x84, 0x7b, 0x81, 0x82, 
				0x50, 0x16, 0xe2, 0x17, 0xd3, 0xcd, 0x21, 0x77, 
				0xdd, 0x41, 0x05, 0xad, 0x9f, 0x32, 0xec, 0x49, 
				0x1f, 0x29, 0x2a, 0xfa, 0xf8, 0xa7, 0x6c, 0xdf
			}
	},

		//pub_key No3
	{
		{
			0x9d, 0x5d, 0xcf, 0x57, 0x4d, 0x94, 0x6d, 0x90, 
				0x21, 0x52, 0xaf, 0xb5, 0x28, 0x5e, 0x8e, 0xff, 
				0xa8, 0xe2, 0x37, 0x3d, 0x39, 0x2e, 0x5b, 0xc0, 
				0x1a, 0x8d, 0x16, 0xe0, 0xac, 0x89, 0xa4, 0x94
		},
		{
			0x77, 0x5b, 0xff, 0x94, 0xc5, 0xc3, 0x86, 0x53, 
				0xc3, 0x6c, 0x2e, 0xfb, 0x39, 0x13, 0xb3, 0xcd, 
				0x82, 0x61, 0x7d, 0x3b, 0x16, 0xc4, 0x7e, 0x26, 
				0xd7, 0x43, 0x44, 0x11, 0xa8, 0xc5, 0xee, 0x21
			}
	},
		//pub_key No4
	{
		{
			0x63, 0x45, 0x44, 0x1c, 0x72, 0x4b, 0xdc, 0x82, 
				0xb3, 0xbb, 0xf2, 0x34, 0x52, 0x88, 0x3c, 0xbf, 
				0x99, 0x09, 0xdf, 0x47, 0x35, 0x6b, 0x88, 0xde, 
				0x74, 0xff, 0x12, 0x39, 0x10, 0xda, 0xf5, 0x53
		},
		{
			0x5d, 0x2e, 0x6f, 0xae, 0xa1, 0x73, 0x75, 0x75, 
				0xaf, 0x5c, 0x34, 0x6d, 0x5c, 0x5c, 0x6a, 0x42, 
				0x94, 0x96, 0x9f, 0xe4, 0x30, 0x18, 0x12, 0x2d, 
				0x36, 0x9d, 0x13, 0xb6, 0x3e, 0xbe, 0x7d, 0xcc
			}
	},
		//pub_key No5
	{
		{
			0xf9, 0x7b, 0xe1, 0x11, 0xa1, 0xf9, 0xd6, 0x15, 
				0x7f, 0xc0, 0x94, 0x62, 0x9f, 0x13, 0xa9, 0x93, 
				0x90, 0x8a, 0xf8, 0x86, 0xa4, 0xcb, 0xe8, 0x56, 
				0x1e, 0xbd, 0x2d, 0x70, 0x4b, 0xe8, 0x32, 0x71
		},
		{
			0xa6, 0x16, 0x2f, 0xea, 0x2f, 0xaf, 0x8e, 0x23, 
				0x77, 0x41, 0xff, 0x0e, 0xcb, 0x2c, 0xce, 0x72, 
				0x90, 0x43, 0x55, 0xff, 0xc2, 0xf0, 0x5d, 0x09, 
				0x1f, 0x98, 0x1a, 0xfb, 0x5b, 0x32, 0x05, 0xec
			}
	},
		//pub_key No6
	{
		{
			0xeb, 0xf0, 0x06, 0x5a, 0x9a, 0x96, 0x58, 0x73, 
				0x66, 0x41, 0xc9, 0x3b, 0x82, 0x2d, 0x4f, 0x22, 
				0x65, 0xe4, 0x95, 0x4a, 0xef, 0xcf, 0x8e, 0xac, 
				0x76, 0x5b, 0xb8, 0x52, 0x17, 0xa6, 0xcb, 0x29
		},
		{
			0x5e, 0x52, 0xdc, 0x4b, 0xe5, 0x15, 0x56, 0xec, 
				0xe8, 0x13, 0x74, 0xd7, 0x4b, 0x17, 0x8a, 0xed, 
				0x87, 0xfa, 0x92, 0x82, 0xf5, 0x35, 0xcc, 0x5d, 
				0xfc, 0xfd, 0xd5, 0x0e, 0x31, 0x69, 0x71, 0xe0
			}
	},
		//pub_key No7
	{
		{
			0x04, 0xda, 0xe0, 0x04, 0xea, 0xc2, 0x28, 0x7e, 
				0xaa, 0x0b, 0xdd, 0x75, 0x16, 0x79, 0x48, 0x39, 
				0xf2, 0xd6, 0x54, 0xeb, 0x67, 0x5f, 0x17, 0x59, 
				0x59, 0xa3, 0xd9, 0xe2, 0x07, 0xad, 0x9c, 0x10
		},
		{
			0xbc, 0xfb, 0xe5, 0xa0, 0x24, 0xbc, 0x2a, 0xd4, 
				0xb1, 0x6a, 0xcb, 0xf7, 0x68, 0xc2, 0x78, 0x63, 
				0xc3, 0x9c, 0xdd, 0x7a, 0xcf, 0x33, 0x61, 0x8a, 
				0x69, 0xcc, 0xc8, 0xb1, 0xf7, 0x3e, 0x09, 0xd2
			}
	},
		//pub_key No8
	{
		{
			0x69, 0x1e, 0x08, 0xd0, 0xaa, 0x42, 0x19, 0x73, 
				0x69, 0x8a, 0x77, 0xbc, 0x0a, 0x7f, 0x66, 0xe9, 
				0xb1, 0x8f, 0x6b, 0x7d, 0x20, 0x8d, 0x39, 0x6f, 
				0xee, 0x81, 0x5c, 0x05, 0xe7, 0x19, 0x98, 0x3e
		},
		{
			0xd1, 0x65, 0x39, 0xf4, 0xd8, 0xba, 0x91, 0x7d, 
				0x41, 0x93, 0xd4, 0x86, 0x16, 0x96, 0xf3, 0xd1, 
				0x36, 0x5b, 0x22, 0x3e, 0x8f, 0x98, 0x77, 0x1c, 
				0x88, 0x78, 0x11, 0xd7, 0xc8, 0xb0, 0xd2, 0x5a
			}
	},
		//pub_key No9
	{
		{
			0x96, 0xf7, 0xc9, 0x4e, 0xe4, 0x4d, 0xb1, 0xfb, 
				0x72, 0xbd, 0x68, 0x00, 0x15, 0x77, 0x4d, 0x8d, 
				0xd6, 0x14, 0x31, 0x51, 0x20, 0x8c, 0xce, 0xac, 
				0x77, 0x6d, 0x04, 0xea, 0x71, 0x15, 0x2c, 0xe0
		},
		{
			0xcb, 0x94, 0x4a, 0x2d, 0x99, 0x28, 0xc9, 0xa5, 
				0xb7, 0x53, 0x82, 0x12, 0xcf, 0x1b, 0x3f, 0xd0, 
				0xf9, 0xb7, 0x78, 0x80, 0xe4, 0xca, 0x58, 0x6e, 
				0xe0, 0xa0, 0xa1, 0xcd, 0xc5, 0xb0, 0x5f, 0xe0
			}
	},
		//pub_key No10
	{
		{
			0x71, 0x9b, 0xbc, 0x8e, 0x48, 0x05, 0x6d, 0xff, 
				0xf2, 0xd5, 0x58, 0x72, 0x06, 0x7f, 0x8f, 0x14, 
				0x5b, 0xed, 0xc5, 0xcd, 0xe4, 0xda, 0xe9, 0x6f, 
				0x4b, 0x23, 0x12, 0x3f, 0x66, 0xae, 0x48, 0x7b
		},
		{
			0x3e, 0x56, 0xae, 0x4e, 0xa1, 0x96, 0x7f, 0xe7, 
				0x95, 0x5e, 0x40, 0xff, 0xdc, 0xc5, 0x51, 0x76, 
				0xbd, 0x78, 0x7f, 0x45, 0xbe, 0x6b, 0xe2, 0xb6, 
				0x2d, 0x2b, 0x5c, 0xa6, 0x45, 0xe2, 0x3d, 0x2b
			}
	},
		//pub_key No11
	{
		{
			0xd7, 0x79, 0x7f, 0x71, 0x69, 0x10, 0x3e, 0x11, 
				0x96, 0xbb, 0xc3, 0x89, 0xd8, 0x64, 0xd7, 0xa9, 
				0xde, 0x3b, 0xb5, 0x68, 0xab, 0x78, 0x14, 0x42, 
				0x53, 0xbc, 0x89, 0x5e, 0x34, 0x30, 0x8f, 0x2b
		},
		{
			0x79, 0x13, 0xc1, 0x51, 0xdb, 0x04, 0x19, 0x91, 
				0xcf, 0x40, 0xea, 0x29, 0x22, 0x36, 0x94, 0xa8, 
				0xb0, 0xd0, 0xdb, 0x96, 0x67, 0x7d, 0x97, 0xb5, 
				0x87, 0x9e, 0x13, 0x86, 0x83, 0x43, 0x20, 0xb5
			}
	},
		//pub_key No12
	{
		{
			0x78, 0xcc, 0xbb, 0x16, 0x57, 0xf2, 0x28, 0xcc, 
				0x94, 0x72, 0x75, 0x51, 0xc2, 0x15, 0x6e, 0x10, 
				0x13, 0x5b, 0x2b, 0x76, 0x73, 0x11, 0x8d, 0x80, 
				0x22, 0xbc, 0x43, 0xa6, 0x5f, 0xe4, 0x95, 0xd5
		},
		{
			0xdf, 0xf1, 0x70, 0x67, 0xd6, 0xe8, 0x19, 0x64, 
				0x1b, 0x80, 0x82, 0x5d, 0x3e, 0x97, 0x95, 0xb3, 
				0x26, 0x81, 0x8d, 0x0b, 0xe1, 0x15, 0x47, 0x72, 
				0x11, 0x2d, 0xe7, 0xdc, 0x29, 0x53, 0xb4, 0x12
			}
	}
};


// This ecall is a wrapper of sgx_ra_init to create the trusted
// KE exchange key context needed for the remote attestation
// SIGMA API's. Input pointers aren't checked since the trusted stubs
// copy them into EPC memory.
//
// @param b_pse Indicates whether the ISV app is using the
//              platform services.
// @param p_context Pointer to the location where the returned
//                  key context is to be copied.
// @param client_id
//
// @return Any error return from the create PSE session if b_pse
//         is true.
// @return Any error returned from the trusted key exchange API
//         for creating a key context.

sgx_status_t enclave_init_ra(
	int b_pse,
	int client_id,
	sgx_ra_context_t *p_context)
{
	// isv enclave call to trusted key exchange library.
	sgx_status_t ret;
	if(b_pse)
	{
		int busy_retry_times = 2;
		do{
			ret = sgx_create_pse_session();
		}while (ret == SGX_ERROR_BUSY && busy_retry_times--);
		if (ret != SGX_SUCCESS)
			return ret;
	}



	ret = sgx_ra_init(&g_sp_pub_key[client_id], b_pse, p_context);
	if(b_pse)
	{
		sgx_close_pse_session();
		return ret;
	}
	return ret;
}

// Verify the mac sent in att_result_msg from the SP using the
// MK key. Input pointers aren't checked since the trusted stubs
// copy them into EPC memory.
//
//
// @param context The trusted KE library key context.
// @param p_message Pointer to the message used to produce MAC
// @param message_size Size in bytes of the message.
// @param p_mac Pointer to the MAC to compare to.
// @param mac_size Size in bytes of the MAC
//
// @return SGX_ERROR_INVALID_PARAMETER - MAC size is incorrect.
// @return Any error produced by tKE  API to get SK key.
// @return Any error produced by the AESCMAC function.
// @return SGX_ERROR_MAC_MISMATCH - MAC compare fails.

sgx_status_t verify_att_result_mac(sgx_ra_context_t context,
								   uint8_t* p_message,
								   size_t message_size,
								   uint8_t* p_mac,
								   size_t mac_size)
{
	sgx_status_t ret;
	sgx_ec_key_128bit_t mk_key;

	if(mac_size != sizeof(sgx_mac_t))
	{
		ret = SGX_ERROR_INVALID_PARAMETER;
		return ret;
	}
	if(message_size > UINT32_MAX)
	{
		ret = SGX_ERROR_INVALID_PARAMETER;
		return ret;
	}

	do {
		uint8_t mac[SGX_CMAC_MAC_SIZE] = {0};

		ret = sgx_ra_get_keys(context, SGX_RA_KEY_MK, &mk_key);
		if(SGX_SUCCESS != ret)
		{
			break;
		}
		ret = sgx_rijndael128_cmac_msg(&mk_key,
			p_message,
			(uint32_t)message_size,
			&mac);
		if(SGX_SUCCESS != ret)
		{
			break;
		}
		if(0 == consttime_memequal(p_mac, mac, sizeof(mac)))
		{
			ret = SGX_ERROR_MAC_MISMATCH;
			break;
		}

	}
	while(0);

	return ret;
}

// Closes the tKE key context used during the SIGMA key
// exchange.
//
// @param context The trusted KE library key context.
//
// @return Return value from the key context close API

sgx_status_t SGXAPI enclave_ra_close(
	sgx_ra_context_t context)
{
	sgx_status_t ret;
	ret = sgx_ra_close(context);
	return ret;
}

sgx_status_t getDecryptedBlock(sgx_ra_context_t context, 
				 const uint8_t *p_src, uint32_t src_len, uint8_t *p_dst)
{
	//uint32_t src_len = SEALING_BUFFER_SIZE;
	sgx_status_t ret = SGX_SUCCESS;
	sgx_ec_key_128bit_t sk_key;
	ret = sgx_ra_get_keys(context, SGX_RA_KEY_SK, &sk_key);

	if(SGX_SUCCESS != ret)
		printf("get sk key failed!!\n");

	uint8_t aes_gcm_iv[12] = {0};

	//printf("The IV is %d\n", iv_counter[context]);


	memcpy( aes_gcm_iv, &iv_counter[context], sizeof(int));
	iv_counter[context] ++;

	ret = sgx_rijndael128GCM_decrypt(&sk_key,
		p_src,
		src_len,
		(uint8_t *)p_dst,
		&aes_gcm_iv[0],
		12,
		NULL,
		0,
		(const sgx_aes_gcm_128bit_tag_t *)(p_src + src_len));

	return ret;
}

void initializeEnclave(int client_num)
{
	if (! iv_initialize_paras_flag) {
		iv_initialize_paras_flag = true;
		sealed_buffer = new uint8_t[MAXIMUM_SEALED_SIZE];
		iv_counter = new int[client_num];
		for ( int i = 0; i < client_num; i ++) {
			iv_counter[i] = 0;
		}
		g_max_client_num = client_num;
	}
}

void implementQuery(sgx_ra_context_t context,
				  uint8_t *enc_res, int enc_res_size,
				  uint8_t *enc_data, int enc_data_buffer_size)
{
	int query_buffer_size = enc_data_buffer_size - ENCRYPTED_ADD_SIZE;
	int num_of_query = query_buffer_size / sizeof(uint64_t);
	uint64_t *query_buffer = (uint64_t*)malloc(query_buffer_size);
	//uint64_t *query_buffer

	int *res0 = (int *)malloc(num_of_query * sizeof(int));
	//int *res0 = new int[num_of_query];

	getDecryptedBlock(context, enc_data, query_buffer_size, (uint8_t*)query_buffer);

	answerQuery(query_buffer, res0, num_of_query);
	encryptData(context, (uint8_t *)res0, sizeof(int) * num_of_query, enc_res, enc_res_size);

	free(res0);
	//delete[] res0;
	free(query_buffer);
}

void cleanBuffers()
{
	if(iv_initialize_paras_flag)
	{
		delete[] iv_counter;
		delete[] sealed_buffer;
	}
}


void encryptData(sgx_ra_context_t context, 
				 uint8_t *p_src, uint32_t src_len,
				 uint8_t *p_dst, uint32_t dst_len)
{
	sgx_status_t ret = SGX_SUCCESS;
	
	//load the key
	sgx_ec_key_128bit_t sk_key;
	ret = sgx_ra_get_keys(context, SGX_RA_KEY_SK, &sk_key);
	if(SGX_SUCCESS != ret)
		printf("get sk key failed!!\n");

	uint8_t aes_gcm_iv[12] = {0};

	memcpy( aes_gcm_iv, &iv_counter[context], sizeof(int));
	iv_counter[context] ++;

	ret = sgx_rijndael128GCM_encrypt(&sk_key,
		p_src,
		src_len,
		p_dst,
		&aes_gcm_iv[0],
		12,
		NULL,
		0,
		(sgx_aes_gcm_128bit_tag_t *)(p_dst + src_len));

	if (ret != SGX_SUCCESS)
	{
		printf("Data encryted failed!");
		abort();
	}
}

void ecall_decryped_seal_buffer(sgx_ra_context_t context,
								int file_type,
								int* final_len,
								char* data2seal, int data_buffer_size, 
								char* sealed_secret, int sealed_secret_size) 
{
	int seal_buffer_size = data_buffer_size - ENCRYPTED_ADD_SIZE;
	char *decryptedData = (char *)malloc(seal_buffer_size);

	getDecryptedBlock(context, (uint8_t*) data2seal, seal_buffer_size, (uint8_t*)decryptedData);

	int final_len_0;
	uint32_t ret = seal_data(final_len_0,(uint8_t *)decryptedData, seal_buffer_size, sealed_buffer, MAXIMUM_SEALED_SIZE, false, false);
	memcpy(sealed_secret, sealed_buffer, final_len_0);
	*final_len = final_len_0;

	if(file_type)
	{
		g_num_data_file++;
		g_data_file_size.push_back(final_len_0);
		g_data_secret_size.push_back(seal_buffer_size);

	}
	else
	{
		g_num_hash_file++;
		g_hash_file_size.push_back(final_len_0);
		g_hash_secrect_size.push_back(seal_buffer_size);
	}

	free(decryptedData);

}


int answerQuery(uint64_t* query0, int *res, int num_of_query)
{
	char hash_key[HASH_KEY_LEN];

	memset(res, 0, sizeof(int)*num_of_query);

	for(int n = 0; n < g_data_file_size.size(); n++)
	{
		//printf("g_data_file_size:=%d \n", n);
		//step1: fetch sealed data
		int res_fetch;

		uint8_t *sealed_hash_buffer = (uint8_t*)malloc(g_hash_file_size[n]);
		uint8_t *sealed_data_buffer = (uint8_t*)malloc(g_data_file_size[n]);
		uint8_t *secrect_hash_buffer = (uint8_t*)malloc(g_hash_secrect_size[n]);
		uint64_t *secrect_data_buffer = (uint64_t*)malloc(g_data_secret_size[n]);

		if(ocall_fetch_file(&res_fetch, 0, n, sealed_hash_buffer, g_hash_file_size[n]) || 
			ocall_fetch_file(&res_fetch, 1, n, sealed_data_buffer, g_data_file_size[n]))
		{
			return FETCH_SEALED_FILE_BUFFER_FAILED;
		}

		int res_unsealed = unseal_data(sealed_hash_buffer, g_hash_file_size[n], secrect_hash_buffer, g_hash_secrect_size[n]);
		if(res_unsealed != SGX_SUCCESS)
		{
			ocall_print_string("unseal data failed, error code = ");
			ocall_print_string("\r\n");
			return FETCH_SEALED_FILE_BUFFER_FAILED;
		}

		res_unsealed = unseal_data(sealed_data_buffer, g_data_file_size[n], (uint8_t*)secrect_data_buffer, g_data_secret_size[n]);
		if(res_unsealed != SGX_SUCCESS)
		{
			ocall_print_string("unseal data failed, error code = ");
			ocall_print_string("\r\n");
			return FETCH_SEALED_FILE_BUFFER_FAILED;
		}

		Memory_IO mem;
		mem.mem_ptr = (char*)secrect_hash_buffer;
		mem.len = g_hash_secrect_size[n];
		mem.current_pos = 0;

		cmph_t *hash = cmph_load(&mem);


		for(int m = 0; m < num_of_query; m++)
		{
			sprintf(hash_key, "%llu", *(query0 + m));
			unsigned int id = cmph_search(hash, hash_key, (cmph_uint32)strlen(hash_key));
			if(*(secrect_data_buffer + id) == *(query0 + m) &&(id < g_data_secret_size[n]))
			{
				*(res + m) = *(res + m) + 1; 
			}
		}


		free(hash);
		free(sealed_hash_buffer);
		free(sealed_data_buffer);
		free(secrect_hash_buffer);
		free(secrect_data_buffer);
	}

	return FETCH_SEALED_FILE_SUCESS;
}