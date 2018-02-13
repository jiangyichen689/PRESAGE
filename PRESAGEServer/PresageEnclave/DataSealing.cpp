// This file is modified by cf
#include "DataSealing.h"

#include "sgx_tae_service.h"
#include "sgx_trts.h"
#include "sgx_tseal.h"
#include "string.h"


typedef struct _protected_secret_pack_head
{
	/* reserved */
	uint8_t reserved[SECRET_RESERVED_SIZE];

	/* index part */
	bool index_enabled;
	uint64_t index;

	/* MAC part */
	bool MAC_enabled;
	uint8_t MAC[SECRET_MAC_SIZE];

	/* timing part */
	bool time_enabled;
	sgx_time_source_nonce_t nonce;
    sgx_time_t timestamp_base;
    sgx_time_t lease_duration;
	
	/* replay part */
	bool replay_enabled;
	uint32_t release_version;
    uint32_t max_release_version;
	sgx_mc_uuid_t mc;
    uint32_t mc_value;

}protected_secret_pack_head;


//written by cf

uint32_t seal_data(int &final_sealed_len,
				   const uint8_t *secret, uint32_t secret_len, 
				   uint8_t *sealed_secrect, uint32_t sealed_secrect_len,
				   bool time_policy, bool replay_policy)
{
	uint32_t ret = 0;
	int busy_retry_times = PSE_SESSION_MAX_RETRY_TIME;
	uint32_t plain_text_size = sizeof(protected_secret_pack_head) + secret_len;
	uint8_t* plain_text = new uint8_t[plain_text_size];
	memset_s(plain_text, plain_text_size, 0, plain_text_size);
	protected_secret_pack_head* plain_text_head = (protected_secret_pack_head*)plain_text; 
	uint8_t* ptr_plain_text_content = plain_text + sizeof(protected_secret_pack_head);
	memcpy(ptr_plain_text_content, secret, secret_len);

	uint32_t size = sgx_calc_sealed_data_size(0, plain_text_size);
	final_sealed_len = size;

	uint8_t* tmp_sealed_screct = NULL;

	if(size > sealed_secrect_len)
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}else{
		tmp_sealed_screct = new uint8_t[size];
	}
	if(time_policy || replay_policy)
	{
		do{
			ret = sgx_create_pse_session();
		}while (ret == SGX_ERROR_BUSY && busy_retry_times--);
		if (ret != SGX_SUCCESS)
			return ret;
	}

	do{
		if(time_policy)
		{
			ret = sgx_get_trusted_time(&plain_text_head->timestamp_base, &plain_text_head->nonce);
			if(ret != SGX_SUCCESS)
			{
				switch(ret)
				{
				case SGX_ERROR_SERVICE_UNAVAILABLE:
					/* Architecture Enclave Service Manager is not installed or not
					working properly.*/
					break;
				case SGX_ERROR_SERVICE_TIMEOUT:
					/* retry the operation*/
					break;
				case SGX_ERROR_BUSY:
					/* retry the operation later*/
					break;
				default:
					/*other errors*/
					break;
				}
				break;
			}
			plain_text_head->lease_duration = TIME_BASED_LEASE_DURATION_SECOND;
		}

		if(replay_policy)
		{
			ret = sgx_create_monotonic_counter(&plain_text_head->mc, &plain_text_head->mc_value);
			if(ret != SGX_SUCCESS)
			{
				switch(ret)
				{
				case SGX_ERROR_SERVICE_UNAVAILABLE:
					/* Architecture Enclave Service Manager is not installed or not
					working properly.*/
					break;
				case SGX_ERROR_SERVICE_TIMEOUT:
					/* retry the operation later*/
					break;
				case SGX_ERROR_BUSY:
					/* retry the operation later*/
					break;
				case SGX_ERROR_MC_OVER_QUOTA:
					/* SGX Platform Service enforces a quota scheme on the Monotonic
					Counters a SGX app can maintain. the enclave has reached the
					quota.*/
					break;
				case SGX_ERROR_MC_USED_UP:
					/* the Monotonic Counter has been used up and cannot create
					Monotonic Counter anymore.*/
					break;
				default:
					/*other errors*/
					break;
				}
				break;
			}
		}

		ret = sgx_seal_data(0, NULL,plain_text_size, plain_text,
			size, (sgx_sealed_data_t*)tmp_sealed_screct);
	}while(0);

	/* remember to clear secret data after been used by memset_s */
	memcpy(sealed_secrect, tmp_sealed_screct, size);
  	memset_s(plain_text, plain_text_size, 0, plain_text_size);

	

	delete[] plain_text;
	delete[] tmp_sealed_screct;

	if(time_policy || replay_policy)
		sgx_close_pse_session();

	return ret;
}


//written by cf
uint32_t unseal_data(uint8_t *sealed_secret, uint32_t sealed_secret_len,
					 uint8_t *secret, uint32_t secret_len)
{
	uint32_t ret = 0;
	uint32_t ret_copy = 0;
	bool need_close = false;
    int busy_retry_times = PSE_SESSION_MAX_RETRY_TIME;
	uint32_t unsealed_data_size = sizeof(protected_secret_pack_head) + secret_len;
	uint8_t* temp_unsealed_data = new uint8_t[unsealed_data_size];
	protected_secret_pack_head* ptr_unsealed_data_head = (protected_secret_pack_head *)temp_unsealed_data;
	memset_s(temp_unsealed_data, unsealed_data_size, 0, unsealed_data_size);

	if(sealed_secret_len != sgx_calc_sealed_data_size(0, unsealed_data_size)) 
        return SGX_ERROR_INVALID_PARAMETER;

	ret = sgx_unseal_data((sgx_sealed_data_t*)sealed_secret, NULL, 0, temp_unsealed_data, &unsealed_data_size);
	ret_copy = ret;
	if((ptr_unsealed_data_head->time_enabled || ptr_unsealed_data_head->replay_enabled) && ret)
	{
		need_close = true;
		do
		{
			ret = sgx_create_pse_session();
		}while (ret == SGX_ERROR_BUSY && busy_retry_times--);
		if (ret != SGX_SUCCESS)
			return ret;
	}
	do
    {
		if(ret_copy != SGX_SUCCESS)
		{
			switch(ret_copy)
			{
			case SGX_ERROR_MAC_MISMATCH:
				/* MAC of the sealed data is incorrect.
				The sealed data has been tampered.*/
				break;
			case SGX_ERROR_INVALID_ATTRIBUTE:
				/*Indicates attribute field of the sealed data is incorrect.*/
				break;
			case SGX_ERROR_INVALID_ISVSVN:
				/* Indicates isv_svn field of the sealed data is greater than
				the enclave ISVSVN. This is a downgraded enclave.*/
				break;
			case SGX_ERROR_INVALID_CPUSVN:
				/* Indicates cpu_svn field of the sealed data is greater than
				the platform cpu_svn. enclave is on a downgraded platform.*/
				break;
			case SGX_ERROR_INVALID_KEYNAME:
				/*Indicates key_name field of the sealed data is incorrect.*/
				break;
			default:
				/*other errors*/
				break;
			}
			break;
		}


		if(ptr_unsealed_data_head->time_enabled == true)
		{
			sgx_time_source_nonce_t nonce = {0};
			sgx_time_t current_timestamp;
			ret = sgx_get_trusted_time(&current_timestamp, &nonce);
			if(ret != SGX_SUCCESS)
			{
				switch(ret)
				{
				case SGX_ERROR_SERVICE_UNAVAILABLE:
					/* Architecture Enclave Service Manager is not installed or not
					working properly.*/
					break;
				case SGX_ERROR_SERVICE_TIMEOUT:
					/* retry the operation*/
					break;
				case SGX_ERROR_BUSY:
					/* retry the operation later*/
					break;
				default:
					/*other errors*/
					break;
				}
				break;
			}
			/*source nonce must be the same, otherwise time source is changed and
			the two timestamps are not comparable.*/
			if (memcmp(&nonce,&ptr_unsealed_data_head->nonce, sizeof(sgx_time_source_nonce_t)))
			{
				ret = TIMESOURCE_CHANGED;
				break;
			}

			/* This should not happen. 
			SGX Platform service guarantees that the time stamp reading moves
			forward, unless the time source is changed.*/
			if(current_timestamp < ptr_unsealed_data_head->timestamp_base)
			{
				ret = TIMESTAMP_UNEXPECTED;
				break;
			}
			/*compare lease_duration and timestamp_diff
			if lease_duration is less than difference of current time and base time,
			lease tern has expired.*/
			if(current_timestamp - ptr_unsealed_data_head->timestamp_base > ptr_unsealed_data_head->lease_duration)
			{
				ret = LEASE_EXPIRED;
				break;
			}
		}
		if(ptr_unsealed_data_head->replay_enabled == true)
		{
			uint32_t mc_value_from_memory;
			ret = sgx_read_monotonic_counter(&ptr_unsealed_data_head->mc,&mc_value_from_memory);
			if(ret != SGX_SUCCESS)
			{
				switch(ret)
				{
				case SGX_ERROR_SERVICE_UNAVAILABLE:
					/* Architecture Enclave Service Manager is not installed or not
					working properly.*/
						break;
				case SGX_ERROR_SERVICE_TIMEOUT:
					/* retry the operation later*/
						break;
				case SGX_ERROR_BUSY:
					/* retry the operation later*/
						break;
				case SGX_ERROR_MC_NOT_FOUND:
					/* the the Monotonic Counter ID is invalid.*/
						break;
				default:
					/*other errors*/
					break;
				}
				break;
			}
			if(mc_value_from_memory != ptr_unsealed_data_head->mc_value)
			{
				ret = REPLAY_DETECTED;
				break;
			}
			ret = sgx_increment_monotonic_counter(&ptr_unsealed_data_head->mc, &ptr_unsealed_data_head->mc_value);
			if(ret != SGX_SUCCESS)
			{
				switch(ret)
				{
				case SGX_ERROR_SERVICE_UNAVAILABLE:
					/* Architecture Enclave Service Manager is not installed or not
					working properly.*/
					break;
				case SGX_ERROR_SERVICE_TIMEOUT:
					/* retry the operation*/
					break;
				case SGX_ERROR_BUSY:
					/* retry the operation later*/
					break;
				case SGX_ERROR_MC_NOT_FOUND:
					/* The Monotonic Counter was deleted or invalidated.
					This might happen under certain conditions.
					For example, the Monotonic Counter has been deleted, the SGX
					Platform Service lost its data or the system is under attack. */
					break;
				case SGX_ERROR_MC_NO_ACCESS_RIGHT:
					/* The Monotonic Counter is not accessible by this enclave.
					This might happen under certain conditions.
					For example, the SGX Platform Service lost its data or the
					system is under attack. */
					break;
				default:
					/*other errors*/
					break;
				}
				break;
			}
			if(ptr_unsealed_data_head->release_version >= ptr_unsealed_data_head->max_release_version)
			{
				/* the max release version has reached, cannot update. Delete the
				monotonic_counter, whether the deleting is successful or not. */
				(void)sgx_destroy_monotonic_counter(&ptr_unsealed_data_head->mc);
				ret= MAX_RELEASE_REACHED;
				break;
			}
			ptr_unsealed_data_head->release_version ++;
			ret = sgx_seal_data(0, NULL, unsealed_data_size, temp_unsealed_data,
            sealed_secret_len, (sgx_sealed_data_t*)sealed_secret);
		}
		memcpy(secret, temp_unsealed_data + sizeof(protected_secret_pack_head), secret_len);
	} while (0);

	memset_s(temp_unsealed_data, unsealed_data_size, 0, unsealed_data_size);
	delete[] temp_unsealed_data;
	if(need_close)
	{
		sgx_close_pse_session();
	}
    return ret;
}


uint32_t delete_sealed_conter(const uint8_t *sealed_secret, uint32_t sealed_secret_len)
{
	uint32_t ret = 0;
    int busy_retry_times = PSE_SESSION_MAX_RETRY_TIME;
	uint32_t data_unsealed_len = sealed_secret_len + sizeof(protected_secret_pack_head);
	uint8_t* data_unsealed = new uint8_t[data_unsealed_len];
	protected_secret_pack_head* ptr_data_unsealed_head = (protected_secret_pack_head *)data_unsealed;
    
    if(sealed_secret_len != sgx_calc_sealed_data_size(0, data_unsealed_len)) 
        return SGX_ERROR_INVALID_PARAMETER;
    do{
        ret = sgx_create_pse_session();
    }while (ret == SGX_ERROR_BUSY && busy_retry_times--);
    if (ret != SGX_SUCCESS)
        return ret;
	do
    {
        ret = sgx_unseal_data((sgx_sealed_data_t*)sealed_secret, NULL, 0, data_unsealed, &data_unsealed_len);
        if(ret != SGX_SUCCESS)
            break;
        ret = sgx_destroy_monotonic_counter(&ptr_data_unsealed_head->mc);
        if(ret != SGX_SUCCESS)
        {
            switch(ret)
            {
            case SGX_ERROR_SERVICE_UNAVAILABLE:
                /* Architecture Enclave Service Manager is not installed or not
                working properly.*/
                break;
            case SGX_ERROR_SERVICE_TIMEOUT:
                /* retry the operation later*/
                break;
            case SGX_ERROR_BUSY:
                /* retry the operation later*/
                break;
            case SGX_ERROR_MC_NOT_FOUND:
                /* the the Monotonic Counter ID is invalid.*/
                break;
            case SGX_ERROR_MC_NO_ACCESS_RIGHT:
                /* the Monotonic Counter is not accessible by this enclave.
                This might happen under certain conditions.
                For example, the SGX Platform Service lost its data or
                the system is under attack. */
                break;
            default:
                /*other errors*/
                break;
            }
        }
    } while (0);
    /* remember to clear secret data after been used by memset_s */
    memset_s(&data_unsealed, data_unsealed_len, 0, data_unsealed_len);
    sgx_close_pse_session();
    return ret;
}
