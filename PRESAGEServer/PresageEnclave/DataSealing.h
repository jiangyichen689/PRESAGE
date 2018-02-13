#pragma once
#ifndef DATASEALING_H
#define DATASEALING_H

#include "stdint.h"

#define PLATFORM_SERVICE_DOWNGRADED 0xF001

/* replay policy */
#define REPLAY_DETECTED             0xF002

#ifndef MAX_RELEASE_REACHED
#define MAX_RELEASE_REACHED         0xF003
#endif

/* time based policy */
#define TIMESOURCE_CHANGED          0xF004
#define TIMESTAMP_UNEXPECTED        0xF005
#define LEASE_EXPIRED               0xF006

/* index policy */
#define INDEX_CHANGED				0xF007

/* message authentication code policy */
#define MAC_CHANGED					0xF008

/* max time when try to create the pse session */
#define PSE_SESSION_MAX_RETRY_TIME 2

/* max release times */
#define REPLAY_PROTECTED_PAY_LOAD_MAX_RELEASE_VERSION 5

/* define max time base policy duration, set to 86400 will be exactly one day */
#define TIME_BASED_LEASE_DURATION_SECOND 86400

#ifndef SEALED_BUFFER_SIZE
/* 
   This size will be exactly the same as get_sealed_secret_buffer_size(), I recommend you to call that function instead of reading this const. 
   However, if you change any const below, or the protected_secret_pack in the cpp file, this size will not be 1760 anymore but that function will still work.
*/
#define SEALED_BUFFER_SIZE 1760
#endif

/* define your secret size in each block */
#ifndef SEALING_BUFFER_SIZE
#define SEALING_BUFFER_SIZE 1024
#endif

#define SECRET_MAC_SIZE 64
#define SECRET_RESERVED_SIZE 8


/* 
  Seal data.
  This function must be called inside the enclave because the secret is being read.
  [in] secret : data to be sealed, MUST NOT be NULL.
  [in] secret_len : the length of the secret, usually this will be the same as SEALING_BUFFER_SIZE. MUST NOT be zero.
  [out] sealed_secret : the data that will be saved outside the enclave, which has been encrypted. MUST NOT be NULL.
  NOTE : the space of sealed_secret MUST be created before calling this function.
  [in] sealed_secret_len : the length of the sealed_secret, you may call this function to get this length:
  uint32_t sealed_secret_len = sgx_calc_sealed_data_size(0, sizeof(protected_secret_pack));

  [in] Policy Option:
  NOTE : once the policy is enabled, the unseal function will however check every policy when you want to unseal them.
  secret_index : set to an positive number (including zero) to enable index protect policy.
  secret_MAC : set to a sized array to enable MAC protect policy.
  NOTE : the length of the secret_MAC MUST be the same as SECRET_MAC_SIZE.
  time_policy : set to true to enable time protect policy, the lease duration will be the same as TIME_BASED_LEASE_DURATION_SECOND.
  relplay_policy : set to true to enable replay_policy, there are only 256 counters in every enclave, if you need a lot, just don't enable it.
*/
uint32_t seal_data(int &final_sealed_len,
				   const uint8_t *secret, uint32_t secret_len, 
				   uint8_t *sealed_secrect, uint32_t sealed_secrect_len,
				   bool time_policy = false, bool replay_policy = false);

/*
  Unseal data.
  This function must be called inside the enclave because the secret is being read.
  If you enabled replay policy, please note that: 
  1.Data can NOT be reused after REPLAY_PROTECTED_PAY_LOAD_MAX_RELEASE_VERSION times.
  2.Save the sealed_secret back to the sealed data file after calling this function, otherwise you will not be able to use them anymore.
  [in/out] sealed_secret : the data that was sealed by the function above, after calling, it will be refreshed if you enabled replay policy.
  [in] sealed_secret_len : the length of the sealed_secret.
  [out] secret : the secret in the sealed_secret.
  [in] secret_len : the length of the secret, usually it will be the same as SEALING_BUFFER_SIZE.

  [in] Policy Options:
  The data will be checked if and only if the data itself has already enabled a policy, an unsuccessful unsealing will occur if any of them mismatch.
  check_secret_index : set to the expected index to match the data.
  check_secret_MAC : set to the expected MAC to match the data.
  Remember that we will also check the timestamp and the counter if their policy is enabled.
*/
uint32_t unseal_data(uint8_t *sealed_secret, uint32_t sealed_secret_len,
					 uint8_t *secret, uint32_t secret_len);

/*
  Delete the counter for the sealed data, you must call this function when you don't need the counter anymore. (Based on Replay Policy)
  NOTE: When the counter is destroyed, you will not be able to use the sealed data anymore.
  You will only need to call this function when the replay policy in the sealed data is enabled.
  [in] sealed_secret : the data that was sealed by the function above.
  NOTE:Remember to clear this data after calling this function, because the data inside will not be able to be unsealed anymore.
  [in] sealed_secret_len : the length of the sealed_secret.
*/
uint32_t delete_sealed_conter(const uint8_t *sealed_secret, uint32_t sealed_secret_len);

/*
  Get the size of sealed_secret, this function works exactly the same as 
  'sgx_calc_sealed_data_size(0, sizeof(protected_secret_pack))'.
*/
uint32_t get_sealed_secret_buffer_size();



#endif