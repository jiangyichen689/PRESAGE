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


#include <stdlib.h>
#include <string.h>
#include "ecp.h"

//#include "sample_libcrypto.h"
#include "crypto_API.h"

//New
#define EC_DERIVATION_BUFFER_SIZE(label_length) ((label_length) +4)

typedef enum _sample_derive_key_type_t
{
    SAMPLE_DERIVE_KEY_SMK = 0,
    SAMPLE_DERIVE_KEY_SK,
    SAMPLE_DERIVE_KEY_MK,
    SAMPLE_DERIVE_KEY_VK,
} sample_derive_key_type_t;

const char str_SMK[] = "SMK";
const char str_SK[] = "SK";
const char str_MK[] = "MK";
const char str_VK[] = "VK";
//New

#ifdef _MSC_VER
#endif

#define MAC_KEY_SIZE       16

#ifndef _MSC_VER
errno_t memcpy_s(
    void *dest,
    size_t numberOfElements,
    const void *src,
    size_t count)
{
    if(numberOfElements<count)
        return -1;
    memcpy(dest, src, count);
    return 0;
}
#endif

/*bool verify_cmac128(
    sample_ec_key_128bit_t mac_key,
    const uint8_t *p_data_buf,
    uint32_t buf_size,
    const uint8_t *p_mac_buf)
{
    uint8_t data_mac[SAMPLE_EC_MAC_SIZE];
    sample_status_t sample_ret;

    sample_ret = sample_rijndael128_cmac_msg((sample_cmac_128bit_key_t*)mac_key,
        p_data_buf,
        buf_size,
        (sample_cmac_128bit_tag_t *)data_mac);
    if(sample_ret != SAMPLE_SUCCESS)
        return false;
    // In real implementation, should use a time safe version of memcmp here,
    // in order to avoid side channel attack.
    if(!memcmp(p_mac_buf, data_mac, SAMPLE_EC_MAC_SIZE))
        return true;
    return false;
}*/

typedef struct _ec_padded_shared_key_t
{
    uint8_t s[SAMPLE_ECP_KEY_SIZE];
    uint8_t padding;
} ec_padded_shared_key_t;

//New

#define DERIVE_BY_CTYPTOPP

bool derive_key(
    const sample_ec_dh_shared_t *p_shared_key,
    uint8_t key_id,
    sample_ec_key_128bit_t* derived_key)
{
#ifdef DERIVE_BY_CTYPTOPP
	trust_status_t ret = TRUST_SUCCESS;
#else
	sample_status_t sample_ret = SAMPLE_SUCCESS;
#endif

   //sample_status_t sample_ret = SAMPLE_SUCCESS;
    uint8_t cmac_key[MAC_KEY_SIZE];
    sample_ec_key_128bit_t key_derive_key;
    
    memset(&cmac_key, 0, MAC_KEY_SIZE);

#ifdef DERIVE_BY_CTYPTOPP

	ret = trust_rijndael128_cmac_msg(
        cmac_key,
        (uint8_t*)p_shared_key,
        sizeof(sample_ec_dh_shared_t),
        key_derive_key);


	if (ret != TRUST_SUCCESS)
	{
		// memset here can be optimized away by compiler, so please use memset_s on
		// windows for production code and similar functions on other OSes.
		memset(&key_derive_key, 0, sizeof(key_derive_key));
		return false;
	}
	
#else
    sample_ret = sample_rijndael128_cmac_msg(
        (sample_cmac_128bit_key_t *)&cmac_key,
        (uint8_t*)p_shared_key,
        sizeof(sample_ec_dh_shared_t),
        (sample_cmac_128bit_tag_t *)&key_derive_key);
    if (sample_ret != SAMPLE_SUCCESS)
    {
        // memset here can be optimized away by compiler, so please use memset_s on
        // windows for production code and similar functions on other OSes.
        memset(&key_derive_key, 0, sizeof(key_derive_key));
        return false;
    }
#endif

    const char *label = NULL;
    uint32_t label_length = 0;
    switch (key_id)
    {
    case SAMPLE_DERIVE_KEY_SMK:
        label = str_SMK;
        label_length = sizeof(str_SMK) -1;
        break;
    case SAMPLE_DERIVE_KEY_SK:
        label = str_SK;
        label_length = sizeof(str_SK) -1;
        break;
    case SAMPLE_DERIVE_KEY_MK:
        label = str_MK;
        label_length = sizeof(str_MK) -1;
        break;
    case SAMPLE_DERIVE_KEY_VK:
        label = str_VK;
        label_length = sizeof(str_VK) -1;
        break;
    default:
        // memset here can be optimized away by compiler, so please use memset_s on
        // windows for production code and similar functions on other OSes.
        memset(&key_derive_key, 0, sizeof(key_derive_key));
        return false;
        break;
    }
    /* derivation_buffer = counter(0x01) || label || 0x00 || output_key_len(0x0080) */
    uint32_t derivation_buffer_length = EC_DERIVATION_BUFFER_SIZE(label_length);
    uint8_t *p_derivation_buffer = (uint8_t *)malloc(derivation_buffer_length);
    if (p_derivation_buffer == NULL)
    {
        // memset here can be optimized away by compiler, so please use memset_s on
        // windows for production code and similar functions on other OSes.
        memset(&key_derive_key, 0, sizeof(key_derive_key));
        return false;
    }
    memset(p_derivation_buffer, 0, derivation_buffer_length);

    /*counter = 0x01 */
    p_derivation_buffer[0] = 0x01;
    /*label*/
    memcpy(&p_derivation_buffer[1], label, label_length);
    /*output_key_len=0x0080*/
    uint16_t *key_len = (uint16_t *)(&(p_derivation_buffer[derivation_buffer_length - 2]));
    *key_len = 0x0080;

#ifdef DERIVE_BY_CTYPTOPP
	ret = trust_rijndael128_cmac_msg(
		key_derive_key,
		p_derivation_buffer,
		derivation_buffer_length,
		(uint8_t *)*derived_key);

#else
    sample_ret = sample_rijndael128_cmac_msg(
        (sample_cmac_128bit_key_t *)&key_derive_key,
        p_derivation_buffer,
        derivation_buffer_length,
        (sample_cmac_128bit_tag_t *)derived_key);
#endif


    free(p_derivation_buffer);
    // memset here can be optimized away by compiler, so please use memset_s on
    // windows for production code and similar functions on other OSes.
    memset(&key_derive_key, 0, sizeof(key_derive_key));

#ifdef DERIVE_BY_CTYPTOPP
	if (ret != TRUST_SUCCESS)
	{
		return false;
	}
#else
    if (sample_ret != SAMPLE_SUCCESS)
    {
        return false;
    }
#endif

    return true;
}
//New