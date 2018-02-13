#pragma once
#include<stdint.h>

#define SAMPLE_ECP256_KEY_SIZE             32

typedef struct sample_ec256_private_t
{
    uint8_t r[SAMPLE_ECP256_KEY_SIZE];
} sample_ec256_private_t;