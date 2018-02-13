#ifndef DATA_PROCESS_H
#define DATA_PROCESS_H
#include <stdio.h>
#include <iostream>
#include <fstream>
#include <string>
#include <assert.h>
#include <math.h>
#include <ctime>
#include <chrono>
#include <windows.h>
#include <cstring>
#include <iomanip>
#include <queue>

#include "sgx_urts.h" 
#include "Basic.h";

#include "Config.h"
#include "network_ra.h"
// Needed for definition of remote attestation messages.
#include "remote_attestation_result.h"
#include "Debug_Flags.h"

#include "pthread.h"
#include "ssl_server.h"
#include "FileIO.h"

//File* sealedFile;
//File* inFile;
//extern Reference* reference;

using namespace std;

#define MAXIMUM_SEALED_SIZE 1024 * 1024 * 1


//void sealDZFile(sgx_ra_context_t context, const char* data, MESSAGE_LENGTH_TYPE inputFileSize, string sealed_dz, char * sealedDataMAC, sgx_enclave_id_t eid);
void sealDZFile(sgx_ra_context_t context, int file_type,const char* data, uint32_t inputFileSize, string sealed_dz, char* sealedDataMAC, sgx_enclave_id_t eid);

void decompressSealedDZ(string sealed_deez_file,  size_t inFileSz, string optRef, int DZ_order, sgx_enclave_id_t eid);

#endif