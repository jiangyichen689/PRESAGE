#include "DataProcess.h"

void sealDZFile(sgx_ra_context_t context, int file_type, const char* data, uint32_t inputFileSize, string sealed_dz, char* sealedDataMAC, sgx_enclave_id_t eid)
{
	uint32_t pos = 0;
	uint32_t size_after_seal = 0;
	__int64 index = 0;
	char* encryptedData = new char[inputFileSize];
	char* sealed_data = new char[MAXIMUM_SEALED_SIZE];

	ofstream outFile(sealed_dz, std::ifstream::binary);

	if(outFile ==NULL)
		throw DZException("Cannot open the file %s", sealed_dz);

	memmove(encryptedData, data, inputFileSize);

	int* ptr_final_data_size = new int[1];
	ecall_decryped_seal_buffer(eid, context, file_type, ptr_final_data_size, encryptedData, inputFileSize, sealed_data, MAXIMUM_SEALED_SIZE);
	outFile.write(sealed_data, *ptr_final_data_size);
	outFile.close();

	//ifstream tmp(sealed_dz, ios::binary | ios::ate);
	//streamsize size = tmp.tellg();
	//tmp.seekg(0, std::ios::beg);
	//cout << "The sealed fiel size is " << size << endl;

	delete[] encryptedData;
	delete[] sealed_data;
	delete ptr_final_data_size;
}

