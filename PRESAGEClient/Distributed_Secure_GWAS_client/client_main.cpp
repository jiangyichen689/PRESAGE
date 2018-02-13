#include <stdio.h>
#include <iostream>
#include <fstream>
#include <string>
#include <assert.h>
#include <tchar.h>
#include <stdint.h>
#include <ctime>
#include <chrono>
#include <iomanip>
#include <vector>

#include "EnclaveEM.h"
#include "TDT.h"
#include "Config.h"
#include "network_ra.h"
//#include "sample_libcrypto.h"
#include "remote_attestation_result.h"
#include "Debug_Flags.h"
#include "range_code.h"

#include "ssl_client.h"
#include "cdflib.hpp"
#include "FileIO.h"

//#include <sgx_tcrypto.h>
#include "Attestation_client.h"
#include "ClientDataManagement.h"
#include "VCFFile.h"

#include "Debug.h"


using namespace std;
using namespace std::chrono;

#define MAX_FILE_PATH_LENGTH 2000
#define DEBUG1	
#define QUERY_UPLOADING_MOD 1000

#if defined FUNCTION_LEVEL_PROFILE
typedef struct client_profile {
	duration<double> client_loadfile;
	duration<double> client_encryption;
	duration<double> waiting_result;
	duration<double> client_decryption;

} c_p;

c_p client_duration;
#endif

//*****************************************************************************
//                 GLOBAL VARIABLES -- Start
//*****************************************************************************

//global buffer for compression
extern unsigned char* g_buffer;
extern int current_byte;
//*****************************************************************************
//                 GLOBAL VARIABLES -- End
//*****************************************************************************

//******************************************************************************
//                    FUNCTION DECLARATIONS
//******************************************************************************
bool loadData(string fileName, char* data);
bool readIntArrFromString(string str, string delimiter, vector<EM_PARA_TYPE>& int_vec);
int readIntArrFromString(string str, string delimiter, EM_PARA_TYPE* int_vec);
int readDoubleArrFromString(string str, string delimiter, EM_DATA_TYPE* arr, const int L_NUM);

extern MESSAGE_LENGTH_TYPE CutAndEncrypt(char * inputFileName, char * storeFileName);
extern MESSAGE_LENGTH_TYPE getFileSize(char * inputFileName);
extern MESSAGE_LENGTH_TYPE getEncryptedLength(char * inputFileName);
extern MESSAGE_LENGTH_TYPE paraEncryptedAndCombine(MESSAGE_LENGTH_TYPE data, char** ptr, MESSAGE_LENGTH_TYPE length);
extern MESSAGE_LENGTH_TYPE fileEncryptedAndCombine(char* fileName, char** ptr, MESSAGE_LENGTH_TYPE length);

int count_lines(char* file_path);
int attestation_client(Socket *S, sample_ec256_private_t g_sp_priv_key);
int load_data_client( int algo, char* file_path, char** SNPs_IDs, char** pp_data, int* data_size);
int data_encryption( char* data, int data_size, char* data_encrypted);
int assemble_msg4( ra_samp_response_header_t** pp_msg4, int* msg4_full_size, char* data, int data_size);
int data_decryption( char* data, char* decrypted_data, int data_size);
int data_decryption1( char* data, char* decrypted_data, int data_size);

bool readyToSend(Socket *clientSocket);
void sendPara(Socket* S, MESSAGE_LENGTH_TYPE para);
void sendFile(Socket* S, string fileName);

string getFilename (const std::string& str)
{
  std::size_t found = str.find_last_of("/\\");
  return str.substr(found+1);
}


sample_ec256_private_t convert_private_key(char *private_key)
{
	sample_ec256_private_t p_key;
	char hex[3];
	hex[2] = 0;
	char dec;
	char *str; 

	for (int i=0; i<32; i++)
	{
		memcpy(hex, private_key+i*2,2);
		dec = (char)strtol(hex, &str, 16);
		p_key.r[31-i] = (uint8_t)dec;
	}

	return p_key;
}


int client (const char *IP, int port, ClientDataManagement* client_data_mngt, char *username, char *password, sample_ec256_private_t g_sp_priv_key, int max_attempt)
{
	int* CHR = NULL;
	char * SNPs_IDs =NULL;
	int* BP = NULL;
	char* b_label = NULL;
	char* c_label = NULL;
	bool SSLenable = false;
	Socket S;
	int tried_times = 0;

	//Try to connect the server;
#define MAX_DELAY 100
	while ( tried_times < max_attempt)
	{
		cout << "Attempt:" << tried_times + 1 << "/" <<max_attempt << endl; 
		tried_times ++;
		if(S.Connect(IP,port,0))
		{
			break;
		}

	}

	printf ("CLIENT: connect\n");
	char askSSL[] = "SSL?";
	S.Send(askSSL,5);

	char buf[5];
	int bytes = S.Recv (buf, 5);
	SSL_CTX *ctx;
	if ((bytes >= 0) && (!strcmp(buf, "SSL!")))
	{
		SSLenable = true;
		S.setSSLenable(SSLenable);
		ctx = initilizeSSL();
		char CA_file[20] = "ca-chain.cert.pem";
		SSL_CTX_load_verify_locations(ctx, CA_file, NULL);

		SSL* ssl = establishSSL(S.GetSockfd(), ctx);
		S.setSSLpair(ssl, S.GetSockfd());
	}

	//authentication
	printf("CLIENT: Start Authentication!\n");
	char msg[5];
	bytes = S.Recv (msg, 5);
	if ((bytes >= 0) && (!strcmp(msg, "auth")))
	{
		int size = strlen(username) + strlen(password) + 2;
		int sz_d = S.Send((char *)&size, sizeof(int));
		sz_d = S.Send(username, strlen(username)+1);
		sz_d = S.Send(password, strlen(password)+1);
	}

	printf("CLIENT: Authentication Pass!\n");

	int segment_length = 0;
	int total_length = 0;
	if(S.Recv((char*)&segment_length, 4) != 4)
	{
		printf("CLIENT: **TDT** Receiving Segment Length Error!\n");
	}

	int compression = 0;
	if(S.Recv((char*)&compression, 4) != 4) {
		printf("CLIENT: **TDT** Receiving Compression Flag Error!\n");
	}

	int report_summary_flag = 0;
	if(S.Recv((char*)&report_summary_flag, 4) != 4) {
		printf("CLIENT: Receiving Rrport Summary Flag Error!\n");
	}


#ifdef PROFILE_TIME
	microseconds total_time(0);
	auto start = high_resolution_clock::now();
#endif
	attestation_client(&S, g_sp_priv_key);

#ifdef PROFILE_TIME
	auto end = high_resolution_clock::now();
	total_time = duration_cast<microseconds>(end - start);
	cout << "Remote attestation: " << total_time.count() << "microseconds";
	cout << endl << endl;
#endif

	printf("CLIENT: Attestation Pass!\n");



	int server_status;
	bytes = S.Recv ((char*)&server_status, sizeof(int));

	if(server_status != 0){
		return 0;
	}

	int num_of_uploading_files = client_data_mngt->getNumOfUploadingFiles();
	int num_of_queries = client_data_mngt->getNumOfQuery();

	int request0 = num_of_uploading_files * QUERY_UPLOADING_MOD + num_of_queries;
	S.Send((char*)&request0, sizeof(int));	

	if(num_of_uploading_files > 0)
	{
		for(int i = 0; i < client_data_mngt->getNumOfUploadingFiles(); i++){
			string uploading_file_path = client_data_mngt->getUploadingFileAt(i);
			
			VCFFile vcf_file(uploading_file_path);
			vcf_file.packingData();
			int num_of_divided_files = vcf_file.getFilesNum();
			S.Send((char*)&num_of_divided_files, sizeof(int));

			//devide files
			for(int m = 0; m < num_of_divided_files; m++)
			{
				string uploading_file_name = getFilename(vcf_file.getFileName(m));
				int len_file_name = uploading_file_name.length() + 1;
				S.Send((char*)&len_file_name, sizeof(int));
				S.Send(uploading_file_name.c_str(), len_file_name);

				ifstream file_hash(vcf_file.getHashFile(m), std::ios::binary | std::ios::ate);
				int size_hash = file_hash.tellg();
				file_hash.seekg(0, std::ios::beg);
				std::vector<char> buffer_hash(size_hash);
				if (file_hash.read(buffer_hash.data(), size_hash))
				{
					int encryptedFile_size = size_hash + ENCRYPTED_ADD_SIZE;
					char* encrypted_data = new char[encryptedFile_size];
					data_encryption(buffer_hash.data(), size_hash, encrypted_data);
					S.Send((char*)&encryptedFile_size, sizeof(int));
					S.Send(encrypted_data, encryptedFile_size);	
					delete[] encrypted_data;
				}

				ifstream file_data(vcf_file.getDataFile(m), std::ios::binary | std::ios::ate);
				int size_data = file_data.tellg();
				file_data.seekg(0, std::ios::beg);
				std::vector<char> buffer_data(size_data);
				if (file_data.read(buffer_data.data(), size_data))
				{
					int encryptedFile_size = size_data + ENCRYPTED_ADD_SIZE;
					char* encrypted_data = new char[encryptedFile_size];
					data_encryption(buffer_data.data(), size_data, encrypted_data);
					S.Send((char*)&encryptedFile_size, sizeof(int));
					S.Send(encrypted_data, encryptedFile_size);
					delete[] encrypted_data;
				}

				char buffer0[1];
				S.Recv(buffer0, 1);

				if(buffer0[0] != 'Y')
				{
					//cout << "Successfully uploading and sealing file " << uploading_file_name << endl;
					cout << "Unsuccessuflly uploading and sealing data" << uploading_file_name << endl;
					exit(0);
				}
			}
			// end


			//string uploading_file_name = getFilename(uploading_file_path);
			//int len_file_name = uploading_file_name.length() + 1;
			//S.Send((char*)&len_file_name, sizeof(int));
			//S.Send(uploading_file_name.c_str(), len_file_name);

			//ifstream file_hash(vcf_file.getHashFile(), std::ios::binary | std::ios::ate);
			//int size_hash = file_hash.tellg();
			//file_hash.seekg(0, std::ios::beg);
			//std::vector<char> buffer_hash(size_hash);
			//if (file_hash.read(buffer_hash.data(), size_hash))
			//{
			//	int encryptedFile_size = size_hash + ENCRYPTED_ADD_SIZE;
			//	char* encrypted_data = new char[encryptedFile_size];
			//	data_encryption(buffer_hash.data(), size_hash, encrypted_data);
			//	S.Send((char*)&encryptedFile_size, sizeof(int));
			//	S.Send(encrypted_data, encryptedFile_size);	
			//	delete[] encrypted_data;
			//}

			//ifstream file_data(vcf_file.getDataFile(), std::ios::binary | std::ios::ate);
			//int size_data = file_data.tellg();
			//file_data.seekg(0, std::ios::beg);
			//std::vector<char> buffer_data(size_data);
			//if (file_data.read(buffer_data.data(), size_data))
			//{
			//	int encryptedFile_size = size_data + ENCRYPTED_ADD_SIZE;
			//	char* encrypted_data = new char[encryptedFile_size];
			//	data_encryption(buffer_data.data(), size_data, encrypted_data);
			//	S.Send((char*)&encryptedFile_size, sizeof(int));
			//	S.Send(encrypted_data, encryptedFile_size);
			//	delete[] encrypted_data;
			//}

			//char buffer0[1];
			//S.Recv(buffer0, 1);

			//if(buffer0[0] == 'Y')
			//{
			//	cout << "Successfully uploading and sealing file " << uploading_file_name << endl;
			//}
			//else
			//{
			//	cout << "Unsuccessuflly uploading and sealing data" << uploading_file_name << endl;
			//}

		}
	}

	
	if(num_of_queries > 0){
		char* server_state_tmp = new char[1];
		int len1 = S.Recv(server_state_tmp, 1);

		if((len1 != 1) || (*server_state_tmp != 'Y')){
			printf("Fail to make query with the SGX!\n");
			goto CLEAN_UP_1;
		}else{
			printf("Start making query with the SGX!\n");
		}

		//int enc_query_len = sizeof(Query) + ENCRYPTED_ADD_SIZE;
		//char* tmp_enc = new char[enc_query_len];
		int i = 0;

		//Query tmp2;
		while(i < num_of_queries){
			vector<uint64_t> query_tmp = client_data_mngt->getPackedQueryAt(i);
			int query_len = sizeof(uint64_t) * query_tmp.size();
			int enc_query_len = query_len + ENCRYPTED_ADD_SIZE;
			char *query = new char[query_len];
			char *enc_query = new char[enc_query_len];
			//std::copy(query_tmp.begin(), query_tmp.end(), query);
			memcpy(query, &query_tmp[0], query_len);

			cout << "query_tmp[0] = " << query_tmp[0] << ", query = " << *((uint64_t*)query) << endl;
			

			data_encryption(query, query_len, enc_query);
			cout << "enc_64bit = " << *((uint64_t*)enc_query)<<endl;

			char* data_dec1 = new char[query_len];


#ifdef DEB_QUERY_ECNRYPTION
			data_decryption1(enc_query, data_dec1, query_len);

			if(*((uint64_t*)data_dec1) == *((uint64_t*)query))
			{
				cout << "decryption successlly in debug" << endl;
			}
#endif


			S.Send((char*)&enc_query_len, sizeof(int));
			S.Send(enc_query, enc_query_len);

			int enc_res_len;
			S.Recv(&enc_res_len, sizeof(int));
			char* enc_res = new char[enc_res_len];
			S.Recv(enc_res, enc_res_len);
			int res_len = sizeof(int) * query_tmp.size();
			int* res = (int *)malloc(res_len);
			data_decryption(enc_res, (char*)res, res_len);

			int correct_num = 0;
			for( int n = 0; n < query_tmp.size(); n++)
			{
				if(res[n] > 0)
				{
					correct_num++;
				}
			}

			cout << "Query " << client_data_mngt->getQueryAt(i) <<": " << correct_num << " over " << query_tmp.size() << " correct!"<<endl;
			i++;

			free(res);
			free(query);
			free(enc_query);
		}

	}

CLEAN_UP_1:

	S.Close();

	if (SSLenable)
	{
		freeCTX(ctx);
	}

	return 1;
}

//******************************************************************************
//                            MAIN FUNCTION
//******************************************************************************
int main(int argc, char *argv[]) 
{
	//usage:
	//Distributed_Secure_GWAS_client -c <config file path>
	//Distributed_Secure_GWAS_client -s <server IP> -p <port> -f <case file path> <control file path>
	//Distributed_Secure_GWAS_client -h
	//Distributed_Secure_GWAS_client -v

	//parse the arguments
	int max_timeout = 0;
	int port = 7890;
	int parser = 0;
	int compression = 0;
	char server_IP[30];
	char file_uploading_query[MAX_FILE_PATH_LENGTH];
	char private_Key[65];
	char username[20];
	char password[20];
	sample_ec256_private_t g_sp_priv_key;
	ClientDataManagement client_data_mngt;

	if (argc <= 1)
	{
		Config configSetting;
		if (configSetting.Parse("client_config.txt"))
		{
			//configSetting.Read("DataFilePath0").length()
			strcpy_s(server_IP, configSetting.Read("ServerIP").c_str());
			max_timeout = atoi( configSetting.Read("MaxAttempt").c_str());
			parser = atoi(configSetting.Read("Parser").c_str());
			port = atoi(configSetting.Read("ServerPort").c_str());
			strcpy_s(private_Key, configSetting.Read("PrivateKey").c_str());
			g_sp_priv_key = convert_private_key(private_Key);
			strcpy_s(file_uploading_query, configSetting.Read("UploadingQueryFiles").c_str());
			strcpy_s(username, configSetting.Read("Username").c_str());
			strcpy_s(password, configSetting.Read("Password").c_str());
		}
		else
		{
			printf("Config file open fail.\n");
			return -1;
		}

	}
	else 
	{
		for (int i = 1; i < argc; i++) 
		{
			if (argv[i][0] == '-') 
			{			
				if (argv[i][1] == 'c') 
				{
					Config configSetting;
					if (configSetting.Parse(argv[i+1]))
					{
						//configSetting.Read("DataFilePath0").length()
						strcpy_s(server_IP, configSetting.Read("ServerIP").c_str());
						max_timeout = atoi( configSetting.Read("MaxAttempt").c_str());
						parser = atoi(configSetting.Read("Parser").c_str());
						port = atoi(configSetting.Read("ServerPort").c_str());
						strcpy_s(private_Key, configSetting.Read("PrivateKey").c_str());
						g_sp_priv_key = convert_private_key(private_Key);
						strcpy_s(file_uploading_query, configSetting.Read("UploadingQueryFiles").c_str());
						strcpy_s(username, configSetting.Read("Username").c_str());
						strcpy_s(password, configSetting.Read("Password").c_str());
						i++;
					}
					else
					{
						printf("Config file open fail.\n");
						return -1;
					}
				}
				else if (argv[i][1] == 's') 
				{
					strcpy_s(server_IP, argv[i+1]);
					i++;
				}
				else if (argv[i][1] == 'p')
				{
					port = atoi(argv[i+1]);
					i++;
				}
				else if (argv[i][1] == 'f')
				{
					strcpy_s(file_uploading_query, argv[i+1]);
					i+=1;
				}
				else if (argv[i][1] == 'h')
				{
					printf("usage:\n");
					printf("Distributed_Secure_GWAS_client -c <config file path>\n");
					printf("Distributed_Secure_GWAS_client -s <server IP> -p <port> -f <case file path> <control file path>\n");
					printf("Distributed_Secure_GWAS_client -h\n");
					printf("Distributed_Secure_GWAS_client -v\n");
					return 0;
				}
				else if (argv[i][1] == 'v')
				{
					printf("Version: v1.0\nRelease data: Feb 10th 2016\n");
					return 0;
				}
				else 
				{
					printf("Unknown option!\n");
					return -1;
				}
			} 
			else 
			{
				printf("Unknown option!\n");
				return -1;
			}

		}
	}

	client_data_mngt.Parse((uint8_t*)file_uploading_query);
	//client_data_mngt.printAllUploadingFilesAndQueries();

	client(server_IP, port, &client_data_mngt, username, password, g_sp_priv_key, max_timeout);

	return 0;
}

//*****************************************************************************
//
//! Application could identify whether to send message
//!
//! \param  clientSocket : the pointer to the socket
//! 
//! \return indicate whether to send message
//!
//*****************************************************************************
bool readyToSend(Socket *clientSocket)
{
	char answer = '0';
	clientSocket->Recv((char*)&answer, sizeof(char));

	if (answer == '0')
	{
		return false;
	}

	else
	{
		return true;
	}
}

//*****************************************************************************
//
//! Application could send the encrypted parameter
//!
//! \param  buffer : the pointer to the parameter
//! \param  length : the num of the bytes in the parameter
//! 
//! \return none
//!
//*****************************************************************************
void sendPara(Socket* S, MESSAGE_LENGTH_TYPE para)
{
	char *rawBuffer = new char[sizeof(MESSAGE_LENGTH_TYPE)];
	MESSAGE_LENGTH_TYPE encryptedLength = sizeof(MESSAGE_LENGTH_TYPE) + ENCRYPTED_ADD_SIZE;
	char *encryptedBuffer = new char[encryptedLength];

	memmove(rawBuffer, &para, sizeof(MESSAGE_LENGTH_TYPE));
	data_encryption(rawBuffer, sizeof(MESSAGE_LENGTH_TYPE), encryptedBuffer);

	//for (int i = 0; i < encryptedLength; i++)
	//{
	//	putchar(encryptedBuffer[i]);
	//}
	//cout<<endl;

	//Send the para, first the length then the content
	//S->Send((char *)&encryptedLength, sizeof(MESSAGE_LENGTH_TYPE));
	S->Send((char *) encryptedBuffer, encryptedLength);

	delete[] rawBuffer;
	delete[] encryptedBuffer;
}

//*****************************************************************************
//
//! Application could send the encrypted parameter
//!
//! \param  buffer : the pointer to the parameter
//! \param  length : the num of the bytes in the parameter
//! 
//! \return none
//!
//*****************************************************************************
void sendFile(Socket* S, string fileName)
{
	MESSAGE_LENGTH_TYPE pos = 0;
	MESSAGE_LENGTH_TYPE temp_size;
	MESSAGE_LENGTH_TYPE counter = TRANSFERBOLCKS;
	MESSAGE_LENGTH_TYPE fillSize = 0;
	MESSAGE_LENGTH_TYPE sentSize = 0;

	char* storeData = new char[SEALING_BUFFER_SIZE];
	char* encryptedData = new char[SEALING_BUFFER_SIZE + ENCRYPTED_ADD_SIZE];
	char* sendBuffer = new char[(SEALING_BUFFER_SIZE + ENCRYPTED_ADD_SIZE)*TRANSFERBOLCKS];
	File* deezFile = File::Open(fileName,"rb");

	if (deezFile == NULL)
	{
		cout<<"Could not open the file"<<fileName<<endl;
		exit(1);
	}

	MESSAGE_LENGTH_TYPE deezFileSize = deezFile->size();

#ifdef DEBUG1
	cout<<"The size of deez file "<<fileName<<" is : "<<deezFileSize<<endl;
	std::chrono::high_resolution_clock::time_point start;
	unsigned long encryptedTime = 0;
	unsigned long sendTime = 0;

	//unsigned long sendSize = 0;
#endif
	while (pos != deezFileSize)
	{
		if (counter == 0)
		{
#ifdef DEBUG1
	start = std::chrono::high_resolution_clock::now();
#endif

			S->Send(sendBuffer, fillSize);

#ifdef DEBUG1
	sendTime += chrono::duration<double, milli>(std::chrono::high_resolution_clock::now() - start).count();
#endif
			printf("\r %.2f%%",pos/(double)deezFileSize*100);
			sentSize += fillSize;
			fillSize = 0;
			counter = TRANSFERBOLCKS;
		}
		else
		{
			temp_size = SEALING_BUFFER_SIZE < (deezFileSize-pos)? SEALING_BUFFER_SIZE:(deezFileSize - pos);
			deezFile->read(storeData, temp_size, pos);
#ifdef DEBUG1
	start = std::chrono::high_resolution_clock::now();
#endif
			data_encryption((char*)storeData, temp_size, encryptedData);
#ifdef DEBUG1
	encryptedTime += chrono::duration<double, milli>(std::chrono::high_resolution_clock::now() - start).count();
			//start = std::chrono::high_resolution_clock::now();
#endif
			memmove(sendBuffer + fillSize, encryptedData, temp_size + ENCRYPTED_ADD_SIZE);
			fillSize = fillSize + temp_size + ENCRYPTED_ADD_SIZE;
			pos += temp_size;
			counter--;
		}
	}
#ifdef DEBUG1
	start = std::chrono::high_resolution_clock::now();
#endif
	S->Send(sendBuffer, fillSize);
#ifdef DEBUG1
	sendTime += chrono::duration<double, milli>(std::chrono::high_resolution_clock::now() - start).count();
#endif
	sentSize += fillSize;
	printf("\r %.2f%%",pos/(double)deezFileSize*100);
	cout<<endl<<"sent "<<sentSize<<endl;
	cout<<"The encrypted time is : "<<encryptedTime<<endl;
	cout<<"The sending time is : " << sendTime << endl; 

	delete[] storeData;
	delete[] encryptedData;
	delete[] sendBuffer;
	deezFile->close();
}

void sendEncryptedBuffer(Socket* S, uint8_t *buffer, int buffer_size)
{
	char *rawBuffer = new char[buffer_size];
	MESSAGE_LENGTH_TYPE encryptedLength = buffer_size + ENCRYPTED_ADD_SIZE;
	char *encryptedBuffer = new char[encryptedLength];

	memmove(rawBuffer, &buffer, buffer_size);
	data_encryption(rawBuffer, buffer_size, encryptedBuffer);

	S->Send((char *)(&encryptedLength), sizeof(MESSAGE_LENGTH_TYPE));
	S->Send((char *) encryptedBuffer, encryptedLength);

	delete[] rawBuffer;
	delete[] encryptedBuffer;
}




