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

#include <unordered_map>

#include "sgx_urts.h" 
#include "Basic.h";

#include "Config.h"
#include "network_ra.h"
// Needed for definition of remote attestation messages.
#include "remote_attestation_result.h"
#include "Debug_Flags.h"
#include "dirent.h"

#include "pthread.h"
#include "ssl_server.h"
#include "FileIO.h"
#include "DataProcess.h"

#include "genome_thread_status.h"

using namespace std;
using namespace chrono;


#define SEALED_FOLDER "../SealedData/"
#define PROFILE_TIME



vector<string> sealed_files_info;

sgx_ra_context_t *context;
sgx_enclave_id_t eid;


#if defined FUNCTION_LEVEL_PROFILE

void *startGenomeThread( void* s_c);

typedef struct server_profile {
	std::chrono::duration<double> create_enclave;
	std::chrono::duration<double> attestation[100];
	std::chrono::duration<double> receive_msg4[100];
	std::chrono::duration<double> verify_attstation[100];
	std::chrono::duration<double> enclave_cal_TDT;
	std::chrono::duration<double> enclave_encryption;

} s_p;

s_p duration;
#endif

const std::string currentDateTime() {
	time_t     now = time(0);
	struct tm  tstruct;
	char       buf[80];
	tstruct = *localtime(&now);
	strftime(buf, sizeof(buf), "%Y-%m-%d-%H-%M-%S", &tstruct);

	return buf;
}


struct compare  
{  
	bool operator()(const int& l, const int& r)  
	{  
		return l > r;  
	}  
};  



/* OCall functions to dump dump*/
void ocall_print_string(const char *str)
{
	/* Proxy/Bridge will check the length and null-terminate 
	* the input string to prevent buffer overflow. 
	*/
	printf("%s", str);
}

Socket serverSocket;
string folder_name;

typedef struct Genome_data
{
	int SNP_count;
	int case_count;
	int control_count;
	char *case_data;
	char *control_data;
}GNOMEDATA;

typedef struct socket_client_pair
{
	int socket_fd;
	int client_id;
	char username[128];
}S_C;

void getFileList(std::string folder, std::string ext, std::vector<std::string> &file_list)
{
	DIR *dir = opendir(folder.c_str());

	struct dirent *entry = readdir(dir);

	while(entry){
		if(entry->d_type == DT_REG){
			std::string fname = entry->d_name;

			if(fname.find(ext, (fname.length() - ext.length())) !=  std::string::npos){
				file_list.push_back(fname);
			}
		}

		entry = readdir(dir);
	}

	return;
}


void reply(Socket* serverSocket, bool receive)
{
	char answer = '1';

	if (receive == true)
	{
		serverSocket->Send((char *)&answer, sizeof(char));
	}
	else
	{
		answer = '0';
		serverSocket->Send((char *)&answer, sizeof(char));
	}
}

void *receive_data( void* s_c) 
{
	//getchar();
#if defined FUNCTION_LEVEL_PROFILE
	std::chrono::high_resolution_clock::time_point start = std::chrono::high_resolution_clock::now();
#endif
	S_C socket_client = *(S_C*)s_c;
	int socket_fd = socket_client.socket_fd;
	int client_id = socket_client.client_id;
	char username[128];
	strcpy_s( username, socket_client.username);

	std::cout <<"SERVER: Request data from client: [" << username <<"] " <<"confirmed!" <<endl;

	char msg[] = "data";
	serverSocket.Send(socket_fd, msg, strlen(msg)+1);

	cout <<"SERVER: Start Receiving Data From client: [" << username <<"]" <<endl;
	//receive msg4
	char *msg4;
	MESSAGE_LENGTH_TYPE length = 0;
	MESSAGE_LENGTH_TYPE pos = 0;
	MESSAGE_LENGTH_TYPE recvLength;
	while(true)
	{
		if (!length)
		{
			if(serverSocket.Recv(socket_fd, (char*)&length,sizeof(MESSAGE_LENGTH_TYPE))!=sizeof(MESSAGE_LENGTH_TYPE)) 
			{
				printf("SERVER: Recv Error! Error code: %i\n", GetLastError());
				return 0;
			}
			msg4 = new char[length];
		}
		else
		{
			while (pos < length)
			{
				recvLength = serverSocket.Recv(socket_fd, msg4+pos,length-pos);

				if (recvLength < 0)
				{
					printf("SERVER: Recv Error! Error code: %i\n", GetLastError());
					return 0;
				}


				pos += recvLength;
				printf("\rThe receiving process: %.2f%%",pos/(double)length*100);
			}
			cout<<endl;
			break;
		}
	}

	cout << "SERVER: MSG4 received form client: [" << username <<"]!" <<endl;
#if defined FUNCTION_LEVEL_PROFILE
	//duration.receive_msg4[client_id] = std::chrono::duration_cast<std::chrono::duration<double>>(std::chrono::high_resolution_clock::now() - start);
	cout << "The running time for transfer data is: " 
		<< chrono::duration<double, milli>(std::chrono::high_resolution_clock::now() - start).count() << " ms\n";
#endif
	return msg4;
}

void *server_data_collection(void* socket_fd)
{
	GNOMEDATA *genome_data = new GNOMEDATA;
	int socket = *(int *)socket_fd;

	printf ("SERVER: Request data\n");

	char msg[] = "data";
	serverSocket.Send(socket, msg, strlen(msg)+1);

	printf("SERVER: Start Receiving Data!\n");

	int length = 0;
	int pos = 0;
	char *buf;
	while(true)
	{
		if (!length)
		{
			if(serverSocket.Recv(socket, (char*)&length,4)!=4) 
			{
				printf("SERVER: Recv Error! Error code: %i\n", GetLastError());
				return 0;
			}
			buf = new char[length];
		}
		else
		{
			while (pos < length)
			{
				pos += serverSocket.Recv(socket, buf+pos,length-pos);
			}
			break;
		}
	}
	if (length >= 0)
	{
		printf ("SERVER: Client data received %d bytes\n", length);

		genome_data->SNP_count = *((int *)buf);
		genome_data->case_count = *((int *)(buf+sizeof(int)));
		genome_data->control_count = *((int *)(buf+2*sizeof(int)));

		int case_bytes = genome_data->SNP_count*genome_data->case_count*2;
		genome_data->case_data = new char[case_bytes];
		memcpy(genome_data->case_data, buf+3*sizeof(int),case_bytes);

		int control_bytes = genome_data->SNP_count*genome_data->control_count*2;
		genome_data->control_data = new char[control_bytes];
		memcpy(genome_data->control_data, buf+3*sizeof(int)+case_bytes, control_bytes);

		delete buf;
	}

	return genome_data;
}

void sendBackMessage(Socket* serverSocket, int socketID, double dist, sgx_ra_context_t context, sgx_enclave_id_t eid)
{
	char * response = new char[sizeof(double)];
	char * encryptedResponse = new char[sizeof(double) + ENCRYPTED_ADD_SIZE];

	memmove(response, &dist, sizeof(double));
	encryptData(eid, context, (uint8_t *) response, sizeof(double), 
		(uint8_t *)encryptedResponse, sizeof(double) + ENCRYPTED_ADD_SIZE);

	serverSocket->Send(socketID, encryptedResponse, sizeof(double)+ENCRYPTED_ADD_SIZE);

	delete[] response;
	delete[] encryptedResponse;
}

int server (int client_num, int account_count, int port, char **username, char **password, int algo, int topK,int segment_length, int SSLenable, int compression, int request_summary)
{
	bool *authResult = new bool[account_count];
	for (int i=0; i<account_count; i++)
	{
		authResult[i] = false;
	}


	FILE* OUTPUT = stdout;

	//create enclave
	int ret = SGX_SUCCESS;
	sgx_launch_token_t token = {0};
	int updated = 0;
	context = new sgx_ra_context_t[client_num];
	sgx_status_t status = SGX_SUCCESS;

#ifdef PROFILE_TIME
	microseconds total_time(0);
	auto start = high_resolution_clock::now();
#endif

	ret = sgx_create_enclave(ENCLAVE_FILE,
		SGX_DEBUG_FLAG,
		&token,
		&updated,
		&eid, NULL);

#ifdef PROFILE_TIME
	auto end = high_resolution_clock::now();
	total_time = duration_cast<microseconds>(end - start);
	cout << "Create enclave time: " << total_time.count() << "microseconds";
	cout << endl << endl;
#endif

	if(SGX_SUCCESS != ret)
	{
		fprintf(OUTPUT, "\nError %#x, call sgx_create_enclave fail [%s].", ret,
			__FUNCTION__);
		return -1;
	}
	fprintf(OUTPUT, "\nCall sgx_create_enclave success.\n");

	//Communication with client
	pthread_t *t_client = (pthread_t *)malloc(client_num*sizeof(pthread_t));
	ra_samp_response_header_t **pp_att_result_msg_full = new ra_samp_response_header_t*[client_num];

	S_C *socket_client = new S_C[client_num];


	serverSocket.setSSLenable(SSLenable);
	SSL_CTX *ctx;
	if (SSLenable)
	{
		char certificate_file[30] = "enclave_server.cert.pem";
		char privkey_file[30] = "enclave_server.key.pem";
		ctx = initilizeSSL(certificate_file, privkey_file);
	}


	if(!serverSocket.Connect(0,port,0))
	{
		printf("SERVER: Fail to Listen!\n");
	}
	printf("SERVER: Start Listening!\n");

	for (int i=0; i<client_num; )
	{
		socket_client[i].socket_fd = serverSocket.Accept();

		//SSL setting
		char buf_SSL[5];
		int bytes = serverSocket.RecvInitInfo (socket_client[i].socket_fd, buf_SSL, 5);
		if ((bytes >= 0) && (!strcmp(buf_SSL, "SSL?")))
		{
			if (SSLenable)
			{
				strcpy(buf_SSL,"SSL!");
				serverSocket.SendInitInfo(socket_client[i].socket_fd, buf_SSL, 5);
			}
			else
			{
				strcpy(buf_SSL,"nSSL");
				serverSocket.SendInitInfo(socket_client[i].socket_fd, buf_SSL, 5);
			}
		}
		printf("SERVER: SSL settings sent!\n");

		if (SSLenable)
		{
			SSL *ssl = acceptSSL(socket_client[i].socket_fd, ctx);
			serverSocket.setSSLpair(ssl, socket_client[i].socket_fd);
		}

		//authentication
		printf("SERVER: Start Authentication!\n");
		char msg[] = "auth";
		serverSocket.Send(socket_client[i].socket_fd, msg, strlen(msg)+1);

		int length = 0;
		int pos = 0;
		char *buf;
		int recvLength;
		while(true)
		{
			if (!length)
			{
				if(serverSocket.Recv(socket_client[i].socket_fd, (char*)&length,4)!=4) 
				{
					printf("SERVER: Recv Error! Error code: %i\n", GetLastError());
					return 0;
				}
				buf = new char[length];
			}
			else
			{
				while (pos < length)
				{
					recvLength = serverSocket.Recv(socket_client[i].socket_fd, buf+pos,length-pos);
					if (recvLength < 0)
					{
						printf("SERVER: Recv Error! Error code: %i\n", GetLastError());
						return 0;
					}
					pos += recvLength;
				}
				break;
			}
		}
		if (length >= 0)
		{
			//split username and password
			int split_pos = 0;
			for (int j=0; j<length; j++)
			{
				if (buf[j] == 0)
				{	
					split_pos = j+1;
					break;
				}
			}
			//compare and authorize
			int authSuccess = 0;
			for (int j=0; j<account_count; j++)
			{
				if (!strcmp(buf,username[j]))
				{
					if (!strcmp(buf+split_pos,password[j]))
					{
						if (authResult[j])
							break;
						authResult[j] = true;
						authSuccess = 1;
						socket_client[i].client_id = j;
						strcpy_s(socket_client[i].username, username[j]);
						break;
					}
				}
			}
			if (!authSuccess)
			{
				printf("No such username password combination.\n");
				continue;
			}
		}

		printf("SERVER: Authentication Pass!\n");

#if defined SERVER_DEBUG
		printf("!!DEBUG!! segment length: %d\n", segment_length);
#endif

		if( algo == 0) 
		{
			serverSocket.Send( socket_client[i].socket_fd, (char*)&segment_length, sizeof(int));
			serverSocket.Send( socket_client[i].socket_fd, (char*)&compression, sizeof(int));
		}
		serverSocket.Send( socket_client[i].socket_fd, (char*)&request_summary, sizeof(int));

		//attestation
		cout <<"SERVER: Start Attestation to client: [" << username[socket_client[i].client_id] <<"]" <<endl;
#if defined PROFILE_TIME
		start = high_resolution_clock::now();
#endif
		ret = attestation(eid, &(context[i]), status, &serverSocket, socket_client[i].socket_fd, socket_client[i].client_id);
#if defined FUNCTION_LEVEL_PROFILE
		end = high_resolution_clock::now();
		total_time = duration_cast<microseconds>(end - start);
		cout<< "The attestation time in serve side: " << total_time.count();
		cout << endl << endl;
#endif		

		if (ret == 1)
		{
			cout << "SERVER: Attestation Report to client: [" << username[socket_client[i].client_id] <<"]" <<endl;
		}

		int msg4_full_size = 0;
		serverSocket.Recv(socket_client[i].socket_fd, (char*)&msg4_full_size, sizeof(int));
		ra_samp_response_header_t* p_att_result_full = (ra_samp_response_header_t *)malloc(msg4_full_size);
		serverSocket.Recv(socket_client[i].socket_fd, (char*)p_att_result_full, msg4_full_size);

		sample_ra_att_result_msg_t * p_att_result_msg_body =
			(sample_ra_att_result_msg_t *)((uint8_t*)p_att_result_full
			+ sizeof(ra_samp_response_header_t));

		if(p_att_result_full != NULL && TYPE_RA_ATT_RESULT != p_att_result_full->type)
		{
			ret = -1;
			fprintf(OUTPUT, "\nError. Sent MSG3 successfully, but the message "
				"received was NOT of type att_msg_result. Type = "
				"%d. [%s].", p_att_result_full->type,
				__FUNCTION__);
			exit (-1);
		}


#if defined DUMP_LOG
		PRINT_BYTE_ARRAY(OUTPUT, p_att_result_full->body,
			p_att_result_full->size);
#endif

		// Check the MAC using MK on the attestation result message.
		// The format of the attestation result message is ISV specific.
		// This is a simple form for demonstration. In a real product,
		// the ISV may want to communicate more information.


		ret = verify_att_result_mac(eid,
			&status,
			context[i],
			(uint8_t*)&p_att_result_msg_body->platform_info_blob,
			sizeof(ias_platform_info_blob_t),
			(uint8_t*)&p_att_result_msg_body->mac,
			sizeof(sgx_mac_t));


		if((SGX_SUCCESS != ret) ||
			(SGX_SUCCESS != status))
		{
			ret = -1;
			fprintf(OUTPUT, "\nError: INTEGRITY FAILED - attestation result "
				"message MK based cmac failed in [%s].",
				__FUNCTION__);
			exit (-1);
		}

		bool attestation_passed = true;
		// Check the attestation result for pass or fail.
		// @TODO:  Check the status.  This is ISV defined.
		if(0 != p_att_result_full->status[0]
		|| 0 != p_att_result_full->status[1])
		{
			fprintf(OUTPUT, "\nError, attestation result message MK based cmac "
				"failed in [%s].", __FUNCTION__);
			attestation_passed = false;
		}

		if (attestation_passed) 
		{
			cout << endl << "SERVER: MSG4 from client: [" << username[socket_client[i].client_id] <<"] " <<"confirmed." <<endl;
		}

		initializeEnclave(eid,client_num);

		//start receiving data
		pthread_create(&t_client[i], NULL, &startGenomeThread, &(socket_client[i]));

	}

	cleanBuffers(eid);
	sgx_destroy_enclave(eid);
	return 0;
}


#ifdef UNICODE
#define CreateDirectory  CreateDirectoryW
#else
#define CreateDirectory  CreateDirectoryA
#endif // !UNICODE

bool CheckFolderExist(string &strPath)
{
	WIN32_FIND_DATA  wfd;
	bool rValue = false;

	wchar_t wtext[200];
	mbstowcs(wtext, strPath.c_str(), strPath.size()+1);//Plus null

	HANDLE hFind = FindFirstFile(wtext, &wfd);
	if ((hFind != INVALID_HANDLE_VALUE) && (wfd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
	{
		rValue = true;   
	}
	FindClose(hFind);
	return rValue;
}

int main(int argc, char *argv[]) {
	//usage:
	//Distributed_Secure_GWAS -c <config file path>
	//Distributed_Secure_GWAS -n <number of clients> -p <port> -a <algorithm>
	//Distributed_Secure_GWAS -h
	//Distributed_Secure_GWAS -v

	//parse the arguments

	string resultFolder = "result";
	if (!CheckFolderExist(resultFolder))
	{
		wchar_t wtext_result[200];
		mbstowcs(wtext_result, resultFolder.c_str(), resultFolder.size()+1);//Plus null
		if( !CreateDirectory(wtext_result, NULL)) {
			printf ("create result directory failed!\n");
			exit(1);
		}
	}

	folder_name = "result\\" + currentDateTime();
	wchar_t wtext[200];
	mbstowcs(wtext, folder_name.c_str(), folder_name.size()+1);//Plus null
	folder_name = folder_name + "\\";
	if( !CreateDirectory(wtext, NULL)) {
		printf ("create directory failed!\n");
		exit(1);
	}

	int client_num;
	int account_count;
	int algo = 1;
	int topK = 0;
	int segment_length = 0;
	int port = 7890;
	int compression;
	int request_summary;
	int SSL = 0;
	char **username;
	char **password;
	for (int i = 1; i < argc; i++) 
	{
		if (argv[i][0] == '-') 
		{
			if (argv[i][1] == 'c') 
			{
				Config configSetting;

				if (configSetting.Parse(argv[i+1]))
				{
					account_count = atoi(configSetting.Read("AccountCount").c_str());
					client_num = atoi(configSetting.Read("ClientNum").c_str());
					algo = atoi(configSetting.Read("Algortihm").c_str());
					if (algo == 0) //TDT
					{
						topK = atoi(configSetting.Read("TopK").c_str());
						segment_length = atoi(configSetting.Read("SegmentLength").c_str());

					}
					port = atoi(configSetting.Read("ServerPort").c_str());
					compression = atoi(configSetting.Read("Compression").c_str());
					request_summary = atoi(configSetting.Read("RequestSummary").c_str());
					SSL = atoi(configSetting.Read("SSL").c_str());

					username = new char*[account_count];
					password = new char*[account_count];

					for (int j=0; j<account_count; j++)
					{
						string key_u = "Username";
						key_u += std::to_string(j);
						int length = configSetting.Read(key_u).length();
						username[j] = new char[length+1];
						strcpy(username[j], configSetting.Read(key_u).c_str());

						string key_p = "Password";
						key_p += std::to_string(j);
						length = configSetting.Read(key_p).length();
						password[j] = new char[length+1];
						strcpy(password[j], configSetting.Read(key_p).c_str());
					}
					i++;
				}
				else
				{
					printf("Config file open fail.\n");
					return -1;
				}
			}
			else if (argv[i][1] == 'n') 
			{
				client_num = atoi(argv[i+1]);
				i++;
			}
			else if (argv[i][1] == 'p')
			{
				port = atoi(argv[i+1]);
				i++;
			}
			else if (argv[i][1] == 'a')
			{
				algo = atoi(argv[i+1]);
				i++;
			}
			else if (argv[i][1] == 'h')
			{
				printf("usage:\n");
				printf("Distributed_Secure_GWAS -c <config file path>\n");
				printf("Distributed_Secure_GWAS -n <number of clients> -p <port> -a <algorithm>\n");
				printf("Distributed_Secure_GWAS -h\n");
				printf("Distributed_Secure_GWAS -v\n");
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

	server(client_num, account_count, port, username, password, algo, topK, segment_length, SSL, compression, request_summary);
	return 0;
}


void *startGenomeThread( void* s_c)
{
	int ret_status = GENOME_THREAD_RET_OK;

	S_C socket_client = *(S_C*)s_c;
	int socket_fd = socket_client.socket_fd;
	int client_id = socket_client.client_id;
	char username[128];
	strcpy_s( username, socket_client.username);

	printf("SERVER: Secure channel has been established between SGX and client : [ %s ]\n", username);


	int status0 = READY_STATUS;
	serverSocket.Send(socket_fd, (char*)&status0, sizeof(int));

	int buffer_size = sizeof(int);
	char* buffer0 = (char*)malloc(buffer_size);


	int rec_len = serverSocket.Recv(socket_fd, buffer0, buffer_size);
	if(rec_len != buffer_size){
		ret_status = GENOME_THREAD_RET_ERROR_REQUEST;
		goto GENOME_THREAD_FINISH;
	}

	int req = *((int*)buffer0);

	if(req == 0){
		ret_status = GENOME_THREAD_RET_CLOSE_SERVER;
		goto GENOME_THREAD_FINISH;
	}

	int query_num = req % QUERY_UPLOADING_MOD;
	int uploading_num = req / QUERY_UPLOADING_MOD;

#ifdef PROFILE_TIME
	microseconds total_time(0);
#endif

	if(uploading_num > 0){
		printf("SERVER: Starting receiving data from client: [ %s ] confirmed!\n", username);

		while(uploading_num-- > 0){
			int num_of_divided_files = 0;
			if(serverSocket.Recv(socket_fd, (char*)&num_of_divided_files ,sizeof(int))!=sizeof(int))
			{
				ret_status = GENOME_THREAD_RET_ERROR_REQUEST;
				goto GENOME_THREAD_FINISH;
			}

			for(int m = 0; m < num_of_divided_files; m++){
				int pos = 0;
				int recvLength;
				char* file_name = NULL;

				if(serverSocket.Recv(socket_fd, (char*)&recvLength,sizeof(int))!=sizeof(int)) 
				{
					ret_status = GENOME_THREAD_RET_ERROR_REQUEST;
					goto GENOME_THREAD_FINISH;
				} 

				//file_name = (char*)malloc(recvLength);
				file_name = new char[recvLength];

				if(serverSocket.Recv(socket_fd, file_name ,recvLength)!=recvLength)
				{
					ret_status = GENOME_THREAD_RET_ERROR_REQUEST;
					goto GENOME_THREAD_FINISH;
				}

				int enc_hash_file_len;

				if(serverSocket.Recv(socket_fd, (char*)&enc_hash_file_len,sizeof(int))!=sizeof(int)) 
				{
					ret_status = GENOME_THREAD_RET_ERROR_REQUEST;
					goto GENOME_THREAD_FINISH;
				} 

				char* enc_hash_file = (char *)malloc(enc_hash_file_len);
				pos = 0;

				while (pos < enc_hash_file_len)
				{

					recvLength = serverSocket.Recv(socket_fd, enc_hash_file+pos, enc_hash_file_len-pos);

					if (recvLength < 0)
					{
						printf("SERVER: Recv Error! Error code: %i\n", GetLastError());
						return 0;
					}


					pos += recvLength;
					//printf("\rThe receiving process: %.2f%%",pos/(double)len_enc_deez*100);
				}

				int enc_data_file_len;

				if(serverSocket.Recv(socket_fd, (char*)&enc_data_file_len,sizeof(int))!=sizeof(int)) 
				{
					ret_status = GENOME_THREAD_RET_ERROR_REQUEST;
					goto GENOME_THREAD_FINISH;
				} 
				char* enc_data_file = (char *)malloc(enc_data_file_len);

				pos = 0;

				while (pos < enc_data_file_len)
				{

					recvLength = serverSocket.Recv(socket_fd, enc_data_file + pos, enc_data_file_len-pos);

					if (recvLength < 0)
					{
						printf("SERVER: Recv Error! Error code: %i\n", GetLastError());
						return 0;
					}


					pos += recvLength;
//					printf("\rThe receiving process: %.2f%%",pos/(double)len_enc_deez*100);
				}
				string sealed_enc_hash_file(SEALED_FOLDER);
				string sealed_enc_data_file(SEALED_FOLDER);
				sealed_enc_hash_file += file_name;
				sealed_enc_data_file += file_name;

				sealed_enc_hash_file += ".hash.sealed";
				sealed_enc_data_file += ".data.sealed";

#ifdef PROFILE_TIME
				auto start = high_resolution_clock::now();
#endif

				sealDZFile(context[0], 0, enc_hash_file, enc_hash_file_len, sealed_enc_hash_file, NULL, eid);
				sealDZFile(context[0], 1, enc_data_file, enc_data_file_len, sealed_enc_data_file, NULL, eid);

#ifdef PROFILE_TIME
				auto end = high_resolution_clock::now();
				total_time += duration_cast<microseconds>(end - start);
#endif

				char buffer1[2] = {'Y', '\0'};
				serverSocket.Send(socket_fd, buffer1 ,1);

				sealed_files_info.push_back(string(file_name));

				//free(file_name);
				delete[] file_name;
			}
		}
	}

#ifdef PROFILE_TIME
	cout << "Seal data: " << total_time.count() << "microseconds";
	cout << endl << endl;
#endif

	if(query_num > 0){
		int res_size = sizeof(uint64_t) + ENCRYPTED_ADD_SIZE;
		uint8_t* res = (uint8_t *)malloc(res_size);//new uint8_t[res_size];

		printf("SERVER: Starting answering query from client.\n", username);
		char tmp[1] = {'Y'}; 

		serverSocket.Send(socket_fd, tmp, 1);

		int tmp_query_num = query_num;
		int enc_query_len;
		char* enc_query_tmp = NULL;



		while(tmp_query_num-->0){
			memset(res, '\0', res_size);

			serverSocket.Recv(socket_fd, &enc_query_len, sizeof(int));
			enc_query_tmp = (char *)malloc(enc_query_len);
			serverSocket.Recv(socket_fd, enc_query_tmp, enc_query_len);

			//printf("The cnc size is %d, and value is %ul\n ", enc_query_len, *((uint64_t*)enc_query_tmp));
			//cout << "The value is " << *((uint64_t*)enc_query_tmp);

			int enc_res_size = (enc_query_len - ENCRYPTED_ADD_SIZE) / sizeof(uint64_t) * sizeof(int) + ENCRYPTED_ADD_SIZE;
			uint8_t *enc_res = (uint8_t*)malloc(enc_res_size);

#ifdef PROFILE_TIME
			auto start = high_resolution_clock::now();
#endif
			cout << "enc_query_len: " << enc_query_len<< endl;
			implementQuery(eid, context[0], enc_res, enc_res_size, (uint8_t *)enc_query_tmp, enc_query_len);
#ifdef PROFILE_TIME
			auto end = high_resolution_clock::now();
			total_time = duration_cast<microseconds>(end - start);
			cout << "The total running time of query " << (query_num - tmp_query_num) << ":" <<  total_time.count() << "microseconds";
			cout << endl << endl;
#endif

			serverSocket.Send(socket_fd, &enc_res_size, sizeof(int));
			serverSocket.Send(socket_fd, enc_res, enc_res_size);

			free(enc_query_tmp);
			free(enc_res);
		}

		free(res);
	}
	
GENOME_THREAD_FINISH:	
	exit(0);
	return (void*)&ret_status;
}


int ocall_fetch_file(int file_type, int file_num, uint8_t* fetched_buffers2unseal,size_t size_to_fetch)
{
	string file_name(SEALED_FOLDER);

	file_name += sealed_files_info[file_num];

	if(file_type == 0)
	{
		file_name +=  ".hash.sealed";
	}
	else
	{
		file_name +=  ".data.sealed";
	}

	ifstream file(file_name, ios::binary | ios::ate);
	streamsize size = file.tellg();
	file.seekg(0, std::ios::beg);

	if ((size != size_to_fetch) ||(!file.read((char *)fetched_buffers2unseal, size_to_fetch)))
	{
		file.close();
		return -1;
	}

	return 0;
}