#include <stdio.h>
#include <iostream>
#include <fstream>
#include <string>
#include <assert.h>
#include <math.h>
#include <ctime>
#include <iomanip>
#include <queue>

#include "sgx_urts.h" 

#include "../Common/Config.h"
#include "../Common/network_ra.h"
// Needed for definition of remote attestation messages.
#include "../Common/remote_attestation_result.h"
#include "../Common/Debug_Flags.h"


#include "../ThirdParty/pthread/include/pthread.h"
#include "../Distributed_Secure_GWAS/ssl_server.h"
#include "server_lib.h"

using namespace std;

#if defined FUNCTION_LEVEL_PROFILE
s_p duration;
#endif

Socket S;
pthread_t *t_client;
S_C *socket_client;

///* OCall functions to dump dump*/
//void ocall_print_string(const char *str)
//{
//	/* Proxy/Bridge will check the length and null-terminate 
//	* the input string to prevent buffer overflow. 
//	*/
//	printf("%s", str);
//}
//by wwj

struct compare  
{  
    bool operator()(const int& l, const int& r)  
    {  
        return l > r;  
    }  
};  

string currentDateTime() {
	time_t     now = time(0);
	struct tm  tstruct;
	char       buf[80];
	tstruct = *localtime(&now);
	strftime(buf, sizeof(buf), "%Y-%m-%d-%H-%M-%S", &tstruct);

	return buf;
}

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


string CreateResultFolder()
{
	string folder_name;
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

	return folder_name;
}

int initServerContext(ServerContext *context)
{
	context->client_num = 1;
	context->account_count = 0;
	context->algo = 1;
	context->topK = 0;
	context->segment_length = 0;
	context->port = 7890;
	context->compression = 0;
	context->request_summary = 0;
	context->SSLenable = 0;

	return 1;
}

int InitServerContextAfterConfig(ServerContext *context)
{
	context->analysisMethod = AnalysisMethod::make_analysis_method(context->algo);

	return 1;
}


int InitEnclave(ServerContext *serverCtx)
{
	FILE* OUTPUT = stdout;

	//create enclave
	sgx_enclave_id_t eid;
	int ret = SGX_SUCCESS;
	sgx_launch_token_t token = {0};
	int updated = 0;
	sgx_ra_context_t *context = new sgx_ra_context_t[serverCtx->client_num];
	sgx_status_t status = SGX_SUCCESS;

#if defined FUNCTION_LEVEL_PROFILE
	std::chrono::high_resolution_clock::time_point start = std::chrono::high_resolution_clock::now();
#endif
	ret = sgx_create_enclave(ENCLAVE_FILE,
		SGX_DEBUG_FLAG,
		&token,
		&updated,
		&eid, NULL);

#if defined FUNCTION_LEVEL_PROFILE
	duration.create_enclave = std::chrono::duration_cast<std::chrono::duration<double>>(std::chrono::high_resolution_clock::now() - start);
#endif
	if(SGX_SUCCESS != ret)
	{
		ret = -1;
		fprintf(OUTPUT, "\nError, call sgx_create_enclave fail [%s].",
			__FUNCTION__);
		return ret;
	}
	fprintf(OUTPUT, "\nCall sgx_create_enclave success.\n");

	serverCtx->eid = eid;
	serverCtx->enclaveContext = context;

	return 1;
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

	cout <<"SERVER: Request data from client: [" << username <<"] " <<"confirmed!" <<endl;

	char msg[] = "data";
	S.Send(socket_fd, msg, strlen(msg)+1);

	cout <<"SERVER: Start Receiving Data From client: [" << username <<"]" <<endl;
	//receive msg4
	char *msg4;
	int length = 0;
	int pos = 0;
	int recvLength;
	while(true)
	{
		if (!length)
		{
			if(S.Recv(socket_fd, (char*)&length,4)!=4) 
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
				recvLength = S.Recv(socket_fd, msg4+pos,length-pos);
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

	cout << "SERVER: MSG4 received form client: [" << username <<"]!" <<endl;
#if defined FUNCTION_LEVEL_PROFILE
	duration.receive_msg4[client_id] = std::chrono::duration_cast<std::chrono::duration<double>>(std::chrono::high_resolution_clock::now() - start);
#endif
	return msg4;
}

int WaitForClients(ServerContext *serverCtx)
{
	
	bool *authResult = new bool[serverCtx->account_count];
	for (int i=0; i<serverCtx->account_count; i++)
	{
		authResult[i] = false;
	}

	t_client = (pthread_t *)malloc(serverCtx->client_num*sizeof(pthread_t));

	socket_client = new S_C[serverCtx->client_num];
	//int *socket_fd = new int[client_num];
	//int *client_id = new int[client_num];

	S.setSSLenable(serverCtx->SSLenable);
	SSL_CTX *ctx;
	if (serverCtx->SSLenable)
	{
		char certificate_file[30] = "enclave_server.cert.pem";
		char privkey_file[30] = "enclave_server.key.pem";
		ctx = initilizeSSL(certificate_file, privkey_file);
	}

	if(!S.Connect(0,serverCtx->port,0))
	{
		printf("SERVER: Fail to Listen!\n");
	}
	printf("SERVER: Start Listening!\n");

	for (int i=0; i<serverCtx->client_num; )
	{
		socket_client[i].socket_fd = S.Accept();

		//SSL setting
		char buf_SSL[5];
		int bytes = S.RecvInitInfo (socket_client[i].socket_fd, buf_SSL, 5);
		if ((bytes >= 0) && (!strcmp(buf_SSL, "SSL?")))
		{
			if (serverCtx->SSLenable)
			{
				strcpy(buf_SSL,"SSL!");
				S.SendInitInfo(socket_client[i].socket_fd, buf_SSL, 5);
			}
			else
			{
				strcpy(buf_SSL,"nSSL");
				S.SendInitInfo(socket_client[i].socket_fd, buf_SSL, 5);
			}
		}
		printf("SERVER: SSL settings sent!\n");

		if (serverCtx->SSLenable)
		{
			SSL *ssl = acceptSSL(socket_client[i].socket_fd, ctx);
			S.setSSLpair(ssl, socket_client[i].socket_fd);
		}

		//authentication
		printf("SERVER: Start Authentication!\n");
		char msg[] = "auth";
		S.Send(socket_client[i].socket_fd, msg, strlen(msg)+1);

		int length = 0;
		int pos = 0;
		char *buf;
		int recvLength;
		while(true)
		{
			if (!length)
			{
				if(S.Recv(socket_client[i].socket_fd, (char*)&length,4)!=4) 
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
					recvLength = S.Recv(socket_client[i].socket_fd, buf+pos,length-pos);
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
			for (int j=0; j<serverCtx->account_count; j++)
			{
				if (!strcmp(buf,serverCtx->username[j]))
				{
					if (!strcmp(buf+split_pos,serverCtx->password[j]))
					{
						if (authResult[j])
							break;
						authResult[j] = true;
						authSuccess = 1;
						socket_client[i].client_id = j;
						strcpy_s(socket_client[i].username, serverCtx->username[j]);
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

		if( serverCtx->algo == 0) 
		{
			S.Send( socket_client[i].socket_fd, (char*)&serverCtx->segment_length, sizeof(int));
			S.Send( socket_client[i].socket_fd, (char*)&serverCtx->compression, sizeof(int));
		}
		S.Send( socket_client[i].socket_fd, (char*)&serverCtx->request_summary, sizeof(int));

		//attestation
		cout <<"SERVER: Start Attestation to client: [" << serverCtx->username[socket_client[i].client_id] <<"]" <<endl;
#if defined FUNCTION_LEVEL_PROFILE
		std::chrono::high_resolution_clock::time_point start = std::chrono::high_resolution_clock::now();
#endif	
		sgx_status_t status = SGX_SUCCESS;
		int ret = attestation(serverCtx->eid, &(serverCtx->enclaveContext[i]), status, &S, socket_client[i].socket_fd, socket_client[i].client_id);
#if defined FUNCTION_LEVEL_PROFILE
		duration.attestation[socket_client[i].client_id] = std::chrono::duration_cast<std::chrono::duration<double>>(std::chrono::high_resolution_clock::now() - start);
#endif		

		if (ret == 1)
		{
			cout << "SERVER: Attestation Report to client: [" << serverCtx->username[socket_client[i].client_id] <<"]" <<endl;
		}

		//start receiving data
		//pthread_create (&t_client[i], NULL, &server_data_collection, &(socket_fd[i]));
		pthread_create (&t_client[i], NULL, &receive_data, &(socket_client[i]));
		i++;
	}

	return 1;
}

int ReceiveDataFromClient(ServerContext *serverCtx)
{
	FILE* OUTPUT = stdout;

	ra_samp_response_header_t **pp_att_result_msg_full = new ra_samp_response_header_t*[serverCtx->client_num];	

	//wait
	for (int i=0; i<serverCtx->client_num; i++)
	{
		pthread_join (t_client[i], (void **)&(pp_att_result_msg_full[i]));
		//pthread_join (t_client[i], (void **)&genome_data[i]);
	}


	char **data;
	int data_size;
	char *p_gcm_mac;

	//check clients' responses, re-align data and macs
	for ( int i = 0; i < serverCtx->client_num; i ++) 
	{
		sample_ra_att_result_msg_t * p_att_result_msg_body =
			(sample_ra_att_result_msg_t *)((uint8_t*)pp_att_result_msg_full[i]
			+ sizeof(ra_samp_response_header_t));

		if(TYPE_RA_ATT_RESULT != pp_att_result_msg_full[i]->type)
		{
			int ret = -1;
			fprintf(OUTPUT, "\nError. Sent MSG3 successfully, but the message "
				"received was NOT of type att_msg_result. Type = "
				"%d. [%s].", pp_att_result_msg_full[i]->type,
				__FUNCTION__);
			exit (-1);
		}

#if defined DUMP_LOG
		PRINT_BYTE_ARRAY(OUTPUT, pp_att_result_msg_full[i]->body,
			pp_att_result_msg_full[i]->size);
#endif

		// Check the MAC using MK on the attestation result message.
		// The format of the attestation result message is ISV specific.
		// This is a simple form for demonstration. In a real product,
		// the ISV may want to communicate more information.

#if defined FUNCTION_LEVEL_PROFILE
		std::chrono::high_resolution_clock::time_point start = std::chrono::high_resolution_clock::now();
#endif
		sgx_status_t status = SGX_SUCCESS;
		int ret = verify_att_result_mac(serverCtx->eid,
			&status,
			serverCtx->enclaveContext[i],
			(uint8_t*)&p_att_result_msg_body->platform_info_blob,
			sizeof(ias_platform_info_blob_t),
			(uint8_t*)&p_att_result_msg_body->mac,
			sizeof(sgx_mac_t));

#if defined FUNCTION_LEVEL_PROFILE
		duration.verify_attstation[socket_client[i].client_id] = std::chrono::duration_cast<std::chrono::duration<double>>(std::chrono::high_resolution_clock::now() - start);
#endif
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
		if(0 != pp_att_result_msg_full[i]->status[0]
		|| 0 != pp_att_result_msg_full[i]->status[1])
		{
			fprintf(OUTPUT, "\nError, attestation result message MK based cmac "
				"failed in [%s].", __FUNCTION__);
			attestation_passed = false;
		}

		if (attestation_passed) {
			cout <<"SERVER: MSG4 from client: [" << serverCtx->username[socket_client[i].client_id] <<"] " <<"confirmed." <<endl;
		}

		//align data at erver's platform
		if(attestation_passed)
		{
			if (!i)
			{
				data_size = p_att_result_msg_body->secret.payload_size;
				data = new char*[serverCtx->client_num];
				//p_gcm_mac = new char[mac_size];
			}
			data[i] = new char[p_att_result_msg_body->secret.payload_size];
			memcpy(data[i], (char *)p_att_result_msg_body->secret.payload,p_att_result_msg_body->secret.payload_size);
			//memcpy(p_gcm_mac+i*16, p_att_result_msg_body->secret.payload_tag, 16);
		}

		cout << "SERVER: Secret successfully received from client: [" << serverCtx->username[socket_client[i].client_id] <<"]" <<endl;
	}

	serverCtx->data = data;
	serverCtx->data_size = data_size;

	return 1;
}

int resultFormat(int choice, int SNP_count, int topK)
{
	if (choice == 0)	//TDT
		return topK*(sizeof(TDT_OUTPUT_TYPE) + sizeof(TDT_OUTPUT_INDEX_TYPE) + 4*sizeof(TDT_INPUT_TYPE)) + 16; //16 is the mac size. mac is generated along with result encryption
	else if (choice == 1)	//Chi
		return SNP_count*(sizeof(int)*4+sizeof(double)) + 16;
	return 0;
}

int ProcessandSendResults(ServerContext *serverCtx)
{
	char **data = serverCtx->data;
	int data_size = serverCtx->data_size;
	int size_left = data_size;

	int size_result = resultFormat(serverCtx->algo,0, serverCtx->topK);
	char *result = new char[size_result*serverCtx->client_num];
	int segment_size = sizeof(int) + 4*serverCtx->segment_length*sizeof(TDT_INPUT_TYPE) + 16;
	int segment_num = ceil( (double)data_size/(double)segment_size);
	//printf( "\nsegment_num %d\n", segment_num);
	int temp_size = 0;


#if defined FUNCTION_LEVEL_PROFILE	
	std::chrono::high_resolution_clock::time_point start = std::chrono::high_resolution_clock::now();
#endif	

	initializeIV(serverCtx->eid,serverCtx->client_num);

	if ( serverCtx->compression) {   //for compressed data
		int* pointer_position = new int[serverCtx->client_num];
		bool stop_flag = false;
		for (int i = 0; i < serverCtx->client_num; i ++) 
		{
			pointer_position[i] = 0;
			load_cm( serverCtx->eid, serverCtx->enclaveContext[i], data[i], 258*sizeof(int) + 16, serverCtx->client_num);
			pointer_position[i] += 258*sizeof(int) + 16;
#if defined COMPRESSION_DEBUG
			printf( "**COMPRESSION_DEBUG!!**pointer_position:%d!\n", pointer_position[i]);
#endif
		}
		while ( true) 
		{
			for ( int i = 0;i < serverCtx->client_num; i ++)
			{
				temp_size = *(int*)( data[i] + pointer_position[i]);
#if defined COMPRESSION_DEBUG
				printf( "**COMPRESSION_DEBUG!!**segment_size:%d!\n", temp_size);
#endif
				updateBC_wraper(serverCtx->eid,  serverCtx->enclaveContext[i], data[i] + pointer_position[i] + sizeof(int), temp_size + 16, serverCtx->client_num, serverCtx->topK, serverCtx->compression, i,segment_size - 16);
				pointer_position[i] += temp_size + sizeof(int) + 16;
				if( pointer_position[i] == data_size)
					stop_flag = true;
			}
			if (stop_flag)
				break;
#if defined COMPRESSION_DEBUG
			printf( "**COMPRESSION_DEBUG!!**pointer_position:%d\n", pointer_position[client_num-1]);
#endif
		}
#if defined COMPRESSION_DEBUG
		printf( "**COMPRESSION_DEBUG!!**out of the loop!\n");
#endif

	}

	else {    //for non-compressed data
		for ( int l = 0; l < segment_num; l ++) {
			temp_size = segment_size < size_left? segment_size:size_left;
			//printf( "\n%d\ttemp_size:%d\n", l, temp_size);
			for (int i = 0; i < serverCtx->client_num; i ++) {
#if defined COMPRESSION_DEBUG
				printf( "**COMPRESSION_DEBUG!!**before the first BC_wraper!!!\n");
#endif
				updateBC_wraper(serverCtx->eid,  serverCtx->enclaveContext[i], data[i] + segment_size * l, temp_size, serverCtx->client_num, serverCtx->topK, serverCtx->compression, i,temp_size);

				//printf("%dth done!\n", i);
			}
			size_left -= temp_size;
		}//this loop done, TDT should be done
	}

#if defined FUNCTION_LEVEL_PROFILE
	duration.enclave_cal_TDT = std::chrono::duration_cast<std::chrono::duration<double>>(std::chrono::high_resolution_clock::now() - start);
#endif

	//update_index(eid, 10, 0);
#if defined FUNCTION_LEVEL_PROFILE	
	start = std::chrono::high_resolution_clock::now();
#endif	
	result_encryption(serverCtx->eid, (char *)result, size_result*serverCtx->client_num, serverCtx->enclaveContext, serverCtx->client_num*sizeof(sgx_ra_context_t), serverCtx->client_num, serverCtx->topK);
#if defined FUNCTION_LEVEL_PROFILE
	duration.enclave_encryption = std::chrono::duration_cast<std::chrono::duration<double>>(std::chrono::high_resolution_clock::now() - start);
#endif

	for (int i=0; i<serverCtx->client_num;i++)
	{
		S.Send(socket_client[i].socket_fd,(char *)&size_result, 4);
		S.Send(socket_client[i].socket_fd,(char *)result+i*size_result,size_result);


		if(serverCtx->request_summary) {
			int length = 0;
			char* summary;
			int pos = 0;
			int recvLength;
			while(true)
			{
				if (!length)
				{
					if(S.Recv(socket_client[i].socket_fd, (char*)&length,4)!=4) 
					{
						printf("SERVER: Recv Error! Error code: %i\n", GetLastError());
						return 0;
					}
					summary = new char[length];
				}
				else
				{
					while (pos < length)
					{
						recvLength = S.Recv(socket_client[i].socket_fd, summary+pos,length-pos);
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
				//write client summary to file 
				cout <<"SERVER: Received Summary From Client: [" <<serverCtx->username[socket_client[i].client_id] <<"]!" <<endl;
				int split_pos = 0;
				int compression_flag = *(int*)( summary + split_pos);
				split_pos += sizeof(int);
				int payload_size = *(int*)( summary + split_pos);
				split_pos += sizeof(int);
				int SNP_count = *(int*)( summary + split_pos);
				split_pos += sizeof(int);
				double load_data_time = *(double*)( summary + split_pos);
				split_pos += sizeof(double);
				double encryption_time = *(double*)( summary + split_pos);
				split_pos += sizeof(double);
				double wait_time = *(double*)( summary + split_pos);
				split_pos += sizeof(double);
				double decryption_time = *(double*)( summary + split_pos);
				split_pos += sizeof(double);


				//dumping result report file received from the client
				fstream fs;
				string filename(serverCtx->username[socket_client[i].client_id]);
				filename += ".txt";
				fs.open( serverCtx->resultFolder + filename, ofstream::out);
				fs << fixed << setprecision(9);
				fs << currentDateTime() <<endl;
				fs <<"compression_flag:\t\t\t" << compression_flag <<endl;
				fs <<"SSL_flag:\t\t\t\t\t" <<serverCtx->SSLenable <<endl;
				fs <<"payload_size:\t\t"  << payload_size <<endl;
				fs <<"result_size:\t\t" << size_result <<endl;
				fs <<"total_SNP_count:\t" <<SNP_count <<endl;
				fs <<"segment_length:\t\t" <<serverCtx->segment_length <<endl;
				fs <<"load_data_time:\t\t"  << load_data_time<<endl;
				fs <<"encryption_time:\t" << encryption_time <<endl;
				fs <<"wait_time:\t\t\t" << wait_time <<endl;
				fs <<"decryption_time:\t"<< decryption_time << endl <<endl <<endl;
				fs <<"\nRESULTS:\n";
				fs << setw(4)  <<"CHR";
	fs << setw(13) <<"SNP";
	fs << setw(12) <<"BP";
	fs << setw(4)  <<"A1";
	fs << setw(4)  <<"A2";
	fs << setw(4)  <<"T";
	fs << setw(4)  <<"U";
	fs << setw(15) <<"OR";
	fs << setw(15)  <<"CHISQ";
	fs << setw(15) <<"P" <<endl;
#define SNPs_IDS_MAX_LEN 20
				for (int k = 0; k < serverCtx->topK; k ++) {
					//fs <<setw(5) << k+1;
					
					
					
					
					TDT_OUTPUT_TYPE tdt = *((TDT_OUTPUT_TYPE*)(summary  + split_pos + SNPs_IDS_MAX_LEN  
						+ k * (SNPs_IDS_MAX_LEN + sizeof(TDT_OUTPUT_TYPE) + 2 + 2*sizeof(TDT_INPUT_TYPE) + 2*sizeof(double) + 3*sizeof(int))));
					char A1_label = *( summary  + split_pos + SNPs_IDS_MAX_LEN + sizeof(TDT_OUTPUT_TYPE)
						+ k * (SNPs_IDS_MAX_LEN + sizeof(TDT_OUTPUT_TYPE) + 2 + 2*sizeof(TDT_INPUT_TYPE) + 2*sizeof(double) + 3*sizeof(int)));
					char A2_label = *( summary  + split_pos + SNPs_IDS_MAX_LEN + sizeof(TDT_OUTPUT_TYPE) + 1
						+ k * (SNPs_IDS_MAX_LEN + sizeof(TDT_OUTPUT_TYPE) + 2 + 2*sizeof(TDT_INPUT_TYPE) + 2*sizeof(double) + 3*sizeof(int)));
					
					TDT_INPUT_TYPE T = *((TDT_INPUT_TYPE*)( summary  + split_pos + SNPs_IDS_MAX_LEN + sizeof(TDT_OUTPUT_TYPE) + 2
						+ k * (SNPs_IDS_MAX_LEN + sizeof(TDT_OUTPUT_TYPE) + 2 + 2*sizeof(TDT_INPUT_TYPE) + 2*sizeof(double) + 3*sizeof(int))));
					TDT_INPUT_TYPE U = *((TDT_INPUT_TYPE*)( summary  + split_pos + SNPs_IDS_MAX_LEN + sizeof(TDT_OUTPUT_TYPE) + 2 + sizeof(TDT_INPUT_TYPE)
						+ k * (SNPs_IDS_MAX_LEN + sizeof(TDT_OUTPUT_TYPE) + 2 + 2*sizeof(TDT_INPUT_TYPE) + 2*sizeof(double) + 3*sizeof(int))));
					double maf = *((double*)( summary  + split_pos + SNPs_IDS_MAX_LEN + sizeof(TDT_OUTPUT_TYPE) + 2 + 2*sizeof(TDT_INPUT_TYPE)
						+ k * (SNPs_IDS_MAX_LEN + sizeof(TDT_OUTPUT_TYPE) + 2 + 2*sizeof(TDT_INPUT_TYPE) + 2*sizeof(double) + 3*sizeof(int))));
					int total_count = *((int*)(summary  + split_pos + SNPs_IDS_MAX_LEN + sizeof(TDT_OUTPUT_TYPE) + 2 + 2*sizeof(TDT_INPUT_TYPE) + sizeof(double)
						+ k * (SNPs_IDS_MAX_LEN + sizeof(TDT_OUTPUT_TYPE) + 2 + 2*sizeof(TDT_INPUT_TYPE) + 2*sizeof(double) + 3*sizeof(int))));
					double p_value = *((double*)( summary  + split_pos + SNPs_IDS_MAX_LEN + sizeof(TDT_OUTPUT_TYPE) + 2 + 2*sizeof(TDT_INPUT_TYPE) + sizeof(double) + sizeof(int)
						+ k * (SNPs_IDS_MAX_LEN + sizeof(TDT_OUTPUT_TYPE) + 2 + 2*sizeof(TDT_INPUT_TYPE) + 2*sizeof(double) + 3*sizeof(int))));
					
					int CHR = *((int*)(summary  + split_pos + SNPs_IDS_MAX_LEN + sizeof(TDT_OUTPUT_TYPE) + 2 + 2*sizeof(TDT_INPUT_TYPE) + sizeof(double) + sizeof(int) + sizeof(double)
						+ k * (SNPs_IDS_MAX_LEN + sizeof(TDT_OUTPUT_TYPE) + 2 + 2*sizeof(TDT_INPUT_TYPE) + 2*sizeof(double) + 3*sizeof(int))));
					int BP = *((int*)(summary  + split_pos + SNPs_IDS_MAX_LEN + sizeof(TDT_OUTPUT_TYPE) + 2 + 2*sizeof(TDT_INPUT_TYPE) + sizeof(double) + 2*sizeof(int) + sizeof(double)
						+ k * (SNPs_IDS_MAX_LEN + sizeof(TDT_OUTPUT_TYPE) + 2 + 2*sizeof(TDT_INPUT_TYPE) + 2*sizeof(double) + 3*sizeof(int))));
					
					fs <<setw(4) <<CHR;
					fs <<setw(13)<< summary + split_pos + 
						  k * ( SNPs_IDS_MAX_LEN + sizeof(TDT_OUTPUT_TYPE) + 2 + 2*sizeof(TDT_INPUT_TYPE) + 2*sizeof(double) + 3*sizeof(int));
					fs <<setw(12) <<BP <<setw(4) <<A1_label <<setw(4) <<A2_label <<setw(4) <<T <<setw(4) <<U;
					fs <<setw(15) <<(double)T/(double)U <<setw(15) <<tdt <<setw(15) <<p_value <<endl;
					//fs <<setw(15) <<tdt <<setw(4) <<A1_label <<setw(4) <<A2_label <<setw(4) <<T <<setw(4) <<U;
					//fs <<setw(15) <<maf <<setw(10) <<total_count <<setw(15) <<p_value <<endl;
				}
				fs.close();

#ifdef MATLAB_READABLE_FILE
				fstream mfs;
				string matlab_readable_file(serverCtx->username[socket_client[i].client_id]);
				matlab_readable_file += "_matlab.txt";
				mfs.open( serverCtx->resultFolder + matlab_readable_file, ofstream::out);
				mfs << fixed << setprecision(9);
				mfs <<compression_flag <<endl;
				mfs << serverCtx->SSLenable <<endl;
				mfs << payload_size <<endl;
				mfs << size_result <<endl;
				mfs << SNP_count <<endl;
				mfs << serverCtx->segment_length <<endl;
				mfs << load_data_time <<endl;
				mfs << encryption_time <<endl;
				mfs << wait_time <<endl;
				mfs << decryption_time <<endl;
				mfs.close();
#endif
				delete summary;

			}
		}	
	}


	for (int i=0; i<serverCtx->client_num;i++)
	{
		S.Close(socket_client[i].socket_fd);
	}

	freeBC(serverCtx->eid);
	sgx_destroy_enclave(serverCtx->eid);
	priority_queue<int, vector<int>, compare> temp_queue;
#if defined FUNCTION_LEVEL_PROFILE
	printf("\n*********************************************************************************************\n");
	printf("Time Cost Summary:\n");
	cout <<fixed <<setprecision(9);
	cout << "Client_Num:\t\t\t\t" << serverCtx->client_num <<endl;
	cout << "Segment_Length:\t\t\t\t" << serverCtx->segment_length <<endl;
	cout << "Compression_Flag:\t\t\t" << serverCtx->compression <<endl;
	cout << "SSL_Flag:\t\t\t\t" << serverCtx->SSLenable <<endl <<endl;
	cout << "\ncreate enclave:\t\t" << duration.create_enclave.count() <<endl;
	cout << "\n = = = = = = = = = = = = = = = = = = = \n";
	//print the result in client_id ascending order
	for ( int i = 0; i < serverCtx->client_num; i ++) {
		temp_queue.push(socket_client[i].client_id);
	}
	for ( int i = 0; i < serverCtx->client_num; i ++) {
		cout << "With Client: [" << serverCtx->username[temp_queue.top()] <<"]" <<endl;
		cout << "Attestation:\t\t" << duration.attestation[temp_queue.top()].count() <<endl;
		cout << "Recive Data:\t\t" << duration.receive_msg4[temp_queue.top()].count() <<endl;
		cout << "Verify Attestation:\t" << duration.verify_attstation[temp_queue.top()].count() <<endl <<endl;
		temp_queue.pop();
	}
	cout << "= = = = = = = = = = = = = = = = = = = = \n";
	cout << "Calculate TDT:\t\t" << duration.enclave_cal_TDT.count() << endl;
	cout << "Result Encryption:\t" << duration.enclave_encryption.count() <<endl;
	printf("\n*********************************************************************************************\n");
#endif



	//write server summary file
	fstream fs;
	fs.open( serverCtx->resultFolder + "server summary.txt", ofstream::app);
	fs << currentDateTime() <<endl;
	fs << fixed <<setprecision(9);
	fs << "Client_Num:\t\t\t\t\t" << serverCtx->client_num <<endl;
	fs << "Segment_Length:\t\t\t\t" << serverCtx->segment_length <<endl;
	fs << "Compression_Flag:\t\t\t" << serverCtx->compression <<endl;
	fs << "SSL_Flag:\t\t\t\t\t" << serverCtx->SSLenable <<endl <<endl;
	fs << "create enclave:\t\t" << duration.create_enclave.count() <<endl;
	fs << "= = = = = = = = = = = = = = = = = = = = \n";
	for ( int i = 0; i < serverCtx->client_num; i ++) {
		temp_queue.push(socket_client[i].client_id);
	}
	for ( int i = 0; i < serverCtx->client_num; i ++) {
		fs << "With Client: [" << serverCtx->username[temp_queue.top()] <<"]" <<endl;
		fs << "Attestation:\t\t" << duration.attestation[temp_queue.top()].count() <<endl;
		fs << "Recive Data:\t\t" << duration.receive_msg4[temp_queue.top()].count() <<endl;
		fs << "Verify Attestation:\t" << duration.verify_attstation[temp_queue.top()].count() <<endl <<endl;
		temp_queue.pop();
	}
	fs << "= = = = = = = = = = = = = = = = = = = = \n";
	fs << "Calculate TDT:\t\t" << duration.enclave_cal_TDT.count() << endl;
	fs << "Result Encryption:\t" << duration.enclave_encryption.count() <<endl <<endl <<endl;
	fs.close();

#ifdef MATLAB_READABLE_FILE
	fstream mfs;
	mfs.open( serverCtx->resultFolder + "server_summary_for_matlab.txt", ofstream::out);
	mfs << fixed <<setprecision(9);
	mfs << serverCtx->client_num <<endl;
	mfs << serverCtx->segment_length <<endl;
	mfs << serverCtx->compression <<endl;
	mfs << serverCtx->SSLenable <<endl <<endl;
	mfs << duration.create_enclave.count() <<endl;
	for ( int i = 0; i < serverCtx->client_num; i ++) {
		temp_queue.push(socket_client[i].client_id);
	}
	for ( int i = 0; i < serverCtx->client_num; i ++) {
		mfs << duration.attestation[temp_queue.top()].count() <<endl;
		mfs << duration.receive_msg4[temp_queue.top()].count() <<endl;
		mfs << duration.verify_attstation[temp_queue.top()].count() <<endl <<endl;
		temp_queue.pop();
	}
	mfs << duration.enclave_cal_TDT.count() << endl;
	mfs << duration.enclave_encryption.count();
	mfs.close();
#endif

	return 1;
}