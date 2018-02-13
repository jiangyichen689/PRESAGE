#include <iostream>
#include <fstream>
#include <string>
//#include <ctime>

#include <stdio.h>
#include <stdlib.h>
#include <cmath>
#include <fcntl.h>
#include <io.h>
#include <sys/types.h>
#include "mman.h"
#include <sys/stat.h>
#include <errno.h>
#include <vector>

#include "stdafx.h"

#include "EnclaveEM.h"

#include "../Common/Config.h"
#include "../Common/FileIO.h"

#define SNPs_IDS_MAX_LEN 20
using namespace std;

extern int data_encryption( char* data, int data_size, char* data_encrypted);

int count_lines(char *filename){
	struct stat sb;
	long cntr = 0;
	int fd;
	char *data;

	// map the file
	fd = _open(filename, O_RDONLY);
	//printf( "%d", fd);
	if ( fd == -1) {
		printf( "File Doesn't exist!\n");
		exit (-1);
	}
	fstat(fd, &sb);

	data = (char *)mmap((void *)0, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);

	int counter = 0;
	for (int i =0; i <sb.st_size; i++){
		if(*(data+i) == '\n')
		{
			counter++;
		}
	}
	return counter;
}


char** allocate2DChar(int rows, int cols){
	char** ret = (char**)calloc(rows, sizeof(char*));
	for(int i = 0; i < rows; i++){
		ret[i] = (char*) calloc(cols, sizeof(char));
	}

	return ret;
}


bool readIntArrFromString(string str, string delimiter, vector<EM_PARA_TYPE>& int_vec)
{
	string::size_type lastPos = str.find_first_not_of(delimiter, 0);
	string::size_type pos     = str.find_first_of(delimiter, lastPos);
	while (string::npos != pos || string::npos != lastPos)
	{
		int_vec.push_back((EM_PARA_TYPE)stoi(str.substr(lastPos, pos - lastPos)));
		lastPos = str.find_first_not_of(delimiter, pos);
		pos = str.find_first_of(delimiter, lastPos);
	}

	return true;
}

int readIntArrFromString(string str, string delimiter, EM_PARA_TYPE* int_vec)
{
	int cnt = 0;
	string::size_type lastPos = str.find_first_not_of(delimiter, 0);
	string::size_type pos     = str.find_first_of(delimiter, lastPos);
	while (string::npos != pos || string::npos != lastPos){
		*int_vec++ = (EM_PARA_TYPE)stoi(str.substr(lastPos, pos - lastPos));
		cnt++;
		lastPos = str.find_first_not_of(delimiter, pos);
		pos = str.find_first_of(delimiter, lastPos);
	}

	return cnt;
}

int readDoubleArrFromString(string str, string delimiter, EM_DATA_TYPE* arr, const int L_NUM){
	int cnt = 0;
	string::size_type lastPos = str.find_first_not_of(delimiter, 0);
	string::size_type pos     = str.find_first_of(delimiter, lastPos);
	while ((cnt++ < L_NUM) &&(string::npos != pos || string::npos != lastPos)){
		*arr++ = (EM_DATA_TYPE)stod(str.substr(lastPos, pos - lastPos));
		lastPos = str.find_first_not_of(delimiter, pos);
		pos = str.find_first_of(delimiter, lastPos);
	}

	return true;
}

bool loadData(vector<string>& data_file_names, EM_PARA_TYPE* data){
	EM_PARA_TYPE* data_tmp = data;
	string line;
	for(int i = 0; i < data_file_names.size(); i++)
	{
		ifstream file1(data_file_names[i]);	
		if(file1.is_open())
		{
			while(getline(file1,line))
			{
				int cnt = readIntArrFromString(line, ",", data_tmp);
				data_tmp += cnt;
			}
		}
		else
		{
			cout << "Unable to open file" << endl;
			return false;
		}
		file1.close();
	}

	return true;
}

bool loadData(string fileName, char* data)
{
	MESSAGE_LENGTH_TYPE pos = 0;

	File* deezFile = File::Open(fileName,"rb");

	if (deezFile == NULL)
	{
		cout<<"Could not open the file"<<fileName<<endl;
		exit(1);
	}

	MESSAGE_LENGTH_TYPE fileSize = deezFile->size();
	deezFile->read(data, fileSize, 0);
}

MESSAGE_LENGTH_TYPE CutAndEncrypt(char * inputFileName, char * storeFileName)
{
	MESSAGE_LENGTH_TYPE pos = 0;
	MESSAGE_LENGTH_TYPE temp_size;
	char* storeData = new char[SEALING_BUFFER_SIZE];
	char* encryptedData = new char[SEALING_BUFFER_SIZE + ENCRYPTED_ADD_SIZE];
	File* deezFile = File::Open(inputFileName,"rb");

	if (deezFile == NULL)
	{
		cout<<"Could not open the file"<<inputFileName<<endl;
		exit(1);
	}

	MESSAGE_LENGTH_TYPE deezFileSize = deezFile->size();
	cout<<"The size of deez file "<<inputFileName<<" is : "<<deezFileSize<<endl;

	File* storeFile = File::Open(storeFileName, "wb");

	while (pos != deezFileSize)
	{
		temp_size = SEALING_BUFFER_SIZE < (deezFileSize-pos)? SEALING_BUFFER_SIZE:(deezFileSize - pos);
		deezFile->read(storeData, temp_size, pos);
		data_encryption((char*)storeData, temp_size, encryptedData);
		storeFile->write(encryptedData, temp_size  + ENCRYPTED_ADD_SIZE);
		pos += temp_size;
	}

	delete[] storeData;
	delete[] encryptedData;

	deezFile->close();
	storeFile->close();

	return deezFileSize;
}


MESSAGE_LENGTH_TYPE getFileSize(char * inputFileName)
{
	File* deezFile = File::Open(inputFileName,"rb");

	if (deezFile == NULL)
	{
		cout<<"Could not open the file"<<inputFileName<<endl;
		exit(1);
	}

	MESSAGE_LENGTH_TYPE deezFileSize = deezFile->size();

	deezFile->close();

	return deezFileSize;
}

MESSAGE_LENGTH_TYPE getEncryptedLength(char * inputFileName)
{
	MESSAGE_LENGTH_TYPE pos = 0;
	MESSAGE_LENGTH_TYPE length = 0;

	MESSAGE_LENGTH_TYPE deezFileSize = getFileSize(inputFileName);

	MESSAGE_LENGTH_TYPE segmentNum = (MESSAGE_LENGTH_TYPE)ceil(((double)deezFileSize) / SEALING_BUFFER_SIZE);

	length = segmentNum * ENCRYPTED_ADD_SIZE + deezFileSize;

	return length;
}

MESSAGE_LENGTH_TYPE paraEncryptedAndCombine(MESSAGE_LENGTH_TYPE data, char** ptr, MESSAGE_LENGTH_TYPE length)
{
	const int RAW_DATA_LENGTH = sizeof(MESSAGE_LENGTH_TYPE);
	const int ENCRYPTED_DATA_LENGTH = RAW_DATA_LENGTH + ENCRYPTED_ADD_SIZE;
	const int TOTAL_LENGTH = ENCRYPTED_DATA_LENGTH + length;

	char storeCharArray[RAW_DATA_LENGTH];
	char encryptedSize[ENCRYPTED_DATA_LENGTH];

	//Transfer the data as the form of char array;
	memcpy(storeCharArray, &data, RAW_DATA_LENGTH);
	data_encryption(storeCharArray, RAW_DATA_LENGTH, encryptedSize);

	char* buffer = new char[TOTAL_LENGTH];

	memmove(buffer, *ptr, length);
	memmove(buffer+length, encryptedSize, ENCRYPTED_DATA_LENGTH);


	char* ptrTemp = *ptr;
	*ptr = buffer;

	delete[] ptrTemp;

	return TOTAL_LENGTH;
}

MESSAGE_LENGTH_TYPE fileEncryptedAndCombine(char* fileName, char** ptr, MESSAGE_LENGTH_TYPE length)
{
	char* storeFilePath = new char[strlen(fileName) + 5];
	memmove(storeFilePath, fileName, strlen(fileName));
	memmove(storeFilePath + strlen(fileName), ".tmp", strlen(fileName) + 1);
	
	MESSAGE_LENGTH_TYPE fileSize = CutAndEncrypt(fileName, storeFilePath);

	MESSAGE_LENGTH_TYPE storeFileSize = getFileSize(storeFilePath);
	cout<<fileName<<"Encrypted File Size :"<<getFileSize(storeFilePath)<<endl;

	MESSAGE_LENGTH_TYPE totalLength = storeFileSize + length;

	char* storeFileBuffer = new char[storeFileSize];
	char* allDataBuffer = new char[totalLength];

	loadData(storeFilePath, storeFileBuffer);

	memmove(allDataBuffer, *ptr, length);
	memmove(allDataBuffer+length, storeFileBuffer, storeFileSize);

	delete[] storeFileBuffer;

	char* ptrTemp = *ptr;
	*ptr = allDataBuffer;
	delete[] ptrTemp;
	delete[] storeFilePath;
	
	return totalLength;
}

MESSAGE_LENGTH_TYPE encFile4Sending(char* fileName, char** ptr, MESSAGE_LENGTH_TYPE length)
{
	char* storeFilePath = "temp.dz";
	
	MESSAGE_LENGTH_TYPE fileSize = CutAndEncrypt(fileName, storeFilePath);

	MESSAGE_LENGTH_TYPE storeFileSize = getFileSize(storeFilePath);
	cout<<fileName<<"Encrypted File Size :"<<getFileSize(storeFilePath)<<endl;

	MESSAGE_LENGTH_TYPE totalLength = storeFileSize + length;
	//totalLength = paraEncryptedAndCombine(fileSize, ptr, totalLength);

	char* storeFileBuffer = new char[storeFileSize];
	char* allDataBuffer = new char[totalLength];

	loadData(storeFilePath, storeFileBuffer);

	memmove(allDataBuffer, *ptr, length);
	memmove(allDataBuffer+length, storeFileBuffer, storeFileSize);

	//memmove(allDataBuffer, storeFileBuffer, storeFileSize);
	//memmove(allDataBuffer+storeFileSize, *ptr, length);

	delete[] storeFileBuffer;

	char* ptrTemp = *ptr;
	*ptr = allDataBuffer;
	delete[] ptrTemp;

	//Assemble the filesize and the encrypted file size;
	//totalLength = paraEncryptedAndCombine(storeFileSize, ptr, totalLength);
	
	return totalLength;
}
