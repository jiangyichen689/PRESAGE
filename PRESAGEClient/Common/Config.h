#pragma once

#include <iostream>
#include <fstream>
#include <string>
#include <map>  

//Also defined in the file "DataSealing.h"
typedef unsigned long long  MESSAGE_LENGTH_TYPE;
#define SEALING_BUFFER_SIZE 1024
#define SEALED_BUFFER_SIZE 1760
#define SECRET_MAC_SIZE 64
#define ENCRYPTED_ADD_SIZE 16
#define TRANSFERBOLCKS		5000
using namespace std; 

class Config
{
public:
	Config(void);
	~Config(void);

	void Trim(string& inout_s);  
	int Parse(char *filePath);
	string Read(string key);

private:
	map<std::string,std::string> contents;  //!< extracted keys and values
};

