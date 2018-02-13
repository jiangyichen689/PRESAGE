#include "ClientDataManagement.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <Windows.h>
#include <map>

#include "Utils.h"

#define VCF_ELEM_STR_LEN 16

const int SHITF_BITS[5] = {0, 5, 35, 37, 39};


std::wstring s2ws(const std::string& s)
{
    int len;
    int slength = (int)s.length() + 1;
    len = MultiByteToWideChar(CP_ACP, 0, s.c_str(), slength, 0, 0); 
    wchar_t* buf = new wchar_t[len];
    MultiByteToWideChar(CP_ACP, 0, s.c_str(), slength, buf, len);
    std::wstring r(buf);
    delete[] buf;
    return r;
}

ClientDataManagement::ClientDataManagement(void)
{
}

ClientDataManagement::~ClientDataManagement(void)
{
}

void ClientDataManagement::trim( string& inout_s )
{
	// Remove leading and trailing whitespace  
	static const char whitespace[] = " \n\t\v\r\f";  
	inout_s.erase( 0, inout_s.find_first_not_of(whitespace) );  
	inout_s.erase( inout_s.find_last_not_of(whitespace) + 1U ); 
}

bool ClientDataManagement::Parse(uint8_t* file_path)
{
	ifstream in;
	in.open((char*)file_path, ios::in);

	if(!in) 
	{
		printf("Uploading and query files not found\n");
		return false;
	}

	char delim[]  = " \n\t\v\r\f";  // separator  
	const string comm   = "#";    // comment  
	string line = "";  // might need to read ahead to see where value ends  

	while(getline(in, line, '\n')){
		// Ignore comments  
        line = line.substr( 0, line.find(comm));
		trim(line);

		if( line == "") continue;

		int choice = atoi(line.c_str());

		if(GENOME_FILE_UPLOADING != choice && GENOME_FILE_QUERY != choice){
			uploading_files.clear();
			query_GDOS.clear();
			return false;
		}

		if(!getline(in, line, '\n')){
			return false;
		}

		line = line.substr( 0, line.find(comm));
		trim(line);

		if( line == "") return false;

		if(GENOME_FILE_UPLOADING == choice){
			getFileList(line, ".vcf", uploading_files);
		}else{
			query_GDOS.push_back(line);
			vector<uint64_t> tmp_vec;
			processQuery(line, tmp_vec);
			query4hash.push_back(tmp_vec);
		}
	}

	in.close();

	return true;
}

int ClientDataManagement::getNumOfUploadingFiles(){
	return this->uploading_files.size();
}

int ClientDataManagement::getNumOfQuery(){
	return this->query_GDOS.size();
}

void ClientDataManagement::printAllUploadingFilesAndQueries(){
	cout << "The number of uploading files is " << this->getNumOfUploadingFiles()<<"."<<endl;
	for (std::vector<string>::iterator it = uploading_files.begin() ; it != uploading_files.end(); ++it){
		cout << *it << endl;
	}
	cout << "The number of query files is " << this->getNumOfQuery()<<"."<<endl;
	for (std::vector<string>::iterator it = query_GDOS.begin() ; it != query_GDOS.end(); ++it){
		cout << *it << endl;
	}
}

string ClientDataManagement::getUploadingFileAt(int num){
	return uploading_files.at(num);
};

string ClientDataManagement::getQueryAt(int num){
	return query_GDOS.at(num);
};

void ClientDataManagement::getFileList(std::string folder, std::string ext, std::vector<std::string> &file_list){
	HANDLE hFind;
	WIN32_FIND_DATA data;

	hFind = FindFirstFile(s2ws(folder + "/*").c_str(), &data);
	
	if(hFind != INVALID_HANDLE_VALUE){
		do {
			wstring tmp0 = data.cFileName;
			std::string tmp1(tmp0.begin(), tmp0.end());

			if(tmp1.find(ext, (tmp1.length() - ext.length())) !=  std::string::npos){
                file_list.push_back(folder+"\\"+tmp1);
            }
		}while(FindNextFile(hFind, &data));
	}

	FindClose(hFind);
}


bool ClientDataManagement::processQuery(string line, vector<uint64_t> &queries)
{
	vector<string> strs = split(line, '-');

	if(strs.size() != QUERY_COMMAND_PARAS + 1)
	{
		return false;
	}

	map<char, string> tmp_command_keys;

	if(!strs[0].compare("query") && !strs[0].compare("multiquery"))
	{
		return false;
	}

	vector<string> query_elem[QUERY_COMMAND_PARAS];

	for(auto it = strs.begin()+1; it != strs.end(); it++)
	{
		vector<string> strs = split(*it, ' ');
		if(strs.size() != 2)
		{
			return false;
		}else{
			trim(strs[0]);
			trim(strs[1]);
			tmp_command_keys[strs[0][0]] = strs[1];
		}
	}

	for(auto const& enc : tmp_command_keys)
	{
		switch(enc.first)
		{
		case 'c':
			query_elem[0] = split(enc.second, ',');
			break;
		case 'p':
			query_elem[1] = split(enc.second, ',');
			break;
		case 'r':
			query_elem[2] = split(enc.second, ',');
			break;
		case 'a':
			query_elem[3] = split(enc.second, ',');
			break;
		//case 'f':
			//break;
		default:
			return false;
		}
	}

	for(int n = 0; n < query_elem[0].size(); n++)
	{
		uint64_t tmp_sum = 0;
		uint64_t tmp_elem;
		
		for(int m = 0; m < 4; m++)
		{
			query_parts_string_to_int(tmp_elem, query_elem[m][n], m);
			tmp_sum += (tmp_elem << SHITF_BITS[m]);
		}
		tmp_elem = 1;
		tmp_sum += (tmp_elem<< SHITF_BITS[4]);
		queries.push_back(tmp_sum);
	}

	return true;
}

void ClientDataManagement::query_parts_string_to_int(uint64_t &result, string input, int dataIndex)
{
	int result0;
	    if (dataIndex == 2 || dataIndex == 3)
    {
        // Reference or Alternative {A, C, G, T}
        convert_char_to_int(result0, input);
    }
    else if (dataIndex == 0)
    {
        // Chromosome Number {1, 2, ..., 22, X, Y}
        if (input == "X")
            result0 = 23;
        else if (input == "Y")
            result0 = 24;
        else
            result0 = atoi(input.c_str());
    }
    else
    {
        // Starting Position or SNP
        result0 = atoi(input.c_str());
    }

	result = result0;
}

void ClientDataManagement::convert_char_to_int(int &result, string value)
{
	if (value == "C")
		result = 1;
	else if (value == "G")
		result = 2;
	else if (value == "T")
		result = 3;
	else
		// A or other
		result = 0;
}

vector<uint64_t> ClientDataManagement::getPackedQueryAt(int num)
{
	return query4hash[num];
}