#pragma once

#include <stdint.h>
#include <vector>
#include <memory>

#define GENOME_FILE_NAME_MAX 256
#define GENOME_ID_MAX_LEN 10
#define GENOME_NUM_MAX_LEN 4

#define GENOME_FILE_UPLOADING 0
#define GENOME_FILE_QUERY 1
#define QUERY_COMMAND_PARAS 4

using namespace std;


class ClientDataManagement{
public:
	ClientDataManagement(void);
	~ClientDataManagement(void);

	bool Parse(uint8_t *file_path);
	int getNumOfUploadingFiles();
	int getNumOfQuery();

	string getUploadingFileAt(int num);
	string getQueryAt(int num);
	vector<uint64_t> getPackedQueryAt(int num);

	void trim(string& inout_s);
	void printAllUploadingFilesAndQueries();

	void getFileList(std::string folder, std::string ext, std::vector<std::string> &file_list);

private:
	vector<string> uploading_files;
	vector<string> query_GDOS;
	vector<vector<uint64_t>> query4hash;
	string processQuery(string line);
	bool processQuery(string line, vector<uint64_t> &queries);
	void query_parts_string_to_int(uint64_t &result, string input, int dataIndex);
	void convert_char_to_int(int &result, string value);
};