#ifndef _VCF_FILE
#define _VCF_FILE
#include<string>
#include<vector>
#include<stdint.h>

#include "perfectHash/cmph.h"

#define VCF_ELEM_STR_LEN 16

using namespace std;


typedef vector<uint64_t> DataVector;
typedef vector<DataVector> DataMatrix;
typedef vector<DataMatrix> DataFile;

/*typedef struct DataVectorStrElem { char x[15]; } DataVectorStrElem;

typedef vector<uint64_t> DataVectorInt;
typedef vector<DataVectorStrElem> DataVectorStr;*/

class VCFFile{
private:
	string file_name;
	string file_hash_table;
	string file_data_array;

	vector<string> files_name;
	vector<string> files_hash_table;
	vector<string> files_data_array;
public:
	VCFFile(std::string _file_name);
	~VCFFile();
	void packingData(CMPH_ALGO hash_method = CMPH_FCH);
	string getHashFile();
	string getDataFile();

	string getFileName(int ind);
	string getHashFile(int ind);
	string getDataFile(int ind);
	
	int getFilesNum();

private:
	int parseFileToColumns();
	void parse_line(string line, string &chromosomeNumber, string &position, int &reference, int &alternative, int &svType);
	void convert_char_to_int(int &result, std::string value);
	void file_parts_string_to_int(uint64_t &result, string input, int dataIndex);
	void construct_raw_data(ifstream & file, char** &data_str, uint64_t* &data_int, int num);
	bool write_hash_table(char** &data_str, uint64_t* &data_int, int num, CMPH_ALGO hash_method);
	bool write_hash_table1(char** &data_str, uint64_t* &data_int, int num, int table_size, CMPH_ALGO hash_method);
};
#endif