#include <fstream>
#include <iostream>
#include <ctime>
#include <chrono>
#include "VCFFile.h"
#include "Debug.h"

using namespace std;
using namespace std::chrono;

const int SHITF_BITS[5] = {0, 5, 35, 37, 39};

VCFFile::VCFFile(string _file_name)
{
	file_name = _file_name;
	
}

void VCFFile::packingData(CMPH_ALGO hash_method)
{
	int line_count = parseFileToColumns();
	char** data_str = new char*[line_count];
	char* data_str_buffer = new char[VCF_ELEM_STR_LEN * line_count];
	char* data_str_buffer_tmp = data_str_buffer;

	memset(data_str_buffer, '\0', VCF_ELEM_STR_LEN * line_count);

	for(int m = 0; m < line_count; m++)
	{
		data_str[m] = data_str_buffer_tmp;
		data_str_buffer_tmp += VCF_ELEM_STR_LEN;
	}
	uint64_t* data_int = new uint64_t[line_count];
	/*int batch_count = line_count / batch_len;
	if(0 != (line_count % batch_len))
	{
		batch_count++;
	}*/
	ifstream file;
	file.open("parsed_file.txt");
	if (!file.is_open())
	{
		std::cout << "Unable to open file: parsed_file.txt\n"<< endl;
	}
	else
	{
#ifdef PROFILE_TIME
		microseconds total_time =microseconds::zero();
		auto start = high_resolution_clock::now();
#endif
		construct_raw_data(file, data_str, data_int, line_count);
#ifdef PROFILE_TIME
		auto end = high_resolution_clock::now();
		total_time = duration_cast<microseconds>(end - start);
		cout << "Client coding time: " << total_time.count() << "microseconds";
		cout << endl << endl;
#endif

#ifdef PROFILE_TIME
		total_time =microseconds::zero();
		start = high_resolution_clock::now();
#endif
		write_hash_table1(data_str, data_int, line_count, 500, hash_method);
#ifdef PROFILE_TIME
		end = high_resolution_clock::now();
		total_time = duration_cast<microseconds>(end - start);
		cout << "Client build hash time: " << total_time.count() << "microseconds";
		cout << endl << endl;
#endif
	}
	file.close();
	remove("parsed_file.txt");
	delete[] data_str_buffer;
	delete[] data_str;
	delete[] data_int;
}

int VCFFile::parseFileToColumns()
{
	ifstream inputFile(file_name);
	if (!inputFile.is_open())
	{
		std::cout << "Unable to open file: " << file_name << "\nProgram terminating...\n";
		return 0;
	}

	ofstream outputFile;
	outputFile.open("parsed_file.txt");
	if (!outputFile.is_open())
	{
		std::cout << "Unable to create output file: " << "parsed_file.txt" << "\nProgram terminating...\n";
		return 0;
	}

	string line;
	string chromosomeNumber;
	string position;
	int reference;
	int alternative;
	int svType;
	int lineCount = 0;
	while (getline(inputFile, line))
	{
		if (line[0] != '#')
		{
			parse_line(line, chromosomeNumber, position, reference, alternative, svType);
			outputFile << chromosomeNumber << "\t" << position << " \t" << reference << "\t" << alternative << "\t" << svType << endl;
			lineCount++;
		}
	}

	inputFile.close();
	outputFile.close();
	return lineCount;
}

void VCFFile::parse_line(string line, string &chromosomeNumber, string &position, int &reference, int &alternative, int &svType)
{
	chromosomeNumber = "";
	position = "";

	int tabIndex[7]; // We know that there are 7 tabs in each line!
	tabIndex[0] = line.find('\t');
	for (int i = 1; i < 7; i++)
		tabIndex[i] = line.find('\t', tabIndex[i - 1] + 1);

	chromosomeNumber = line.substr(0, tabIndex[0]);
	position = line.substr(tabIndex[0] + 1, tabIndex[1] - tabIndex[0] - 1);
	// Skip ID column in between tab[1] and tab[2]
	string temp = line.substr(tabIndex[3] - 1, 1);	// Only the last character in reference
	convert_char_to_int(reference, temp);

	temp = line.substr(tabIndex[4] - 1, 1);	// Only the last character in alternative
	convert_char_to_int(alternative, temp);

	temp = line.substr(tabIndex[6] + 8, 3);		// SVTYPE=SNP or SVTYPE=*
	svType = (temp == "SNP") & 1;
}

void VCFFile::convert_char_to_int(int &result, string value)
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

VCFFile::~VCFFile()
{
}

void VCFFile::file_parts_string_to_int(uint64_t &result, string input, int dataIndex)
{
	if (dataIndex == 0)
	{
		// Chromosome Number {1, 2, ..., 22, X, Y}
		if (input == "X")
			result = 23;
		else if (input == "Y")
			result = 24;
		else
			result = atoi(input.c_str());
	}
	else
	{
		// Starting Position or SNP
		result = atoi(input.c_str());
	}
}

void VCFFile::construct_raw_data(ifstream & file, char** &data_str, uint64_t* &data_int, int num)
{
//#define DEBUG_RAW_DATA
#ifdef DEBUG_RAW_DATA
	int flag = 0;
	vector<uint64_t> tmp;
#endif
	uint64_t data_tmp;
	for(int elemIndex = 0; elemIndex < num; elemIndex++)
	{
		data_int[elemIndex] = 0;
		for(int dataIndex = 0; dataIndex < 5; dataIndex++)
		{
			string s;
			file >> s;
			file_parts_string_to_int(data_tmp, s, dataIndex);

#ifdef DEBUG_RAW_DATA
			if(data_tmp == 161276680){
				flag = 1;
			}

			if(flag){
				printf("state value = %llu\n", data_tmp);
				printf("sum value = %llu\n", data_int[elemIndex]);
			}
#endif
			data_int[elemIndex] += (data_tmp << SHITF_BITS[dataIndex]);
			
		}


		sprintf(data_str[elemIndex], "%llu\0", data_int[elemIndex]);
#ifdef DEBUG_RAW_DATA
		if(flag){
			flag = 0;
			tmp.push_back(data_int[elemIndex]);
		}
#endif
	}

#ifdef DEBUG_RAW_DATA
	for(int m = 0; m < tmp.size(); m++)
	{
		cout << "test value " << m << ":" <<tmp[m]<<endl;
	}
#endif
}

bool VCFFile::write_hash_table(char** &data_str, uint64_t* &data_int, int num, CMPH_ALGO hash_method)
{
	uint64_t *data_for_written = new uint64_t[num];

	file_hash_table = file_name + ".hash";
	file_data_array = file_name + ".data";

	FILE* hash_table_fd = fopen(file_hash_table.c_str(), "w");
	ofstream data_file_out(file_data_array, ios::out | ios::binary);

	cmph_io_adapter_t *source = cmph_io_vector_adapter(data_str, num);
	cmph_config_t *config = cmph_config_new(source);
	cmph_config_set_algo(config, hash_method);
	cmph_config_set_mphf_fd(config, hash_table_fd);
	cmph_t *hash = cmph_new(config);

	unsigned int i = 0;
	while (i < num) {
		const char *key = data_str[i];//vector[i];
		unsigned int id = cmph_search(hash, key, (cmph_uint32)strlen(key));
		data_for_written[id] = data_int[i];
		i++;
	}


	data_file_out.write((char *)data_for_written, sizeof(uint64_t) * num);

	cmph_config_destroy(config);
	cmph_dump(hash, hash_table_fd); 
	cmph_destroy(hash);

	data_file_out.close();
	fclose(hash_table_fd);
	

/*
#define HASH_SEARCH
#ifdef HASH_SEARCH
	FILE *mphf_fd1 = fopen(file_hash_table.c_str(), "r");
	char *key = "967233528065";
	cmph_t* hash0 = cmph_load(mphf_fd1);
	unsigned int id = cmph_search(hash0, key, (cmph_uint32)strlen(key));
	printf("Orignial value %s\n", key);
	printf("Id is %u\n",id);
	printf("Orignial value %s, searched value[%u]= %llu\n", key, id, data_for_written[id]);
	cmph_destroy(hash0);
	fclose(mphf_fd1);
#endif*/

	delete[] data_for_written;
	return true;
}

bool VCFFile::write_hash_table1(char** &data_str, uint64_t* &data_int, int num, int table_size, CMPH_ALGO hash_method)
{
	cout << "divided table size is " << table_size << endl;
	int table_num = (num + table_size - 1) / table_size;
	int* each_file_size = new int[table_num];
	for(int n = 0; n < table_num - 1; n++)
	{
		each_file_size[n] = table_size;
	}
	each_file_size[table_num - 1] = num - (table_num - 1)* table_size;

	char** data_str_tmp = data_str;

#ifdef PROFILE_TIME
	microseconds total_time(0);
#endif

	for(int m = 0; m < table_num; m++)
	{
		if(m == 115)
		{
			cout << ""<<endl;
		}
		uint64_t *data_for_written = new uint64_t[each_file_size[m]];

		string file_name_tmp = file_name + std::to_string(m);
		string file_hash_table_tmp = file_name_tmp + ".hash";
		string file_data_array_tmp = file_name_tmp + ".data";

		FILE* hash_table_fd = fopen(file_hash_table_tmp.c_str(), "w");
		ofstream data_file_out(file_data_array_tmp, ios::out | ios::binary);

		cmph_io_adapter_t *source = cmph_io_vector_adapter(data_str_tmp, each_file_size[m]);
		cmph_config_t *config = cmph_config_new(source);
		cmph_config_set_algo(config, hash_method);
		cmph_config_set_mphf_fd(config, hash_table_fd);
		cmph_t *hash = cmph_new(config);

#ifdef PROFILE_TIME
		auto start = high_resolution_clock::now();
#endif
		if(hash == NULL)
		{
			continue;
		}

		unsigned int i = 0;
		while (i < each_file_size[m]) {
			const char *key = data_str_tmp[i];//vector[i];
			unsigned int id = cmph_search(hash, key, (cmph_uint32)strlen(key));
			id = cmph_search(hash, key, (cmph_uint32)strlen(key));
			id = cmph_search(hash, key, (cmph_uint32)strlen(key));
			if(id < each_file_size[m])
			{
				data_for_written[id] = data_int[i];
			}else
			{
				cout << "The excpetional id = " << id << endl << endl;
			}
						if(id < each_file_size[m])
			{
				data_for_written[id] = data_int[i];
			}else
			{
				cout << "The excpetional id = " << id << endl << endl;
			}
						if(id < each_file_size[m])
			{
				data_for_written[id] = data_int[i];
			}else
			{
				cout << "The excpetional id = " << id << endl << endl;
			}
			i++;
		}
#ifdef PROFILE_TIME
		auto end = high_resolution_clock::now();
		total_time += duration_cast<microseconds>(end - start);
#endif


		data_file_out.write((char *)data_for_written, sizeof(uint64_t) *each_file_size[m]);

		cmph_config_destroy(config);
		cmph_dump(hash, hash_table_fd); 
		cmph_destroy(hash);

		data_file_out.close();
		fclose(hash_table_fd);

		delete[] data_for_written;

		data_str_tmp += each_file_size[m];
		files_name.push_back(file_name_tmp);
		files_hash_table.push_back(file_hash_table_tmp);
		files_data_array.push_back(file_data_array_tmp);
	}

#ifdef PROFILE_TIME
	cout << "Total running time is : " << total_time.count() << "microseconds";
	cout << endl << endl;
#endif

	delete[] each_file_size;

	return true;
}



string VCFFile::getHashFile()
{
	return file_hash_table;
}

string VCFFile::getDataFile()
{
	return file_data_array;
}

string VCFFile::getHashFile(int ind)
{
	return files_hash_table[ind];
}

string VCFFile::getDataFile(int ind)
{
	return files_data_array[ind];
}

string VCFFile::getFileName(int ind)
{
	return files_name[ind];
}

int VCFFile::getFilesNum()
{
	return files_data_array.size();
}