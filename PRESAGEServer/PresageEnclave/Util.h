#ifndef _PRESAGE_ENCLAVE_UTIL
#define _PRESAGE_ENCLAVE_UTIL
#include<vector>

#define DEBUGP printf

typedef struct
{
	char *mem_ptr;
	int len;
	int current_pos;
}Memory_IO;

void printf(const char *fmt, ...);
void sprintf(char* buf, const char *fmt, ...);

size_t mread(void* ptr, size_t size, size_t count, Memory_IO *mem);

void cal_level_num(int num, int level_num, std::vector<int>  &vec);
#endif