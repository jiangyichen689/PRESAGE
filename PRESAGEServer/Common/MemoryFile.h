#ifndef MemoryFile_hpp
#define MemoryFile_hpp
#include "Common.h"
#include "Utils.h"
using namespace std;

class MemoryFile{
	public:
    MemoryFile(const char* file_name);
    char getCharAt(ssize_l_t pos);
    char getc();
	ssize_l_t mtell();
	ssize_l_t seek (ssize_l_t pos);
    ~MemoryFile();

private:
    char* mem_file;
    ssize_l_t curr_pos;
	ssize_l_t fsize;
    
public:
	static MemoryFile* Open (const char* file_name);
};

#endif /* MemoryFile_hpp */