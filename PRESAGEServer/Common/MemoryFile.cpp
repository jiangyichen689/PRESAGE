#include "MemoryFile.h"
#include <stdio.h>
#include <stdlib.h>

MemoryFile* MemoryFile::Open (const char* file_name)
{
	MemoryFile* mf = new MemoryFile(file_name);

	return mf;
}

MemoryFile::MemoryFile(const char* file_name){
    curr_pos = 0;
    FILE *f = fopen(file_name, "rb");
    fseek(f, 0, SEEK_END);
    fsize = ftell(f);
    fseek(f, 0, SEEK_SET);
        
    mem_file = (char *)malloc(fsize + 1);
    fread(mem_file, fsize, 1, f);
    fclose(f);
    
    mem_file[fsize] = 0;
}

char MemoryFile::getCharAt(ssize_l_t pos)
{
    return mem_file[pos];
}

char MemoryFile::getc(){
    char c = mem_file[curr_pos];
    
    if(c == 0){
        return EOF;
    }else{
        curr_pos++;
        return c;
    }
}

ssize_l_t MemoryFile::mtell()
{
	return curr_pos;
}

ssize_l_t MemoryFile::seek (ssize_l_t pos)
{
	if(pos < fsize){
		curr_pos = pos;
		return 0;
	}else{
		return -1;
	}
}

MemoryFile::~MemoryFile(){
    if(mem_file != NULL){
        free(mem_file);
    }
    
}