#ifndef Reference_H
#define Reference_H

#include <map>
#include <string>
#include <vector>
#include <stdio.h>
#include <string.h>

#include "Common.h"
#ifdef NON_SGX
#include "FileIO.h"
#include "MemoryFile.h"
#endif
//#include "Fields/SAMComment.h"

class Stats;

class Reference {
	friend class Stats;

public:
	struct Chromosome {
		std::string chr;
		std::string md5;
		std::string filename;
		size_t len;
		size_t loc;
	};

private:
#ifdef NON_SGX
	//File* input;
	MemoryFile* input;
#endif
	std::string directory, filename;
	std::string currentChr;
	//std::unordered_map<std::string, Chromosome> chromosomes;
	std::map<std::string, Chromosome> chromosomes;
	std::string currentWebFile;

private:
	std::string buffer;
	size_t bufferStart, bufferEnd, currentPos;
	char c;
	
public:
	Reference (const std::string &filename);
	~Reference (void);

public:
	std::string getChromosomeName(void) const;
	std::string scanChromosome(const std::string &s); //, const SAMComment &samComment);
	//void load(char *arr, size_t s, size_t e);
	size_t getChromosomeLength(const std::string &s) const;

	Chromosome getChromosomeInfo (const std::string &chr) {
		return chromosomes[chr];
	}


	void loadIntoBuffer(size_t end);
	//char operator[](size_t pos) const;
	char getCharAt(size_t pos) const;
	std::string copy(size_t start, size_t end);
	void trim(size_t from);
	void reset();

	/*size_t currentMemoryUsage() {
		size_t sz = 0;
			//sizeInMemory(directory) + sizeInMemory(filename) + sizeInMemory(currentWebFile) +
			//sizeInMemory(currentChr) + sizeof(size_t) * 3 + sizeInMemory(buffer);
		return sz; // Ignore chromosome size
	}*/


private:
	void loadFromFASTA (const std::string &fn);

};

#endif
