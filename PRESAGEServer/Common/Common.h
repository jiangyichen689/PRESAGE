#ifndef Common_H
#define Common_H


#include <stdio.h>
#include <string>
#include <stdint.h>
#include <stdlib.h>
#include <stdarg.h> 

#include <map>
//#include <thread>
//#include <mutex>
//#include <memory>
//#include <sstream>
#include <vector>
#include <assert.h>
#include "Array.h"

//#include "Fields/SAMComment.h"
//#include "Streams/Stream.h"

extern bool optStdout;
extern int  optThreads;
extern int  optLogLevel;

extern bool optReadLossy;	
extern bool optBzip;

//void inttostr (int64_t k, FILE *f);
void inttostr (int64_t k, std::string &r);
using namespace std;
std::string xtoa (int64_t k);

char getDNAValue (char ch);

void addEncoded (size_t n, Array<uint8_t> &o, uint8_t offset = 0);
ssize_l_t getEncoded (uint8_t *&len, uint8_t offset = 0);
int packInteger(uint64_t num, Array<uint8_t> &o);
uint64_t unpackInteger(int T, Array<uint8_t> &i, size_t &ii) ;
int vasprintf(char **strp, const char *fmt, va_list ap);


#define CHROM_UPDATE(f, _chr, _md5, _filename, _len, _loc) {\
	f.chr = _chr;\
	f.md5 = _md5;\
	f.filename = _filename;\
	f.len = _len;\
	f.loc = _loc;}

std::string S (const char* fmt, ...);
void initCache();


class DZException: public std::exception {
protected:
	char msg[256];

public:
	DZException (void) {}
	DZException (const char *fmt, ...) {
		char *ptr = 0;
		va_list args;
		va_start(args, fmt);
		vasprintf(&ptr, fmt, args);
		va_end(args);
		string s = ptr;
		free(ptr);
		memcpy(msg, s.c_str(), s.size());
	}

	const char *what (void) const throw() {
		return msg;
	}
};

class DZSortedException : public DZException {
public:
	DZSortedException (const char *fmt, ...) {
		char *ptr = 0;
		va_list args;
		va_start(args, fmt);
		vasprintf(&ptr, fmt, args);
		va_end(args);
		string s = ptr;
		free(ptr);
		memcpy(msg, s.c_str(), s.size());
	}
};


#endif