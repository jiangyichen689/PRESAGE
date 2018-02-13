#ifndef Utils_H
#define Utils_H

#define KB  1024LL
#define MB  KB * 1024LL
#define GB  MB * 1024LL
#define KB500 KB * 1LL

#ifndef __ssize_t_defined
typedef long int ssize_l_t;
# define __ssize_t_defined
#endif

#define VERSION	0x20 // 0x10
#define MAGIC 	(0x07445A00ll | VERSION)

extern int  optLogLevel;

#define SGX_ENCLAVE
#ifndef SGX_ENCLAVE 
#define WARN(c,...)\
	fprintf(stderr, c"\n", ##__VA_ARGS__)
#define DERROR(c,...)\
	fprintf(stderr, c"\n", ##__VA_ARGS__)
#define LOG(c,...)\
{if(optLogLevel>=1) fprintf(stderr, c"\n", ##__VA_ARGS__);}
#define DEBUG(c,...)\
{if(optLogLevel>=2) fprintf(stderr, c"\n", ##__VA_ARGS__);}
#define DEBUGN(c,...)\
{if(optLogLevel>=2) fprintf(stderr, c, ##__VA_ARGS__);}
#define LOGN(c,...)\
{if(optLogLevel>=1) fprintf(stderr, c, ##__VA_ARGS__);}
#else
#define WARN(c,...) 
#define DERROR(c,...)

#define LOG(c,...)

#define DEBUG(c,...)

#define DEBUGN(c,...)

#define LOGN(c,...)

#endif



#define REPEAT(x)\
	for(int _=0;_<x;_++)
#define foreach(i,c) \
	for (auto i = (c).begin(); i != (c).end(); ++i)

// inline std::vector<std::string> split (std::string s, char delim) 
// {
// 	std::stringstream ss(s);
// 	std::string item;
// 	std::vector<std::string> elems;
// 	while (std::getline(ss, item, delim)) 
// 		elems.push_back(item);
// 	return elems;
// }

inline std::vector<std::string> split(std::string str, char delimiter){
	std::vector<std::string> int_vec;
	std::string::size_type lastPos = str.find_first_not_of(delimiter, 0);
	std::string::size_type pos     = str.find_first_of(delimiter, lastPos);
	while (std::string::npos != pos || std::string::npos != lastPos){
		int_vec.push_back(str.substr(lastPos, pos - lastPos));
		lastPos = str.find_first_not_of(delimiter, pos);
		pos = str.find_first_of(delimiter, lastPos);
	}

	return int_vec;
}


/*inline uint64_t zaman() 
{
//struct timeval t;
//gettimeofday(&t, 0);
//return (t.tv_sec * 1000000ll + t.tv_usec);
}*/

#define ZAMAN_VAR(s)	
#define ZAMAN_START(s) 
#define ZAMAN_END(s)
#define ZAMAN_THREAD_JOIN()
#define ZAMAN_START_P(s)
#define ZAMAN_END_P(s)
#define ZAMAN_REPORT()

#endif // Utils_H