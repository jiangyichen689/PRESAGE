#ifndef FileIO_H
#define FileIO_H

#include "Common.h"
#include "Utils.h"

using namespace std;

class File
{
	FILE *fh;
	size_t fsize;

protected:
	File ();

public:
	File (FILE *handle);
	File (const string &path, const char *mode);
	virtual ~File ();

	virtual void open (const string &path, const char *mode);
	virtual void close ();

	virtual ssize_l_t read (void *buffer, size_t size);
	virtual ssize_l_t read (void *buffer, size_t size, size_t offset);
	virtual ssize_l_t write (void *buffer, size_t size);
	virtual size_t advance(size_t size);

	virtual char getc();
	virtual uint8_t readU8();
	virtual uint16_t readU16();
	virtual uint32_t readU32();
	virtual uint64_t readU64();

	virtual ssize_l_t tell ();
	virtual ssize_l_t seek (size_t pos);

	virtual size_t size ();
	virtual bool eof ();
	virtual void *handle ();

private:
	virtual void get_size ();

public:
	static File* Open(const string &path, const char *mode);
	static bool Exists (const string &path);
	static string FullPath (const string &s);
	static string RemoveExtension (const string &s);
	//static bool IsWeb (const string &path);
	//static bool IsS3 (const string &path);
	//static string GetURLforS3 (string url, CURL *ch, string method = "GET");
};

/*class GzFile: public File
{
	gzFile fh;

public:
	GzFile (FILE *handle);
	GzFile (const string &path, const char *mode);
	~GzFile ();

	void open (const string &path, const char *mode);
	void close ();

	ssize_l_t read (void *buffer, size_t size);
	ssize_l_t read(void *buffer, size_t size, size_t offset);
	ssize_l_t write (void *buffer, size_t size);

	ssize_l_t tell ();
	ssize_l_t seek (size_t pos);

	size_t size ();
	bool eof ();
	void *handle ();

private:
	void get_size ();
}; //*/

#endif // FileIO_H
