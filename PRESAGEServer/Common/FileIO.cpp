#include "FileIO.h"

File* File::Open (const string &path, const char *mode) 
{
	File * tmpFile = new File(path, mode);
	return tmpFile;
}

bool File::Exists (const string &path)
{
	bool result = false;
	FILE *f = fopen(path.c_str(), "r");
	result = (f != 0);
	if (f) fclose(f);
	return result;
}

string File::FullPath (const string &s) 
{
	/*char *pp = realpath(s.c_str(), 0);
	string p = pp;
	free(pp);
	return p; */
	return s;
}

string File::RemoveExtension (const string &s) 
{
	int i = s.find_last_of(".");
	if (i == string::npos) 
		i = s.size();
	return s.substr(0, i);
}

/*************************************************************************/

File::File () 
{
	fh = 0;
}

File::File (FILE *handle) 
{
	fh = handle;
}

File::File (const string &path, const char *mode) 
{ 
	open(path, mode); 
}

File::~File () 
{
	close();
}

void File::open (const string &path, const char *mode) 
{ 
	fh = fopen(path.c_str(), mode); 
	if (!fh) throw DZException("Cannot open file %s", path.c_str());
	get_size();
}

void File::close () 
{ 
	if (fh) fclose(fh);
	fh = 0; 
}

ssize_l_t File::read (void *buffer, size_t size) 
{ 
	return fread(buffer, 1, size, fh); 
}

ssize_l_t File::read (void *buffer, size_t size, size_t offset) 
{
	fseek(fh, offset, SEEK_SET);
	return read(buffer, size);
}

size_t File::advance(size_t size)
{
	fseek(fh, size, SEEK_CUR);
	return ftell(fh);
}	

char File::getc ()
{
	char c;
	if (read(&c, 1) == 0)
		c = EOF;
	return c;
}

uint8_t File::readU8 () 
{
	uint8_t var;
	if (read(&var, sizeof(uint8_t)) != sizeof(uint8_t))
		throw DZException("uint8_t read failed");
	return var;
}

uint16_t File::readU16 () 
{
	uint16_t var;
	if (read(&var, sizeof(uint16_t)) != sizeof(uint16_t))
		throw DZException("uint16_t read failed");
	return var;
}

uint32_t File::readU32 () 
{
	uint32_t var;
	if (read(&var, sizeof(uint32_t)) != sizeof(uint32_t))
		throw DZException("uint32_t read failed");
	return var;
}

uint64_t File::readU64 () 
{
	uint64_t var;
	if (read(&var, sizeof(uint64_t)) != sizeof(uint64_t))
		throw DZException("uint64_t read failed");
	return var;
}

ssize_l_t File::write (void *buffer, size_t size) 
{ 
	return fwrite(buffer, 1, size, fh); 
}

ssize_l_t File::tell ()
{
	return ftell(fh);
}

ssize_l_t File::seek (size_t pos)
{
	return fseek(fh, pos, SEEK_SET);
}

size_t File::size () 
{
	return fsize;
}

bool File::eof () 
{ 
	return feof(fh); 
}

void File::get_size () 
{
	fseek(fh, 0, SEEK_END);
	fsize = ftell(fh);
	fseek(fh, 0, SEEK_SET);
}

void *File::handle ()
{
	return fh;
}

/*GzFile::GzFile (const string &path, const char *mode) 
{ 
	open(path, mode); 
}

GzFile::GzFile (FILE *handle) 
{
	fh = gzdopen(_fileno(handle), "rb");
	if (!fh) throw DZException("Cannot open GZ file via handle");
}

GzFile::~GzFile () 
{
	close();
}

void GzFile::open (const string &path, const char *mode) 
{ 
	fh = gzopen(path.c_str(), mode); 
	if (!fh) throw DZException("Cannot open file %s", path.c_str());
}

void GzFile::close () 
{ 
	if (fh) gzclose(fh);
	fh = 0; 
}

ssize_l_t GzFile::read (void *buffer, size_t size) 
{ 
	const size_t offset = 1 * (size_t)GB;
	if (size > offset) {
		return gzread(fh, buffer, offset) + read((char*)buffer + offset, size - offset); 
	} else {
		return gzread(fh, buffer, size);
	}
}

ssize_l_t GzFile::read(void *buffer, size_t size, size_t offset) 
{
	throw DZException("GZ random access is not yet supported");
}

ssize_l_t GzFile::write (void *buffer, size_t size) 
{ 
	return gzwrite(fh, buffer, size); 
}

ssize_l_t GzFile::tell ()
{
	return gztell(fh);
}

ssize_l_t GzFile::seek (size_t pos)
{
	return gzseek(fh, pos, SEEK_SET);
}

size_t GzFile::size () 
{
	throw DZException("GZ file size is not supported");
}

bool GzFile::eof () 
{ 
	return gzeof(fh); 
}

void GzFile::get_size () 
{
	throw DZException("GZ file size is not supported");
}

void *GzFile::handle ()
{
	return fh;
}//*/