#include <stdio.h>
#include <string.h>
#include <vector>
#include "Util.h"

#include "PresageEnclave_t.h"

using namespace std;

//printf data for debugging
void printf(const char *fmt, ...)
{
	char buf[BUFSIZ] = {'\0'};
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(buf, BUFSIZ, fmt, ap);
	va_end(ap);
	ocall_print_string(buf);
}

void sprintf(char* buf, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(buf, BUFSIZ, fmt, ap);
	va_end(ap);
}

size_t mread(void* ptr, size_t size, size_t count, Memory_IO *mem)
{
	if(size == 0 || count == 0 || mem->current_pos + size > mem->len)
	{
		*((char*)ptr) = '\0';
		return 0;
	}

	size_t _size;

	if(mem->current_pos + size * count > mem->len)
	{
		_size =( (count = mem->len - mem->current_pos)) / size * size;
	}
	else
	{
		_size = size * count;
	}

	memcpy(ptr, mem->mem_ptr+ mem->current_pos, _size);
	mem->current_pos += _size;

	return _size;
}

void cal_level_num(int num, int level_num, vector<int>  &vec)
{
	if(num <= 0)
	{
		return;
	}

	vec.push_back(num);
	if(num > level_num)
	{
		cal_level_num((num + level_num - 1)/level_num, level_num, vec);
	}
}