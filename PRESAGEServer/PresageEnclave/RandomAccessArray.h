#ifndef _RANDOM_ACESSS_ARRAY
#define _RANDOM_ACESSS_ARRAY
#include<stdint.h>
#include<vector>

#define PAGE_VOL 4096
typedef uint64_t RandElem_t; //sizeof(RandoElem) must be devided by PAGE_VOL

class RandomAccessArray
{
public:
	RandomAccessArray(RandElem_t* array0, int elem_num);
	RandElem_t get_elem(int ind, int level);
	~RandomAccessArray();

private:
	std::vector<int> arr;
	int level_elem;
	RandElem_t ** rnd_array;

	int shuffle_next_level(int level, int ind);
};

#endif