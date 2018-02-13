#include "RandomAccessArray.h"
#include "Util.h"

using namespace std;

RandomAccessArray::RandomAccessArray(RandElem_t* array0, int elem_num)
{
	level_elem = PAGE_VOL / (sizeof(RandElem_t));
	cal_level_num(elem_num, level_elem, arr);

	rnd_array = (RandElem_t **) malloc(arr.size() * sizeof(RandElem_t*));//new RandElem_t*[arr.size()];

	for(int n = 0; n < arr.size(); n++)
	{
		rnd_array[n] = (RandElem_t *) malloc(arr[n] * sizeof(RandElem_t));
	}

	memcpy(rnd_array[0], array0, sizeof(RandElem_t) * elem_num);
}

RandElem_t RandomAccessArray::get_elem(int ind, int level)
{
	if(level == arr.size() - 1)
	{
		return rnd_array[level][ind];
	}else{
		int pos = shuffle_next_level(level++, ind);
		return get_elem(pos, level);
	}
}

int RandomAccessArray::shuffle_next_level(int level, int ind)
{
	if(level == arr.size() - 1)
	{
		return -1;
	}
	else
	{
		for(int n = 0; n < arr[level+1]; n++)
		{
			rnd_array[level + 1][n] = rnd_array[level][n * level_elem];
		}
		int pos = arr[level+1]/2;
		rnd_array[level + 1][pos] = rnd_array[level][ind];

		return pos;
	}
}

RandomAccessArray::~RandomAccessArray()
{
	for(int n = 0; n < arr.size(); n++)
	{
		free(rnd_array[n]);
	}
	free(rnd_array);
}

