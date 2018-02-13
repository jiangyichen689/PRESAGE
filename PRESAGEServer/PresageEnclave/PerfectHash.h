#ifndef _PERFECT_HASH
#define _PERFECT_HASH

#include "PerfectHash_Types.h"
#include "Util.h"

cmph_t *cmph_load(Memory_IO *mem);
cmph_uint32 cmph_search(cmph_t *mphf, const char *key, cmph_uint32 keylen);

#endif