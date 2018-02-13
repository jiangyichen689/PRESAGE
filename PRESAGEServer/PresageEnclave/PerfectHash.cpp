#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <math.h>
#include <assert.h>

#include "PerfectHash.h"
#include "Util.h"

const char *cmph_hash_names[] = { "jenkins", NULL };
const char *cmph_names[] = {"bmz", "bmz8", "chm", "brz", "fch", "bdz", "bdz_ph", "chd_ph", "chd", NULL };
//cmph_uint32 ngrafos = 0;
//cmph_uint32 ngrafos_aciclicos = 0;
// table used for looking up the number of assigned vertices  a 8-bit integer
const cmph_uint8 bdz_lookup_table[] =
{
4, 4, 4, 3, 4, 4, 4, 3, 4, 4, 4, 3, 3, 3, 3, 2,
4, 4, 4, 3, 4, 4, 4, 3, 4, 4, 4, 3, 3, 3, 3, 2,
4, 4, 4, 3, 4, 4, 4, 3, 4, 4, 4, 3, 3, 3, 3, 2,
3, 3, 3, 2, 3, 3, 3, 2, 3, 3, 3, 2, 2, 2, 2, 1,
4, 4, 4, 3, 4, 4, 4, 3, 4, 4, 4, 3, 3, 3, 3, 2,
4, 4, 4, 3, 4, 4, 4, 3, 4, 4, 4, 3, 3, 3, 3, 2,
4, 4, 4, 3, 4, 4, 4, 3, 4, 4, 4, 3, 3, 3, 3, 2,
3, 3, 3, 2, 3, 3, 3, 2, 3, 3, 3, 2, 2, 2, 2, 1,
4, 4, 4, 3, 4, 4, 4, 3, 4, 4, 4, 3, 3, 3, 3, 2,
4, 4, 4, 3, 4, 4, 4, 3, 4, 4, 4, 3, 3, 3, 3, 2,
4, 4, 4, 3, 4, 4, 4, 3, 4, 4, 4, 3, 3, 3, 3, 2,
3, 3, 3, 2, 3, 3, 3, 2, 3, 3, 3, 2, 2, 2, 2, 1,
3, 3, 3, 2, 3, 3, 3, 2, 3, 3, 3, 2, 2, 2, 2, 1,
3, 3, 3, 2, 3, 3, 3, 2, 3, 3, 3, 2, 2, 2, 2, 1,
3, 3, 3, 2, 3, 3, 3, 2, 3, 3, 3, 2, 2, 2, 2, 1,
2, 2, 2, 1, 2, 2, 2, 1, 2, 2, 2, 1, 1, 1, 1, 0
};

static cmph_uint8 rank_lookup_table[256] ={
   0 , 1 , 1 , 2 , 1 , 2 , 2 , 3 , 1 , 2 , 2 , 3 , 2 , 3 , 3 , 4
,  1 , 2 , 2 , 3 , 2 , 3 , 3 , 4 , 2 , 3 , 3 , 4 , 3 , 4 , 4 , 5
,  1 , 2 , 2 , 3 , 2 , 3 , 3 , 4 , 2 , 3 , 3 , 4 , 3 , 4 , 4 , 5
,  2 , 3 , 3 , 4 , 3 , 4 , 4 , 5 , 3 , 4 , 4 , 5 , 4 , 5 , 5 , 6
,  1 , 2 , 2 , 3 , 2 , 3 , 3 , 4 , 2 , 3 , 3 , 4 , 3 , 4 , 4 , 5
,  2 , 3 , 3 , 4 , 3 , 4 , 4 , 5 , 3 , 4 , 4 , 5 , 4 , 5 , 5 , 6
,  2 , 3 , 3 , 4 , 3 , 4 , 4 , 5 , 3 , 4 , 4 , 5 , 4 , 5 , 5 , 6
,  3 , 4 , 4 , 5 , 4 , 5 , 5 , 6 , 4 , 5 , 5 , 6 , 5 , 6 , 6 , 7
,  1 , 2 , 2 , 3 , 2 , 3 , 3 , 4 , 2 , 3 , 3 , 4 , 3 , 4 , 4 , 5
,  2 , 3 , 3 , 4 , 3 , 4 , 4 , 5 , 3 , 4 , 4 , 5 , 4 , 5 , 5 , 6
,  2 , 3 , 3 , 4 , 3 , 4 , 4 , 5 , 3 , 4 , 4 , 5 , 4 , 5 , 5 , 6
,  3 , 4 , 4 , 5 , 4 , 5 , 5 , 6 , 4 , 5 , 5 , 6 , 5 , 6 , 6 , 7
,  2 , 3 , 3 , 4 , 3 , 4 , 4 , 5 , 3 , 4 , 4 , 5 , 4 , 5 , 5 , 6
,  3 , 4 , 4 , 5 , 4 , 5 , 5 , 6 , 4 , 5 , 5 , 6 , 5 , 6 , 6 , 7
,  3 , 4 , 4 , 5 , 4 , 5 , 5 , 6 , 4 , 5 , 5 , 6 , 5 , 6 , 6 , 7
,  4 , 5 , 5 , 6 , 5 , 6 , 6 , 7 , 5 , 6 , 6 , 7 , 6 , 7 , 7 , 8 
 };

static cmph_uint8 lookup_table[5][256] = {
 {0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0},
 {0, 0, 0, 1, 1, 1, 2, 2, 2, 0, 0, 0, 1, 1, 1, 2, 2, 2, 0, 0, 0, 1, 1, 1, 2, 2, 2, 0, 0, 0, 1, 1, 1, 2, 2, 2, 0, 0, 0, 1, 1, 1, 2, 2, 2, 0, 0, 0, 1, 1, 1, 2, 2, 2, 0, 0, 0, 1, 1, 1, 2, 2, 2, 0, 0, 0, 1, 1, 1, 2, 2, 2, 0, 0, 0, 1, 1, 1, 2, 2, 2, 0, 0, 0, 1, 1, 1, 2, 2, 2, 0, 0, 0, 1, 1, 1, 2, 2, 2, 0, 0, 0, 1, 1, 1, 2, 2, 2, 0, 0, 0, 1, 1, 1, 2, 2, 2, 0, 0, 0, 1, 1, 1, 2, 2, 2, 0, 0, 0, 1, 1, 1, 2, 2, 2, 0, 0, 0, 1, 1, 1, 2, 2, 2, 0, 0, 0, 1, 1, 1, 2, 2, 2, 0, 0, 0, 1, 1, 1, 2, 2, 2, 0, 0, 0, 1, 1, 1, 2, 2, 2, 0, 0, 0, 1, 1, 1, 2, 2, 2, 0, 0, 0, 1, 1, 1, 2, 2, 2, 0, 0, 0, 1, 1, 1, 2, 2, 2, 0, 0, 0, 1, 1, 1, 2, 2, 2, 0, 0, 0, 1, 1, 1, 2, 2, 2, 0, 0, 0, 1, 1, 1, 2, 2, 2, 0, 0, 0, 1, 1, 1, 2, 2, 2, 0, 0, 0, 1, 1, 1, 2, 2, 2, 0, 0, 0, 1, 1, 1, 2, 2, 2, 0, 0, 0, 1},
 {0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1},
 {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
 {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
};


/*
select_lookup_table[i][j] simply gives the index of the j'th bit set to one in the byte of value i.
For example if i=01010101 in binary then we have :
select_lookup_table[i][0] = 0,   the first bit set to one is at position 0
select_lookup_table[i][1] = 2,   the second bit set to one is at position 2
select_lookup_table[i][2] = 4,   the third bit set to one is at position 4
select_lookup_table[i][3] = 6,   the fourth bit set to one is at position 6
select_lookup_table[i][4] = 255, there is no more than 4 bits set to one in i, so we return escape value 255. 
*/
static cmph_uint8 select_lookup_table[256][8]={
{ 255 , 255 , 255 , 255 , 255 , 255 , 255 , 255 } , { 0 , 255 , 255 , 255 , 255 , 255 , 255 , 255 } ,
{ 1 , 255 , 255 , 255 , 255 , 255 , 255 , 255 } , { 0 , 1 , 255 , 255 , 255 , 255 , 255 , 255 } ,
{ 2 , 255 , 255 , 255 , 255 , 255 , 255 , 255 } , { 0 , 2 , 255 , 255 , 255 , 255 , 255 , 255 } ,
{ 1 , 2 , 255 , 255 , 255 , 255 , 255 , 255 } , { 0 , 1 , 2 , 255 , 255 , 255 , 255 , 255 } ,
{ 3 , 255 , 255 , 255 , 255 , 255 , 255 , 255 } , { 0 , 3 , 255 , 255 , 255 , 255 , 255 , 255 } ,
{ 1 , 3 , 255 , 255 , 255 , 255 , 255 , 255 } , { 0 , 1 , 3 , 255 , 255 , 255 , 255 , 255 } ,
{ 2 , 3 , 255 , 255 , 255 , 255 , 255 , 255 } , { 0 , 2 , 3 , 255 , 255 , 255 , 255 , 255 } ,
{ 1 , 2 , 3 , 255 , 255 , 255 , 255 , 255 } , { 0 , 1 , 2 , 3 , 255 , 255 , 255 , 255 } ,
{ 4 , 255 , 255 , 255 , 255 , 255 , 255 , 255 } , { 0 , 4 , 255 , 255 , 255 , 255 , 255 , 255 } ,
{ 1 , 4 , 255 , 255 , 255 , 255 , 255 , 255 } , { 0 , 1 , 4 , 255 , 255 , 255 , 255 , 255 } ,
{ 2 , 4 , 255 , 255 , 255 , 255 , 255 , 255 } , { 0 , 2 , 4 , 255 , 255 , 255 , 255 , 255 } ,
{ 1 , 2 , 4 , 255 , 255 , 255 , 255 , 255 } , { 0 , 1 , 2 , 4 , 255 , 255 , 255 , 255 } ,
{ 3 , 4 , 255 , 255 , 255 , 255 , 255 , 255 } , { 0 , 3 , 4 , 255 , 255 , 255 , 255 , 255 } ,
{ 1 , 3 , 4 , 255 , 255 , 255 , 255 , 255 } , { 0 , 1 , 3 , 4 , 255 , 255 , 255 , 255 } ,
{ 2 , 3 , 4 , 255 , 255 , 255 , 255 , 255 } , { 0 , 2 , 3 , 4 , 255 , 255 , 255 , 255 } ,
{ 1 , 2 , 3 , 4 , 255 , 255 , 255 , 255 } , { 0 , 1 , 2 , 3 , 4 , 255 , 255 , 255 } ,
{ 5 , 255 , 255 , 255 , 255 , 255 , 255 , 255 } , { 0 , 5 , 255 , 255 , 255 , 255 , 255 , 255 } ,
{ 1 , 5 , 255 , 255 , 255 , 255 , 255 , 255 } , { 0 , 1 , 5 , 255 , 255 , 255 , 255 , 255 } ,
{ 2 , 5 , 255 , 255 , 255 , 255 , 255 , 255 } , { 0 , 2 , 5 , 255 , 255 , 255 , 255 , 255 } ,
{ 1 , 2 , 5 , 255 , 255 , 255 , 255 , 255 } , { 0 , 1 , 2 , 5 , 255 , 255 , 255 , 255 } ,
{ 3 , 5 , 255 , 255 , 255 , 255 , 255 , 255 } , { 0 , 3 , 5 , 255 , 255 , 255 , 255 , 255 } ,
{ 1 , 3 , 5 , 255 , 255 , 255 , 255 , 255 } , { 0 , 1 , 3 , 5 , 255 , 255 , 255 , 255 } ,
{ 2 , 3 , 5 , 255 , 255 , 255 , 255 , 255 } , { 0 , 2 , 3 , 5 , 255 , 255 , 255 , 255 } ,
{ 1 , 2 , 3 , 5 , 255 , 255 , 255 , 255 } , { 0 , 1 , 2 , 3 , 5 , 255 , 255 , 255 } ,
{ 4 , 5 , 255 , 255 , 255 , 255 , 255 , 255 } , { 0 , 4 , 5 , 255 , 255 , 255 , 255 , 255 } ,
{ 1 , 4 , 5 , 255 , 255 , 255 , 255 , 255 } , { 0 , 1 , 4 , 5 , 255 , 255 , 255 , 255 } ,
{ 2 , 4 , 5 , 255 , 255 , 255 , 255 , 255 } , { 0 , 2 , 4 , 5 , 255 , 255 , 255 , 255 } ,
{ 1 , 2 , 4 , 5 , 255 , 255 , 255 , 255 } , { 0 , 1 , 2 , 4 , 5 , 255 , 255 , 255 } ,
{ 3 , 4 , 5 , 255 , 255 , 255 , 255 , 255 } , { 0 , 3 , 4 , 5 , 255 , 255 , 255 , 255 } ,
{ 1 , 3 , 4 , 5 , 255 , 255 , 255 , 255 } , { 0 , 1 , 3 , 4 , 5 , 255 , 255 , 255 } ,
{ 2 , 3 , 4 , 5 , 255 , 255 , 255 , 255 } , { 0 , 2 , 3 , 4 , 5 , 255 , 255 , 255 } ,
{ 1 , 2 , 3 , 4 , 5 , 255 , 255 , 255 } , { 0 , 1 , 2 , 3 , 4 , 5 , 255 , 255 } ,
{ 6 , 255 , 255 , 255 , 255 , 255 , 255 , 255 } , { 0 , 6 , 255 , 255 , 255 , 255 , 255 , 255 } ,
{ 1 , 6 , 255 , 255 , 255 , 255 , 255 , 255 } , { 0 , 1 , 6 , 255 , 255 , 255 , 255 , 255 } ,
{ 2 , 6 , 255 , 255 , 255 , 255 , 255 , 255 } , { 0 , 2 , 6 , 255 , 255 , 255 , 255 , 255 } ,
{ 1 , 2 , 6 , 255 , 255 , 255 , 255 , 255 } , { 0 , 1 , 2 , 6 , 255 , 255 , 255 , 255 } ,
{ 3 , 6 , 255 , 255 , 255 , 255 , 255 , 255 } , { 0 , 3 , 6 , 255 , 255 , 255 , 255 , 255 } ,
{ 1 , 3 , 6 , 255 , 255 , 255 , 255 , 255 } , { 0 , 1 , 3 , 6 , 255 , 255 , 255 , 255 } ,
{ 2 , 3 , 6 , 255 , 255 , 255 , 255 , 255 } , { 0 , 2 , 3 , 6 , 255 , 255 , 255 , 255 } ,
{ 1 , 2 , 3 , 6 , 255 , 255 , 255 , 255 } , { 0 , 1 , 2 , 3 , 6 , 255 , 255 , 255 } ,
{ 4 , 6 , 255 , 255 , 255 , 255 , 255 , 255 } , { 0 , 4 , 6 , 255 , 255 , 255 , 255 , 255 } ,
{ 1 , 4 , 6 , 255 , 255 , 255 , 255 , 255 } , { 0 , 1 , 4 , 6 , 255 , 255 , 255 , 255 } ,
{ 2 , 4 , 6 , 255 , 255 , 255 , 255 , 255 } , { 0 , 2 , 4 , 6 , 255 , 255 , 255 , 255 } ,
{ 1 , 2 , 4 , 6 , 255 , 255 , 255 , 255 } , { 0 , 1 , 2 , 4 , 6 , 255 , 255 , 255 } ,
{ 3 , 4 , 6 , 255 , 255 , 255 , 255 , 255 } , { 0 , 3 , 4 , 6 , 255 , 255 , 255 , 255 } ,
{ 1 , 3 , 4 , 6 , 255 , 255 , 255 , 255 } , { 0 , 1 , 3 , 4 , 6 , 255 , 255 , 255 } ,
{ 2 , 3 , 4 , 6 , 255 , 255 , 255 , 255 } , { 0 , 2 , 3 , 4 , 6 , 255 , 255 , 255 } ,
{ 1 , 2 , 3 , 4 , 6 , 255 , 255 , 255 } , { 0 , 1 , 2 , 3 , 4 , 6 , 255 , 255 } ,
{ 5 , 6 , 255 , 255 , 255 , 255 , 255 , 255 } , { 0 , 5 , 6 , 255 , 255 , 255 , 255 , 255 } ,
{ 1 , 5 , 6 , 255 , 255 , 255 , 255 , 255 } , { 0 , 1 , 5 , 6 , 255 , 255 , 255 , 255 } ,
{ 2 , 5 , 6 , 255 , 255 , 255 , 255 , 255 } , { 0 , 2 , 5 , 6 , 255 , 255 , 255 , 255 } ,
{ 1 , 2 , 5 , 6 , 255 , 255 , 255 , 255 } , { 0 , 1 , 2 , 5 , 6 , 255 , 255 , 255 } ,
{ 3 , 5 , 6 , 255 , 255 , 255 , 255 , 255 } , { 0 , 3 , 5 , 6 , 255 , 255 , 255 , 255 } ,
{ 1 , 3 , 5 , 6 , 255 , 255 , 255 , 255 } , { 0 , 1 , 3 , 5 , 6 , 255 , 255 , 255 } ,
{ 2 , 3 , 5 , 6 , 255 , 255 , 255 , 255 } , { 0 , 2 , 3 , 5 , 6 , 255 , 255 , 255 } ,
{ 1 , 2 , 3 , 5 , 6 , 255 , 255 , 255 } , { 0 , 1 , 2 , 3 , 5 , 6 , 255 , 255 } ,
{ 4 , 5 , 6 , 255 , 255 , 255 , 255 , 255 } , { 0 , 4 , 5 , 6 , 255 , 255 , 255 , 255 } ,
{ 1 , 4 , 5 , 6 , 255 , 255 , 255 , 255 } , { 0 , 1 , 4 , 5 , 6 , 255 , 255 , 255 } ,
{ 2 , 4 , 5 , 6 , 255 , 255 , 255 , 255 } , { 0 , 2 , 4 , 5 , 6 , 255 , 255 , 255 } ,
{ 1 , 2 , 4 , 5 , 6 , 255 , 255 , 255 } , { 0 , 1 , 2 , 4 , 5 , 6 , 255 , 255 } ,
{ 3 , 4 , 5 , 6 , 255 , 255 , 255 , 255 } , { 0 , 3 , 4 , 5 , 6 , 255 , 255 , 255 } ,
{ 1 , 3 , 4 , 5 , 6 , 255 , 255 , 255 } , { 0 , 1 , 3 , 4 , 5 , 6 , 255 , 255 } ,
{ 2 , 3 , 4 , 5 , 6 , 255 , 255 , 255 } , { 0 , 2 , 3 , 4 , 5 , 6 , 255 , 255 } ,
{ 1 , 2 , 3 , 4 , 5 , 6 , 255 , 255 } , { 0 , 1 , 2 , 3 , 4 , 5 , 6 , 255 } ,
{ 7 , 255 , 255 , 255 , 255 , 255 , 255 , 255 } , { 0 , 7 , 255 , 255 , 255 , 255 , 255 , 255 } ,
{ 1 , 7 , 255 , 255 , 255 , 255 , 255 , 255 } , { 0 , 1 , 7 , 255 , 255 , 255 , 255 , 255 } ,
{ 2 , 7 , 255 , 255 , 255 , 255 , 255 , 255 } , { 0 , 2 , 7 , 255 , 255 , 255 , 255 , 255 } ,
{ 1 , 2 , 7 , 255 , 255 , 255 , 255 , 255 } , { 0 , 1 , 2 , 7 , 255 , 255 , 255 , 255 } ,
{ 3 , 7 , 255 , 255 , 255 , 255 , 255 , 255 } , { 0 , 3 , 7 , 255 , 255 , 255 , 255 , 255 } ,
{ 1 , 3 , 7 , 255 , 255 , 255 , 255 , 255 } , { 0 , 1 , 3 , 7 , 255 , 255 , 255 , 255 } ,
{ 2 , 3 , 7 , 255 , 255 , 255 , 255 , 255 } , { 0 , 2 , 3 , 7 , 255 , 255 , 255 , 255 } ,
{ 1 , 2 , 3 , 7 , 255 , 255 , 255 , 255 } , { 0 , 1 , 2 , 3 , 7 , 255 , 255 , 255 } ,
{ 4 , 7 , 255 , 255 , 255 , 255 , 255 , 255 } , { 0 , 4 , 7 , 255 , 255 , 255 , 255 , 255 } ,
{ 1 , 4 , 7 , 255 , 255 , 255 , 255 , 255 } , { 0 , 1 , 4 , 7 , 255 , 255 , 255 , 255 } ,
{ 2 , 4 , 7 , 255 , 255 , 255 , 255 , 255 } , { 0 , 2 , 4 , 7 , 255 , 255 , 255 , 255 } ,
{ 1 , 2 , 4 , 7 , 255 , 255 , 255 , 255 } , { 0 , 1 , 2 , 4 , 7 , 255 , 255 , 255 } ,
{ 3 , 4 , 7 , 255 , 255 , 255 , 255 , 255 } , { 0 , 3 , 4 , 7 , 255 , 255 , 255 , 255 } ,
{ 1 , 3 , 4 , 7 , 255 , 255 , 255 , 255 } , { 0 , 1 , 3 , 4 , 7 , 255 , 255 , 255 } ,
{ 2 , 3 , 4 , 7 , 255 , 255 , 255 , 255 } , { 0 , 2 , 3 , 4 , 7 , 255 , 255 , 255 } ,
{ 1 , 2 , 3 , 4 , 7 , 255 , 255 , 255 } , { 0 , 1 , 2 , 3 , 4 , 7 , 255 , 255 } ,
{ 5 , 7 , 255 , 255 , 255 , 255 , 255 , 255 } , { 0 , 5 , 7 , 255 , 255 , 255 , 255 , 255 } ,
{ 1 , 5 , 7 , 255 , 255 , 255 , 255 , 255 } , { 0 , 1 , 5 , 7 , 255 , 255 , 255 , 255 } ,
{ 2 , 5 , 7 , 255 , 255 , 255 , 255 , 255 } , { 0 , 2 , 5 , 7 , 255 , 255 , 255 , 255 } ,
{ 1 , 2 , 5 , 7 , 255 , 255 , 255 , 255 } , { 0 , 1 , 2 , 5 , 7 , 255 , 255 , 255 } ,
{ 3 , 5 , 7 , 255 , 255 , 255 , 255 , 255 } , { 0 , 3 , 5 , 7 , 255 , 255 , 255 , 255 } ,
{ 1 , 3 , 5 , 7 , 255 , 255 , 255 , 255 } , { 0 , 1 , 3 , 5 , 7 , 255 , 255 , 255 } ,
{ 2 , 3 , 5 , 7 , 255 , 255 , 255 , 255 } , { 0 , 2 , 3 , 5 , 7 , 255 , 255 , 255 } ,
{ 1 , 2 , 3 , 5 , 7 , 255 , 255 , 255 } , { 0 , 1 , 2 , 3 , 5 , 7 , 255 , 255 } ,
{ 4 , 5 , 7 , 255 , 255 , 255 , 255 , 255 } , { 0 , 4 , 5 , 7 , 255 , 255 , 255 , 255 } ,
{ 1 , 4 , 5 , 7 , 255 , 255 , 255 , 255 } , { 0 , 1 , 4 , 5 , 7 , 255 , 255 , 255 } ,
{ 2 , 4 , 5 , 7 , 255 , 255 , 255 , 255 } , { 0 , 2 , 4 , 5 , 7 , 255 , 255 , 255 } ,
{ 1 , 2 , 4 , 5 , 7 , 255 , 255 , 255 } , { 0 , 1 , 2 , 4 , 5 , 7 , 255 , 255 } ,
{ 3 , 4 , 5 , 7 , 255 , 255 , 255 , 255 } , { 0 , 3 , 4 , 5 , 7 , 255 , 255 , 255 } ,
{ 1 , 3 , 4 , 5 , 7 , 255 , 255 , 255 } , { 0 , 1 , 3 , 4 , 5 , 7 , 255 , 255 } ,
{ 2 , 3 , 4 , 5 , 7 , 255 , 255 , 255 } , { 0 , 2 , 3 , 4 , 5 , 7 , 255 , 255 } ,
{ 1 , 2 , 3 , 4 , 5 , 7 , 255 , 255 } , { 0 , 1 , 2 , 3 , 4 , 5 , 7 , 255 } ,
{ 6 , 7 , 255 , 255 , 255 , 255 , 255 , 255 } , { 0 , 6 , 7 , 255 , 255 , 255 , 255 , 255 } ,
{ 1 , 6 , 7 , 255 , 255 , 255 , 255 , 255 } , { 0 , 1 , 6 , 7 , 255 , 255 , 255 , 255 } ,
{ 2 , 6 , 7 , 255 , 255 , 255 , 255 , 255 } , { 0 , 2 , 6 , 7 , 255 , 255 , 255 , 255 } ,
{ 1 , 2 , 6 , 7 , 255 , 255 , 255 , 255 } , { 0 , 1 , 2 , 6 , 7 , 255 , 255 , 255 } ,
{ 3 , 6 , 7 , 255 , 255 , 255 , 255 , 255 } , { 0 , 3 , 6 , 7 , 255 , 255 , 255 , 255 } ,
{ 1 , 3 , 6 , 7 , 255 , 255 , 255 , 255 } , { 0 , 1 , 3 , 6 , 7 , 255 , 255 , 255 } ,
{ 2 , 3 , 6 , 7 , 255 , 255 , 255 , 255 } , { 0 , 2 , 3 , 6 , 7 , 255 , 255 , 255 } ,
{ 1 , 2 , 3 , 6 , 7 , 255 , 255 , 255 } , { 0 , 1 , 2 , 3 , 6 , 7 , 255 , 255 } ,
{ 4 , 6 , 7 , 255 , 255 , 255 , 255 , 255 } , { 0 , 4 , 6 , 7 , 255 , 255 , 255 , 255 } ,
{ 1 , 4 , 6 , 7 , 255 , 255 , 255 , 255 } , { 0 , 1 , 4 , 6 , 7 , 255 , 255 , 255 } ,
{ 2 , 4 , 6 , 7 , 255 , 255 , 255 , 255 } , { 0 , 2 , 4 , 6 , 7 , 255 , 255 , 255 } ,
{ 1 , 2 , 4 , 6 , 7 , 255 , 255 , 255 } , { 0 , 1 , 2 , 4 , 6 , 7 , 255 , 255 } ,
{ 3 , 4 , 6 , 7 , 255 , 255 , 255 , 255 } , { 0 , 3 , 4 , 6 , 7 , 255 , 255 , 255 } ,
{ 1 , 3 , 4 , 6 , 7 , 255 , 255 , 255 } , { 0 , 1 , 3 , 4 , 6 , 7 , 255 , 255 } ,
{ 2 , 3 , 4 , 6 , 7 , 255 , 255 , 255 } , { 0 , 2 , 3 , 4 , 6 , 7 , 255 , 255 } ,
{ 1 , 2 , 3 , 4 , 6 , 7 , 255 , 255 } , { 0 , 1 , 2 , 3 , 4 , 6 , 7 , 255 } ,
{ 5 , 6 , 7 , 255 , 255 , 255 , 255 , 255 } , { 0 , 5 , 6 , 7 , 255 , 255 , 255 , 255 } ,
{ 1 , 5 , 6 , 7 , 255 , 255 , 255 , 255 } , { 0 , 1 , 5 , 6 , 7 , 255 , 255 , 255 } ,
{ 2 , 5 , 6 , 7 , 255 , 255 , 255 , 255 } , { 0 , 2 , 5 , 6 , 7 , 255 , 255 , 255 } ,
{ 1 , 2 , 5 , 6 , 7 , 255 , 255 , 255 } , { 0 , 1 , 2 , 5 , 6 , 7 , 255 , 255 } ,
{ 3 , 5 , 6 , 7 , 255 , 255 , 255 , 255 } , { 0 , 3 , 5 , 6 , 7 , 255 , 255 , 255 } ,
{ 1 , 3 , 5 , 6 , 7 , 255 , 255 , 255 } , { 0 , 1 , 3 , 5 , 6 , 7 , 255 , 255 } ,
{ 2 , 3 , 5 , 6 , 7 , 255 , 255 , 255 } , { 0 , 2 , 3 , 5 , 6 , 7 , 255 , 255 } ,
{ 1 , 2 , 3 , 5 , 6 , 7 , 255 , 255 } , { 0 , 1 , 2 , 3 , 5 , 6 , 7 , 255 } ,
{ 4 , 5 , 6 , 7 , 255 , 255 , 255 , 255 } , { 0 , 4 , 5 , 6 , 7 , 255 , 255 , 255 } ,
{ 1 , 4 , 5 , 6 , 7 , 255 , 255 , 255 } , { 0 , 1 , 4 , 5 , 6 , 7 , 255 , 255 } ,
{ 2 , 4 , 5 , 6 , 7 , 255 , 255 , 255 } , { 0 , 2 , 4 , 5 , 6 , 7 , 255 , 255 } ,
{ 1 , 2 , 4 , 5 , 6 , 7 , 255 , 255 } , { 0 , 1 , 2 , 4 , 5 , 6 , 7 , 255 } ,
{ 3 , 4 , 5 , 6 , 7 , 255 , 255 , 255 } , { 0 , 3 , 4 , 5 , 6 , 7 , 255 , 255 } ,
{ 1 , 3 , 4 , 5 , 6 , 7 , 255 , 255 } , { 0 , 1 , 3 , 4 , 5 , 6 , 7 , 255 } ,
{ 2 , 3 , 4 , 5 , 6 , 7 , 255 , 255 } , { 0 , 2 , 3 , 4 , 5 , 6 , 7 , 255 } ,
{ 1 , 2 , 3 , 4 , 5 , 6 , 7 , 255 } , { 0 , 1 , 2 , 3 , 4 , 5 , 6 , 7 } };

//function declaration
cmph_t *__cmph_load(Memory_IO *mem);

void chm_load(Memory_IO *mem, cmph_t *mphf);
void bmz_load(Memory_IO *mem, cmph_t *mphf);
void bmz8_load(Memory_IO *mem, cmph_t *mphf);
void brz_load(Memory_IO* mem, cmph_t *mphf);
void fch_load(Memory_IO *mem, cmph_t *mphf);
void bdz_load(Memory_IO *mem, cmph_t *mphf);
void bdz_ph_load(Memory_IO *mem, cmph_t *mphf);
void chd_ph_load(Memory_IO *mem, cmph_t *mphf);
void chd_load(Memory_IO *mem, cmph_t *mphf);

cmph_uint32 chm_search(cmph_t *mphf, const char *key, cmph_uint32 keylen);
cmph_uint32 bmz_search(cmph_t *mphf, const char *key, cmph_uint32 keylen);
cmph_uint8 bmz8_search(cmph_t *mphf, const char *key, cmph_uint32 keylen);
cmph_uint32 brz_search(cmph_t *mphf, const char *key, cmph_uint32 keylen);
cmph_uint32 fch_search(cmph_t *mphf, const char *key, cmph_uint32 keylen);
cmph_uint32 bdz_search(cmph_t *mphf, const char *key, cmph_uint32 keylen);
cmph_uint32 bdz_ph_search(cmph_t *mphf, const char *key, cmph_uint32 keylen);
cmph_uint32 chd_ph_search(cmph_t *mphf, const char *key, cmph_uint32 keylen);
cmph_uint32 chd_search(cmph_t *mphf, const char *key, cmph_uint32 keylen);

hash_state_t *hash_state_load(const char *buf, cmph_uint32 buflen);
jenkins_state_t *jenkins_state_load(const char *buf, cmph_uint32 buflen);  
cmph_uint32 fch_calc_b(double c, cmph_uint32 m);
void compressed_seq_load(compressed_seq_t * cs, const char * buf, cmph_uint32 buflen);
void select_load(select_t * sel, const char *buf, cmph_uint32 buflen);

cmph_uint32 hash(hash_state_t *state, const char *key, cmph_uint32 keylen);
cmph_uint32 jenkins_hash(jenkins_state_t *state, const char *k, cmph_uint32 keylen);
void hash_vector(hash_state_t *state, const char *key, cmph_uint32 keylen, cmph_uint32 * hashes);
void jenkins_hash_vector_(jenkins_state_t *state, const char *k, cmph_uint32 keylen, cmph_uint32 * hashes);
double fch_calc_p1(cmph_uint32 m);
double fch_calc_p2(cmph_uint32 b);
cmph_uint32 mixh10h11h12(cmph_uint32 b, double p1, double p2, cmph_uint32 initial_index);
cmph_uint32 compressed_seq_query(compressed_seq_t * cs, cmph_uint32 idx);
cmph_uint32 select_query(select_t * sel, cmph_uint32 one_idx);
cmph_uint32 select_next_query(select_t * sel, cmph_uint32 vec_bit_idx);
cmph_uint32 cmph_search_packed(void *packed_mphf, const char *key, cmph_uint32 keylen);
cmph_uint32 compressed_rank_query_packed(void * cr_packed, cmph_uint32 idx);

cmph_uint32 chm_search_packed(void *packed_mphf, const char *key, cmph_uint32 keylen);
cmph_uint32 bmz_search_packed(void *packed_mphf, const char *key, cmph_uint32 keylen);
cmph_uint8 bmz8_search_packed(void *packed_mphf, const char *key, cmph_uint32 keylen);
cmph_uint32 brz_search_packed(void *packed_mphf, const char *key, cmph_uint32 keylen);
cmph_uint32 fch_search_packed(void *packed_mphf, const char *key, cmph_uint32 keylen);
cmph_uint32 bdz_search_packed(void *packed_mphf, const char *key, cmph_uint32 keylen);
cmph_uint32 bdz_ph_search_packed(void *packed_mphf, const char *key, cmph_uint32 keylen);
cmph_uint32 chd_ph_search_packed(void *packed_mphf, const char *key, cmph_uint32 keylen);
cmph_uint32 chd_search_packed(void *packed_mphf, const char *key, cmph_uint32 keylen);


cmph_uint32 hash_state_packed_size(CMPH_HASH hashfunc);
cmph_uint32 jenkins_state_packed_size(void);
cmph_uint32 hash_packed(void *hash_packed, CMPH_HASH hashfunc, const char *k, cmph_uint32 keylen);
cmph_uint32 jenkins_hash_packed(void *jenkins_packed, const char *k, cmph_uint32 keylen);
void hash_vector_packed(void *hash_packed, CMPH_HASH hashfunc, const char *k, cmph_uint32 keylen, cmph_uint32 * hashes);
void jenkins_hash_vector_packed(void *jenkins_packed, const char *k, cmph_uint32 keylen, cmph_uint32 * hashes);
cmph_uint32 compressed_seq_query_packed(void * cs_packed, cmph_uint32 idx);
cmph_uint32 select_query_packed(void * sel_packed, cmph_uint32 one_idx);
cmph_uint32 select_next_query_packed(void * sel_packed, cmph_uint32 vec_bit_idx);

static cmph_uint32 brz_fch_search(brz_data_t *brz, const char *key, cmph_uint32 keylen, cmph_uint32 * fingerprint);
static cmph_uint32 brz_bmz8_search(brz_data_t *brz, const char *key, cmph_uint32 keylen, cmph_uint32 * fingerprint);
static inline cmph_uint32 rank(cmph_uint32 b, cmph_uint32 * ranktable, cmph_uint8 * g, cmph_uint32 vertex);
static cmph_uint32 brz_fch_search_packed(cmph_uint32 *packed_mphf, const char *key, cmph_uint32 keylen, cmph_uint32 * fingerprint);
static cmph_uint32 brz_bmz8_search_packed(cmph_uint32 *packed_mphf, const char *key, cmph_uint32 keylen, cmph_uint32 * fingerprint);


static inline void __jenkins_hash_vector(cmph_uint32 seed, const char *k, cmph_uint32 keylen, cmph_uint32 * hashes)
{
	register cmph_uint32 len, length;

	/* Set up the internal state */
	length = keylen;
	len = length;
	hashes[0] = hashes[1] = 0x9e3779b9;  /* the golden ratio; an arbitrary value */
	hashes[2] = seed;   /* the previous hash value - seed in our case */

	/*---------------------------------------- handle most of the key */
	while (len >= 12)
	{
		hashes[0] += ((cmph_uint32)k[0] +((cmph_uint32)k[1]<<8) +((cmph_uint32)k[2]<<16) +((cmph_uint32)k[3]<<24));
		hashes[1] += ((cmph_uint32)k[4] +((cmph_uint32)k[5]<<8) +((cmph_uint32)k[6]<<16) +((cmph_uint32)k[7]<<24));
		hashes[2] += ((cmph_uint32)k[8] +((cmph_uint32)k[9]<<8) +((cmph_uint32)k[10]<<16)+((cmph_uint32)k[11]<<24));
		mix(hashes[0],hashes[1],hashes[2]);
		k += 12; len -= 12;
	}

	/*------------------------------------- handle the last 11 bytes */
	hashes[2]  += length;
	switch(len)              /* all the case statements fall through */
	{
		case 11:
			hashes[2] +=((cmph_uint32)k[10]<<24);
		case 10:
			hashes[2] +=((cmph_uint32)k[9]<<16);
		case 9 :
			hashes[2] +=((cmph_uint32)k[8]<<8);
			/* the first byte of hashes[2] is reserved for the length */
		case 8 :
			hashes[1] +=((cmph_uint32)k[7]<<24);
		case 7 :
			hashes[1] +=((cmph_uint32)k[6]<<16);
		case 6 :
			hashes[1] +=((cmph_uint32)k[5]<<8);
		case 5 :
			hashes[1] +=(cmph_uint8) k[4];
		case 4 :
			hashes[0] +=((cmph_uint32)k[3]<<24);
		case 3 :
			hashes[0] +=((cmph_uint32)k[2]<<16);
		case 2 :
			hashes[0] +=((cmph_uint32)k[1]<<8);
		case 1 :
			hashes[0] +=(cmph_uint8)k[0];
			/* case 0: nothing left to add */
	}

	mix(hashes[0],hashes[1],hashes[2]);
}

static inline cmph_uint32 _select_query(cmph_uint8 * bits_table, cmph_uint32 * select_table, cmph_uint32 one_idx)
{
	register cmph_uint32 vec_bit_idx ,vec_byte_idx;
	register cmph_uint32 part_sum, old_part_sum;
	
	vec_bit_idx = select_table[one_idx >> NBITS_STEP_SELECT_TABLE]; // one_idx >> NBITS_STEP_SELECT_TABLE = one_idx/STEP_SELECT_TABLE
	vec_byte_idx = vec_bit_idx >> 3; // vec_bit_idx / 8
	
	one_idx &= MASK_STEP_SELECT_TABLE; // one_idx %= STEP_SELECT_TABLE == one_idx &= MASK_STEP_SELECT_TABLE
	one_idx += rank_lookup_table[bits_table[vec_byte_idx] & ((1 << (vec_bit_idx & 0x7)) - 1)];
	part_sum = 0;
	
	do
	{
		old_part_sum = part_sum; 
		part_sum += rank_lookup_table[bits_table[vec_byte_idx]];
		vec_byte_idx++;
		
	}while (part_sum <= one_idx);
	
	return select_lookup_table[bits_table[vec_byte_idx - 1]][one_idx - old_part_sum] + ((vec_byte_idx-1) << 3);
}

static inline cmph_uint32 get_bits_value(cmph_uint32 * bits_table,cmph_uint32 index, cmph_uint32 string_length, cmph_uint32 string_mask)
{
	register cmph_uint32 bit_idx = index * string_length;
	register cmph_uint32 word_idx = bit_idx >> 5;
	register cmph_uint32 shift1 = bit_idx & 0x0000001f;
	register cmph_uint32 shift2 = 32-shift1;
	register cmph_uint32 bits_string;
	
	bits_string = (bits_table[word_idx] >> shift1) & string_mask;
	
	if(shift2 < string_length)
		bits_string |= (bits_table[word_idx+1] << shift2) & string_mask;

	return bits_string;
}

static inline cmph_uint32 _select_next_query(cmph_uint8 * bits_table, cmph_uint32 vec_bit_idx)
{
	register cmph_uint32 vec_byte_idx, one_idx;
	register cmph_uint32 part_sum, old_part_sum;
	
	vec_byte_idx = vec_bit_idx >> 3;
	
	one_idx = rank_lookup_table[bits_table[vec_byte_idx] & ((1U << (vec_bit_idx & 0x7)) - 1U)] + 1U;
	part_sum = 0;
	
	do
	{
		old_part_sum = part_sum; 
		part_sum += rank_lookup_table[bits_table[vec_byte_idx]];
		vec_byte_idx++;
		
	}while (part_sum <= one_idx);
	
	return select_lookup_table[bits_table[(vec_byte_idx - 1)]][(one_idx - old_part_sum)] + ((vec_byte_idx - 1) << 3);
}

static inline cmph_uint32 get_bits_at_pos(cmph_uint32 * bits_table,cmph_uint32 pos,cmph_uint32 string_length)
{
	register cmph_uint32 word_idx = pos >> 5;
	register cmph_uint32 shift1 = pos & 0x0000001f;
	register cmph_uint32 shift2 = 32 - shift1;
	register cmph_uint32 string_mask = (1U << string_length) - 1;
	register cmph_uint32 bits_string;
	
	bits_string = (bits_table[word_idx] >> shift1) & string_mask;

	if(shift2 < string_length)
		bits_string |= (bits_table[word_idx+1] << shift2) & string_mask;
	return bits_string;
}

static inline cmph_uint32 _chd_search(void * packed_chd_phf, void * packed_cr, const char *key, cmph_uint32 keylen)
{
	register cmph_uint32 bin_idx = cmph_search_packed(packed_chd_phf, key, keylen);
	register cmph_uint32 rank = compressed_rank_query_packed(packed_cr, bin_idx);
	return bin_idx - rank;
}

//function definition
cmph_t *cmph_load(Memory_IO *mem)
{
	cmph_t *mphf = NULL;
	//DEBUGP("Loading mphf generic parts\n");
	mphf =  __cmph_load(mem);
	if (mphf == NULL) return NULL;
	//DEBUGP("Loading mphf algorithm dependent parts\n");

	switch (mphf->algo)
	{
		case CMPH_CHM:
			chm_load(mem, mphf);
			break;
		case CMPH_BMZ: /* included -- Fabiano */
			//DEBUGP("Loading bmz algorithm dependent parts\n");
			bmz_load(mem, mphf);
			break;
		case CMPH_BMZ8: /* included -- Fabiano */
			//DEBUGP("Loading bmz8 algorithm dependent parts\n");
			bmz8_load(mem, mphf);
			break;
		case CMPH_BRZ: /* included -- Fabiano */
			//DEBUGP("Loading brz algorithm dependent parts\n");
			brz_load(mem, mphf);
			break;
		case CMPH_FCH: /* included -- Fabiano */
			//DEBUGP("Loading fch algorithm dependent parts\n");
			fch_load(mem, mphf);
			break;
		case CMPH_BDZ: /* included -- Fabiano */
			//DEBUGP("Loading bdz algorithm dependent parts\n");
			bdz_load(mem, mphf);
			break;
		case CMPH_BDZ_PH: /* included -- Fabiano */
			//DEBUGP("Loading bdz_ph algorithm dependent parts\n");
			bdz_ph_load(mem, mphf);
			break;
		case CMPH_CHD_PH: /* included -- Fabiano */
			//DEBUGP("Loading chd_ph algorithm dependent parts\n");
			chd_ph_load(mem, mphf);
			break;
		case CMPH_CHD: /* included -- Fabiano */
			//DEBUGP("Loading chd algorithm dependent parts\n");
			chd_load(mem, mphf);
			break;
		default:
			assert(0);
	}
	//DEBUGP("Loaded mphf\n");
	return mphf;
}

cmph_uint32 cmph_search(cmph_t *mphf, const char *key, cmph_uint32 keylen)
{
	//DEBUGP("mphf algorithm: %u \n", mphf->algo);
	switch(mphf->algo)
	{
	case CMPH_CHM:
		return chm_search(mphf, key, keylen);
	case CMPH_BMZ: /* included -- Fabiano */
		//DEBUGP("bmz algorithm search\n");
		return bmz_search(mphf, key, keylen);
	case CMPH_BMZ8: /* included -- Fabiano */
		//DEBUGP("bmz8 algorithm search\n");
		return bmz8_search(mphf, key, keylen);
	case CMPH_BRZ: /* included -- Fabiano */
		//DEBUGP("brz algorithm search\n");
		return brz_search(mphf, key, keylen);
	case CMPH_FCH: /* included -- Fabiano */
		//DEBUGP("fch algorithm search\n");
		return fch_search(mphf, key, keylen);
	case CMPH_BDZ: /* included -- Fabiano */
		//DEBUGP("bdz algorithm search\n");
		return bdz_search(mphf, key, keylen);
	case CMPH_BDZ_PH: /* included -- Fabiano */
		//DEBUGP("bdz_ph algorithm search\n");
		return bdz_ph_search(mphf, key, keylen);
	case CMPH_CHD_PH: /* included -- Fabiano */
		//DEBUGP("chd_ph algorithm search\n");
		return chd_ph_search(mphf, key, keylen);
	case CMPH_CHD: /* included -- Fabiano */
		//DEBUGP("chd algorithm search\n");
		return chd_search(mphf, key, keylen);
	default:
		assert(0);
	}
	assert(0);
	return 0;
}

cmph_uint32 compressed_rank_query_packed(void * cr_packed, cmph_uint32 idx)
{
	// unpacking cr_packed
	register cmph_uint32 *ptr = (cmph_uint32 *)cr_packed;
	register cmph_uint32 max_val = *ptr++;
	register cmph_uint32 n = *ptr++;
	register cmph_uint32 rem_r = *ptr++;
	register cmph_uint32 buflen_sel = *ptr++;
	register cmph_uint32 * sel_packed = ptr;
	
	register cmph_uint32 * bits_vec = sel_packed + 2; // skipping n and m

	register cmph_uint32 * vals_rems = (ptr += (buflen_sel >> 2)); 

	// compressed sequence query computation
	register cmph_uint32 rems_mask;
	register cmph_uint32 val_quot, val_rem;
	register cmph_uint32 sel_res, rank;
	
	if(idx > max_val)
	{
		return n;
	}
	
	val_quot = idx >> rem_r; 	
	rems_mask = (1U << rem_r) - 1U; 
	val_rem = idx & rems_mask; 
	if(val_quot == 0)
	{
		rank = sel_res = 0;
	}
	else
	{
		sel_res = select_query_packed(sel_packed, val_quot - 1) + 1;
		rank = sel_res - val_quot;
	}
	
	do
	{
		if(GETBIT32(bits_vec, sel_res))
		{
			break;
		}
		if(get_bits_value(vals_rems, rank, rem_r, rems_mask) >= val_rem)
		{
			break;
		}
		sel_res++;
		rank++;
	} while(1);	
	
	return rank;
}

cmph_t *__cmph_load(Memory_IO *mem)
{
	cmph_t *mphf = NULL;
	cmph_uint32 i;
	char algo_name[BUFSIZ];
	char *ptr = algo_name;
	CMPH_ALGO algo = CMPH_COUNT;
	register size_t nbytes;

	//DEBUGP("Loading mphf\n");
	while(1)
	{
		size_t c = mread(ptr, (size_t)1, (size_t)1, mem);
		if (c != 1) return NULL;
		if (*ptr == 0) break;
		++ptr;
	}
	for(i = 0; i < CMPH_COUNT; ++i)
	{
		if (strcmp(algo_name, cmph_names[i]) == 0)
		{
			algo = (CMPH_ALGO)(i);
		}
	}
	if (algo == CMPH_COUNT)
	{
		DEBUGP("Algorithm %s not found\n", algo_name);
		return NULL;
	}
	mphf = (cmph_t *)malloc(sizeof(cmph_t));
	mphf->algo = algo;
	nbytes = mread(&(mphf->size), sizeof(mphf->size), (size_t)1, mem);
	mphf->data = NULL;
	//DEBUGP("Algorithm is %s and mphf is sized %u\n", cmph_names[algo],  mphf->size);

	return mphf;
}

void chm_load(Memory_IO *mem, cmph_t *mphf)
{
	cmph_uint32 nhashes;
	char *buf = NULL;
	cmph_uint32 buflen;
	cmph_uint32 i;
	chm_data_t *chm = (chm_data_t *)malloc(sizeof(chm_data_t));
	register size_t nbytes;
	//DEBUGP("Loading chm mphf\n");
	mphf->data = chm;
	nbytes = mread(&nhashes, sizeof(cmph_uint32), (size_t)1, mem);
	chm->hashes = (hash_state_t **)malloc(sizeof(hash_state_t *)*(nhashes + 1));
	chm->hashes[nhashes] = NULL;
	//DEBUGP("Reading %u hashes\n", nhashes);
	for (i = 0; i < nhashes; ++i)
	{
		hash_state_t *state = NULL;
		nbytes = mread(&buflen, sizeof(cmph_uint32), (size_t)1, mem);
		//DEBUGP("Hash state has %u bytes\n", buflen);
		buf = (char *)malloc((size_t)buflen);
		nbytes = mread(buf, (size_t)buflen, (size_t)1, mem);
		state = hash_state_load(buf, buflen);
		chm->hashes[i] = state;
		free(buf);
	}

	//DEBUGP("Reading m and n\n");
	nbytes = mread(&(chm->n), sizeof(cmph_uint32), (size_t)1, mem);
	nbytes = mread(&(chm->m), sizeof(cmph_uint32), (size_t)1, mem);

	chm->g = (cmph_uint32 *)malloc(sizeof(cmph_uint32)*chm->n);
	nbytes = mread(chm->g, chm->n*sizeof(cmph_uint32), (size_t)1, mem);
	#ifdef DEBUG
	fprintf(stderr, "G: ");
	for (i = 0; i < chm->n; ++i) fprintf(stderr, "%u ", chm->g[i]);
	fprintf(stderr, "\n");
	#endif
	return;
}

void bmz_load(Memory_IO *mem, cmph_t *mphf)
{
	cmph_uint32 nhashes;
	char *buf = NULL;
	cmph_uint32 buflen;
	cmph_uint32 i;
	bmz_data_t *bmz = (bmz_data_t *)malloc(sizeof(bmz_data_t));
	register size_t nbytes;
	//DEBUGP("Loading bmz mphf\n");
	mphf->data = bmz;
	nbytes = mread(&nhashes, sizeof(cmph_uint32), (size_t)1, mem);
	bmz->hashes = (hash_state_t **)malloc(sizeof(hash_state_t *)*(nhashes + 1));
	bmz->hashes[nhashes] = NULL;
	//DEBUGP("Reading %u hashes\n", nhashes);
	for (i = 0; i < nhashes; ++i)
	{
		hash_state_t *state = NULL;
		nbytes = mread(&buflen, sizeof(cmph_uint32), (size_t)1, mem);
		//DEBUGP("Hash state has %u bytes\n", buflen);
		buf = (char *)malloc((size_t)buflen);
		nbytes = mread(buf, (size_t)buflen, (size_t)1, mem);
		state = hash_state_load(buf, buflen);
		bmz->hashes[i] = state;
		free(buf);
	}

	//DEBUGP("Reading m and n\n");
	nbytes = mread(&(bmz->n), sizeof(cmph_uint32), (size_t)1, mem);
	nbytes = mread(&(bmz->m), sizeof(cmph_uint32), (size_t)1, mem);

	bmz->g = (cmph_uint32 *)malloc(sizeof(cmph_uint32)*bmz->n);
	nbytes = mread(bmz->g, bmz->n*sizeof(cmph_uint32), (size_t)1, mem);
	#ifdef DEBUG
	fprintf(stderr, "G: ");
	for (i = 0; i < bmz->n; ++i) fprintf(stderr, "%u ", bmz->g[i]);
	fprintf(stderr, "\n");
	#endif
	return;
}

void bmz8_load(Memory_IO *mem, cmph_t *mphf)
{
	cmph_uint8 nhashes;
	char *buf = NULL;
	cmph_uint32 buflen;
	cmph_uint8 i;
	register size_t nbytes;
	bmz8_data_t *bmz8 = (bmz8_data_t *)malloc(sizeof(bmz8_data_t));

	//DEBUGP("Loading bmz8 mphf\n");
	mphf->data = bmz8;
	nbytes = mread(&nhashes, sizeof(cmph_uint8), (size_t)1, mem);
	bmz8->hashes = (hash_state_t **)malloc(sizeof(hash_state_t *)*(size_t)(nhashes + 1));
	bmz8->hashes[nhashes] = NULL;
	//DEBUGP("Reading %u hashes\n", nhashes);
	for (i = 0; i < nhashes; ++i)
	{
		hash_state_t *state = NULL;
		nbytes = mread(&buflen, sizeof(cmph_uint32), (size_t)1, mem);
		//DEBUGP("Hash state has %u bytes\n", buflen);
		buf = (char *)malloc((size_t)buflen);
		nbytes = mread(buf, (size_t)buflen, (size_t)1, mem);
		state = hash_state_load(buf, buflen);
		bmz8->hashes[i] = state;
		free(buf);
	}

	//DEBUGP("Reading m and n\n");
	nbytes = mread(&(bmz8->n), sizeof(cmph_uint8), (size_t)1, mem);
	nbytes = mread(&(bmz8->m), sizeof(cmph_uint8), (size_t)1, mem);

	bmz8->g = (cmph_uint8 *)malloc(sizeof(cmph_uint8)*bmz8->n);
	nbytes = mread(bmz8->g, bmz8->n*sizeof(cmph_uint8), (size_t)1, mem);
	#ifdef DEBUG
	fprintf(stderr, "G: ");
	for (i = 0; i < bmz8->n; ++i) fprintf(stderr, "%u ", bmz8->g[i]);
	fprintf(stderr, "\n");
	#endif
	return;
}

void brz_load(Memory_IO* mem, cmph_t *mphf)
{
	char *buf = NULL;
	cmph_uint32 buflen;
	register size_t nbytes;
	cmph_uint32 i, n;
	brz_data_t *brz = (brz_data_t *)malloc(sizeof(brz_data_t));

	//DEBUGP("Loading brz mphf\n");
	mphf->data = brz;
	nbytes = mread(&(brz->c), sizeof(double), (size_t)1, mem);
	nbytes = mread(&(brz->algo), sizeof(brz->algo), (size_t)1, mem); // Reading algo.
	nbytes = mread(&(brz->k), sizeof(cmph_uint32), (size_t)1, mem);
	brz->size   = (cmph_uint8 *) malloc(sizeof(cmph_uint8)*brz->k);
	nbytes = mread(brz->size, sizeof(cmph_uint8)*(brz->k), (size_t)1, mem);
	brz->h1 = (hash_state_t **)malloc(sizeof(hash_state_t *)*brz->k);
	brz->h2 = (hash_state_t **)malloc(sizeof(hash_state_t *)*brz->k);
	brz->g  = (cmph_uint8 **)  calloc((size_t)brz->k, sizeof(cmph_uint8 *));
	//DEBUGP("Reading c = %f   k = %u   algo = %u \n", brz->c, brz->k, brz->algo);
	//loading h_i1, h_i2 and g_i.
	for(i = 0; i < brz->k; i++)
	{
		// h1
		nbytes = mread(&buflen, sizeof(cmph_uint32), (size_t)1, mem);
		//DEBUGP("Hash state 1 has %u bytes\n", buflen);
		buf = (char *)malloc((size_t)buflen);
		nbytes = mread(buf, (size_t)buflen, (size_t)1, mem);
		brz->h1[i] = hash_state_load(buf, buflen);
		free(buf);
		//h2
		nbytes = mread(&buflen, sizeof(cmph_uint32), (size_t)1, mem);
		//DEBUGP("Hash state 2 has %u bytes\n", buflen);
		buf = (char *)malloc((size_t)buflen);
		nbytes = mread(buf, (size_t)buflen, (size_t)1, mem);
		brz->h2[i] = hash_state_load(buf, buflen);
		free(buf);
		switch(brz->algo)
		{
			case CMPH_FCH:
				n = fch_calc_b(brz->c, brz->size[i]);
				break;
			case CMPH_BMZ8:
				n = (cmph_uint32)ceil(brz->c * brz->size[i]);
				break;
			default: assert(0);
		}
		//DEBUGP("g_i has %u bytes\n", n);
		brz->g[i] = (cmph_uint8 *)calloc((size_t)n, sizeof(cmph_uint8));
		nbytes = mread(brz->g[i], sizeof(cmph_uint8)*n, (size_t)1, mem);
	}
	//loading h0
	nbytes = mread(&buflen, sizeof(cmph_uint32), (size_t)1, mem);
	//DEBUGP("Hash state has %u bytes\n", buflen);
	buf = (char *)malloc((size_t)buflen);
	nbytes = mread(buf, (size_t)buflen, (size_t)1, mem);
	brz->h0 = hash_state_load(buf, buflen);
	free(buf);

	//loading c, m, and the vector offset.
	nbytes = mread(&(brz->m), sizeof(cmph_uint32), (size_t)1, mem);
	brz->offset = (cmph_uint32 *)malloc(sizeof(cmph_uint32)*brz->k);
	nbytes = mread(brz->offset, sizeof(cmph_uint32)*(brz->k), (size_t)1, mem);
	return;
}

void fch_load(Memory_IO *mem, cmph_t *mphf)
{
	char *buf = NULL;
	cmph_uint32 buflen;
	register size_t nbytes;
	fch_data_t *fch = (fch_data_t *)malloc(sizeof(fch_data_t));

	//DEBUGP("Loading fch mphf\n");
	mphf->data = fch;
	//DEBUGP("Reading h1\n");
	fch->h1 = NULL;
	nbytes = mread(&buflen, sizeof(cmph_uint32), (size_t)1, mem);
	//DEBUGP("Hash state of h1 has %u bytes\n", buflen);
	buf = (char *)malloc((size_t)buflen);
	nbytes = mread(buf, (size_t)buflen, (size_t)1, mem);
	fch->h1 = hash_state_load(buf, buflen);
	free(buf);

	//DEBUGP("Loading fch mphf\n");
	mphf->data = fch;
	//DEBUGP("Reading h2\n");
	fch->h2 = NULL;
	nbytes = mread(&buflen, sizeof(cmph_uint32), (size_t)1, mem);
	//DEBUGP("Hash state of h2 has %u bytes\n", buflen);
	buf = (char *)malloc((size_t)buflen);
	nbytes = mread(buf, (size_t)buflen, (size_t)1, mem);
	fch->h2 = hash_state_load(buf, buflen);
	free(buf);


	//DEBUGP("Reading m and n\n");
	nbytes = mread(&(fch->m), sizeof(cmph_uint32), (size_t)1, mem);
	nbytes = mread(&(fch->c), sizeof(double), (size_t)1, mem);
	nbytes = mread(&(fch->b), sizeof(cmph_uint32), (size_t)1, mem);
	nbytes = mread(&(fch->p1), sizeof(double), (size_t)1, mem);
	nbytes = mread(&(fch->p2), sizeof(double), (size_t)1, mem);

	fch->g = (cmph_uint32 *)malloc(sizeof(cmph_uint32)*fch->b);
	nbytes = mread(fch->g, fch->b*sizeof(cmph_uint32), (size_t)1, mem);
	#ifdef DEBUG
	cmph_uint32 i;
	fprintf(stderr, "G: ");
	for (i = 0; i < fch->b; ++i) fprintf(stderr, "%u ", fch->g[i]);
	fprintf(stderr, "\n");
	#endif
	return;
}


void bdz_load(Memory_IO *mem, cmph_t *mphf)
{
	char *buf = NULL;
	cmph_uint32 buflen, sizeg;
	register size_t nbytes;
	bdz_data_t *bdz = (bdz_data_t *)malloc(sizeof(bdz_data_t));

	//DEBUGP("Loading bdz mphf\n");
	mphf->data = bdz;

	nbytes = mread(&buflen, sizeof(cmph_uint32), (size_t)1, mem);
	//DEBUGP("Hash state has %u bytes\n", buflen);
	buf = (char *)malloc((size_t)buflen);
	nbytes = mread(buf, (size_t)buflen, (size_t)1, mem);
	bdz->hl = hash_state_load(buf, buflen);
	free(buf);


	//DEBUGP("Reading m and n\n");
	nbytes = mread(&(bdz->n), sizeof(cmph_uint32), (size_t)1, mem);
	nbytes = mread(&(bdz->m), sizeof(cmph_uint32), (size_t)1, mem);
	nbytes = mread(&(bdz->r), sizeof(cmph_uint32), (size_t)1, mem);
	sizeg = (cmph_uint32)ceil(bdz->n/4.0);
	bdz->g = (cmph_uint8 *)calloc((size_t)(sizeg), sizeof(cmph_uint8));
	nbytes = mread(bdz->g, sizeg*sizeof(cmph_uint8), (size_t)1, mem);

	nbytes = mread(&(bdz->k), sizeof(cmph_uint32), (size_t)1, mem);
	nbytes = mread(&(bdz->b), sizeof(cmph_uint8), (size_t)1, mem);
	nbytes = mread(&(bdz->ranktablesize), sizeof(cmph_uint32), (size_t)1, mem);

	bdz->ranktable = (cmph_uint32 *)calloc((size_t)bdz->ranktablesize, sizeof(cmph_uint32));
	nbytes = mread(bdz->ranktable, sizeof(cmph_uint32)*(bdz->ranktablesize), (size_t)1, mem);

	#ifdef DEBUG
	cmph_uint32  i = 0;
	fprintf(stderr, "G: ");
	for (i = 0; i < bdz->n; ++i) fprintf(stderr, "%u ", GETVALUE(bdz->g,i));
	fprintf(stderr, "\n");
	#endif
	return;
}

void bdz_ph_load(Memory_IO *mem, cmph_t *mphf)
{
	char *buf = NULL;
	cmph_uint32 buflen;
	cmph_uint32 sizeg = 0;
	register size_t nbytes;
	bdz_ph_data_t *bdz_ph = (bdz_ph_data_t *)malloc(sizeof(bdz_ph_data_t));

	//DEBUGP("Loading bdz_ph mphf\n");
	mphf->data = bdz_ph;

	nbytes = mread(&buflen, sizeof(cmph_uint32), (size_t)1, mem);
	//DEBUGP("Hash state has %u bytes\n", buflen);
	buf = (char *)malloc((size_t)buflen);
	nbytes = mread(buf, (size_t)buflen, (size_t)1, mem);
	bdz_ph->hl = hash_state_load(buf, buflen);
	free(buf);


	//DEBUGP("Reading m and n\n");
	nbytes = mread(&(bdz_ph->n), sizeof(cmph_uint32), (size_t)1, mem);
	nbytes = mread(&(bdz_ph->m), sizeof(cmph_uint32), (size_t)1, mem);
	nbytes = mread(&(bdz_ph->r), sizeof(cmph_uint32), (size_t)1, mem);
	sizeg = (cmph_uint32)ceil(bdz_ph->n/5.0);
	bdz_ph->g = (cmph_uint8 *)calloc((size_t)sizeg, sizeof(cmph_uint8));
	nbytes = mread(bdz_ph->g, sizeg*sizeof(cmph_uint8), (size_t)1, mem);

	return;
}

void chd_ph_load(Memory_IO *mem, cmph_t *mphf)
{
	char *buf = NULL;
	cmph_uint32 buflen;
	register size_t nbytes;
	chd_ph_data_t *chd_ph = (chd_ph_data_t *)malloc(sizeof(chd_ph_data_t));

	DEBUGP("Loading chd_ph mphf\n");
	mphf->data = chd_ph;

	nbytes = mread(&buflen, sizeof(cmph_uint32), (size_t)1, mem);
	DEBUGP("Hash state has %u bytes\n", buflen);
	buf = (char *)malloc((size_t)buflen);
	nbytes = mread(buf, (size_t)buflen, (size_t)1, mem);
	chd_ph->hl = hash_state_load(buf, buflen);
	free(buf);

	nbytes = mread(&buflen, sizeof(cmph_uint32), (size_t)1, mem);
	DEBUGP("Compressed sequence structure has %u bytes\n", buflen);
	buf = (char *)malloc((size_t)buflen);
	nbytes = mread(buf, (size_t)buflen, (size_t)1, mem);
	chd_ph->cs = (compressed_seq_t *) calloc(1, sizeof(compressed_seq_t));
	compressed_seq_load(chd_ph->cs, buf, buflen);
	free(buf);

	// loading n and nbuckets
	DEBUGP("Reading n and nbuckets\n");
	nbytes = mread(&(chd_ph->n), sizeof(cmph_uint32), (size_t)1, mem);
	nbytes = mread(&(chd_ph->nbuckets), sizeof(cmph_uint32), (size_t)1, mem);
}

void chd_load(Memory_IO *mem, cmph_t *mphf)
{
	register size_t nbytes;
	chd_data_t *chd = (chd_data_t *)malloc(sizeof(chd_data_t));

	DEBUGP("Loading chd mphf\n");
	mphf->data = chd;

	nbytes = mread(&chd->packed_chd_phf_size, sizeof(cmph_uint32), (size_t)1, mem);
	DEBUGP("Loading CHD_PH perfect hash function with %u bytes to disk\n", chd->packed_chd_phf_size);
	chd->packed_chd_phf = (cmph_uint8 *) calloc((size_t)chd->packed_chd_phf_size,(size_t)1);
	nbytes = mread(chd->packed_chd_phf, chd->packed_chd_phf_size, (size_t)1, mem);

	nbytes = mread(&chd->packed_cr_size, sizeof(cmph_uint32), (size_t)1, mem);
	DEBUGP("Loading Compressed rank structure, which has %u bytes\n", chd->packed_cr_size);
	chd->packed_cr = (cmph_uint8 *) calloc((size_t)chd->packed_cr_size, (size_t)1);
	nbytes = mread(chd->packed_cr, chd->packed_cr_size, (size_t)1, mem);
}

//perfect hash search functions
cmph_uint32 chm_search(cmph_t *mphf, const char *key, cmph_uint32 keylen)
{
	chm_data_t *chm = (chm_data_t *)mphf->data;
	cmph_uint32 h1 = hash(chm->hashes[0], key, keylen) % chm->n;
	cmph_uint32 h2 = hash(chm->hashes[1], key, keylen) % chm->n;
	DEBUGP("key: %s h1: %u h2: %u\n", key, h1, h2);
	if (h1 == h2 && ++h2 >= chm->n) h2 = 0;
	DEBUGP("key: %s g[h1]: %u g[h2]: %u edges: %u\n", key, chm->g[h1], chm->g[h2], chm->m);
	return (chm->g[h1] + chm->g[h2]) % chm->m;
}

cmph_uint32 bmz_search(cmph_t *mphf, const char *key, cmph_uint32 keylen)
{
	bmz_data_t *bmz = (bmz_data_t *)mphf->data;
	cmph_uint32 h1 = hash(bmz->hashes[0], key, keylen) % bmz->n;
	cmph_uint32 h2 = hash(bmz->hashes[1], key, keylen) % bmz->n;
	DEBUGP("key: %.*s h1: %u h2: %u\n", keylen, key, h1, h2);
	if (h1 == h2 && ++h2 > bmz->n) h2 = 0;
	DEBUGP("key: %.*s g[h1]: %u g[h2]: %u edges: %u\n", keylen, key, bmz->g[h1], bmz->g[h2], bmz->m);
	return bmz->g[h1] + bmz->g[h2];
}

cmph_uint8 bmz8_search(cmph_t *mphf, const char *key, cmph_uint32 keylen)
{
	bmz8_data_t *bmz8 = (bmz8_data_t *)mphf->data;
	cmph_uint8 h1 = (cmph_uint8)(hash(bmz8->hashes[0], key, keylen) % bmz8->n);
	cmph_uint8 h2 = (cmph_uint8)(hash(bmz8->hashes[1], key, keylen) % bmz8->n);
	DEBUGP("key: %s h1: %u h2: %u\n", key, h1, h2);
	if (h1 == h2 && ++h2 > bmz8->n) h2 = 0;
	DEBUGP("key: %s g[h1]: %u g[h2]: %u edges: %u\n", key, bmz8->g[h1], bmz8->g[h2], bmz8->m);
	return (cmph_uint8)(bmz8->g[h1] + bmz8->g[h2]);
}

cmph_uint32 brz_search(cmph_t *mphf, const char *key, cmph_uint32 keylen)
{
	brz_data_t *brz = (brz_data_t *)mphf->data;
	cmph_uint32 fingerprint[3];
	switch(brz->algo)
	{
		case CMPH_FCH:
			return brz_fch_search(brz, key, keylen, fingerprint);
		case CMPH_BMZ8:
			return brz_bmz8_search(brz, key, keylen, fingerprint);
		default: assert(0);
	}
	return 0;
}

cmph_uint32 fch_search(cmph_t *mphf, const char *key, cmph_uint32 keylen)
{
	fch_data_t *fch = (fch_data_t *)mphf->data;
	cmph_uint32 h1 = hash(fch->h1, key, keylen) % fch->m;
	cmph_uint32 h2 = hash(fch->h2, key, keylen) % fch->m;
	h1 = mixh10h11h12 (fch->b, fch->p1, fch->p2, h1);
	//DEBUGP("key: %s h1: %u h2: %u  g[h1]: %u\n", key, h1, h2, fch->g[h1]);
	return (h2 + fch->g[h1]) % fch->m;
}

cmph_uint32 bdz_search(cmph_t *mphf, const char *key, cmph_uint32 keylen)
{
	register cmph_uint32 vertex;
	register bdz_data_t *bdz = (bdz_data_t *)mphf->data;
	cmph_uint32 hl[3];
	hash_vector(bdz->hl, key, keylen, hl);
	hl[0] = hl[0] % bdz->r;
	hl[1] = hl[1] % bdz->r + bdz->r;
	hl[2] = hl[2] % bdz->r + (bdz->r << 1);
	vertex = hl[(GETVALUE(bdz->g, hl[0]) + GETVALUE(bdz->g, hl[1]) + GETVALUE(bdz->g, hl[2])) % 3];
        DEBUGP("Search found vertex %u\n", vertex);
	return rank(bdz->b, bdz->ranktable, bdz->g, vertex);
}

cmph_uint32 bdz_ph_search(cmph_t *mphf, const char *key, cmph_uint32 keylen)
{
	register bdz_ph_data_t *bdz_ph = (bdz_ph_data_t *)mphf->data;
	cmph_uint32 hl[3];
	register cmph_uint8 byte0, byte1, byte2;
	register cmph_uint32 vertex;

	hash_vector(bdz_ph->hl, key, keylen,hl);
	hl[0] = hl[0] % bdz_ph->r;
	hl[1] = hl[1] % bdz_ph->r + bdz_ph->r;
	hl[2] = hl[2] % bdz_ph->r + (bdz_ph->r << 1);

	byte0 = bdz_ph->g[hl[0]/5];
	byte1 = bdz_ph->g[hl[1]/5];
	byte2 = bdz_ph->g[hl[2]/5];

	byte0 = lookup_table[hl[0]%5U][byte0];
	byte1 = lookup_table[hl[1]%5U][byte1];
	byte2 = lookup_table[hl[2]%5U][byte2];
	vertex = hl[(byte0 + byte1 + byte2)%3];

	return vertex;
}

cmph_uint32 chd_ph_search(cmph_t *mphf, const char *key, cmph_uint32 keylen)
{
	register chd_ph_data_t * chd_ph = (chd_ph_data_t *)mphf->data;
	cmph_uint32 hl[3];
	register cmph_uint32 disp,position;
	register cmph_uint32 probe0_num,probe1_num;
	register cmph_uint32 f,g,h;
	hash_vector(chd_ph->hl, key, keylen, hl);
	g = hl[0] % chd_ph->nbuckets;
	f = hl[1] % chd_ph->n;
	h = hl[2] % (chd_ph->n-1) + 1;

	disp = compressed_seq_query(chd_ph->cs, g);
	probe0_num = disp % chd_ph->n;
	probe1_num = disp/chd_ph->n;
	position = (cmph_uint32)((f + ((cmph_uint64 )h)*probe0_num + probe1_num) % chd_ph->n);
	return position;
}

cmph_uint32 chd_search(cmph_t *mphf, const char *key, cmph_uint32 keylen)
{
	register chd_data_t * chd = (chd_data_t *)mphf->data;
	return _chd_search(chd->packed_chd_phf, chd->packed_cr, key, keylen);
}
//end of perfect hash search functions

hash_state_t *hash_state_load(const char *buf, cmph_uint32 buflen)
{
	cmph_uint32 i;
	cmph_uint32 offset;
	CMPH_HASH hashfunc = CMPH_HASH_COUNT;
	for (i = 0; i < CMPH_HASH_COUNT; ++i)
	{
		if (strcmp(buf, cmph_hash_names[i]) == 0)
		{
			hashfunc = (CMPH_HASH)(i);
			break;
		}
	}
	if (hashfunc == CMPH_HASH_COUNT) return NULL;
	offset = (cmph_uint32)strlen(cmph_hash_names[hashfunc]) + 1;
	switch (hashfunc)
	{
		case CMPH_HASH_JENKINS:
			return (hash_state_t *)jenkins_state_load(buf + offset, buflen - offset);
		default:
			return NULL;
	}
	return NULL;
}

jenkins_state_t *jenkins_state_load(const char *buf, cmph_uint32 buflen)
{
	jenkins_state_t *state = (jenkins_state_t *)malloc(sizeof(jenkins_state_t));
	state->seed = *(cmph_uint32 *)buf;
	state->hashfunc = CMPH_HASH_JENKINS;
	//DEBUGP("Loaded jenkins state with seed %u\n", state->seed);
	return state;
}

cmph_uint32 fch_calc_b(double c, cmph_uint32 m)
{
	return (cmph_uint32)ceil((c*m)/(log((double)m)/log(2.0) + 1));
}


void compressed_seq_load(compressed_seq_t * cs, const char * buf, cmph_uint32 buflen)
{
	register cmph_uint32 pos = 0;
	cmph_uint32 buflen_sel = 0;
	register cmph_uint32 length_rems_size = 0;
	register cmph_uint32 store_table_size = 0;
	
	// loading n, rem_r and total_length
	memcpy(&(cs->n), buf, sizeof(cmph_uint32));
	pos += (cmph_uint32)sizeof(cmph_uint32);
	DEBUGP("n = %u\n", cs->n);

	memcpy(&(cs->rem_r), buf + pos, sizeof(cmph_uint32));
	pos += (cmph_uint32)sizeof(cmph_uint32);
	DEBUGP("rem_r = %u\n", cs->rem_r);

	memcpy(&(cs->total_length), buf + pos, sizeof(cmph_uint32));
	pos += (cmph_uint32)sizeof(cmph_uint32);
	DEBUGP("total_length = %u\n", cs->total_length);
	
	// loading sel
	memcpy(&buflen_sel, buf + pos, sizeof(cmph_uint32));
	pos += (cmph_uint32)sizeof(cmph_uint32);
	DEBUGP("buflen_sel = %u\n", buflen_sel);

	select_load(&cs->sel, buf + pos, buflen_sel);
	#ifdef DEBUG	
	cmph_uint32 i = 0;  
	for(i = 0; i < buflen_sel; i++)
	{
	    DEBUGP("pos = %u  -- buf_sel[%u] = %u\n", pos, i, *(buf + pos + i));
	}
	#endif
	pos += buflen_sel;
	
	// loading length_rems
	if(cs->length_rems)
	{
		free(cs->length_rems);
	}
	length_rems_size = BITS_TABLE_SIZE(cs->n, cs->rem_r);
	cs->length_rems = (cmph_uint32 *) calloc(length_rems_size, sizeof(cmph_uint32));
	length_rems_size *= 4;
	memcpy(cs->length_rems, buf + pos, length_rems_size);
	
	#ifdef DEBUG	
	for(i = 0; i < length_rems_size; i++)
	{
	    DEBUGP("pos = %u -- length_rems_size = %u  -- length_rems[%u] = %u\n", pos, length_rems_size, i, *(buf + pos + i));
	}
	#endif
	pos += length_rems_size;

	// loading store_table
	store_table_size = ((cs->total_length + 31) >> 5);
	if(cs->store_table)
	{
		free(cs->store_table);
	}
	cs->store_table = (cmph_uint32 *) calloc(store_table_size, sizeof(cmph_uint32));
        store_table_size *= 4;
	memcpy(cs->store_table, buf + pos, store_table_size);
	
	#ifdef DEBUG	
	for(i = 0; i < store_table_size; i++)
	{
	    DEBUGP("pos = %u -- store_table_size = %u  -- store_table[%u] = %u\n", pos, store_table_size, i, *(buf + pos + i));
	}
	#endif

	DEBUGP("Loaded compressed sequence structure with size %u bytes\n", buflen);
}

void select_load(select_t * sel, const char *buf, cmph_uint32 buflen)
{
	register cmph_uint32 pos = 0;
        register cmph_uint32 nbits = 0;
	register cmph_uint32 vec_size = 0;
	register cmph_uint32 sel_table_size = 0;
	
	memcpy(&(sel->n), buf, sizeof(cmph_uint32));
	pos += (cmph_uint32)sizeof(cmph_uint32);
	memcpy(&(sel->m), buf + pos, sizeof(cmph_uint32));
	pos += (cmph_uint32)sizeof(cmph_uint32);
	
	nbits = sel->n + sel->m;
	vec_size = ((nbits + 31) >> 5) * (cmph_uint32)sizeof(cmph_uint32); // (nbits + 31) >> 5 = (nbits + 31)/32
	sel_table_size = ((sel->n >> NBITS_STEP_SELECT_TABLE) + 1) * (cmph_uint32)sizeof(cmph_uint32); // (sel->n >> NBITS_STEP_SELECT_TABLE) = (sel->n/STEP_SELECT_TABLE)
	
	if(sel->bits_vec) 
	{
		free(sel->bits_vec);
	}
	sel->bits_vec = (cmph_uint32 *)calloc(vec_size/sizeof(cmph_uint32), sizeof(cmph_uint32));

	if(sel->select_table) 
	{
		free(sel->select_table);
	}
	sel->select_table = (cmph_uint32 *)calloc(sel_table_size/sizeof(cmph_uint32), sizeof(cmph_uint32));

	memcpy(sel->bits_vec, buf + pos, vec_size);
	pos += vec_size;
	memcpy(sel->select_table, buf + pos, sel_table_size);
	
	DEBUGP("Loaded select structure with size %u bytes\n", buflen);
}

cmph_uint32 hash(hash_state_t *state, const char *key, cmph_uint32 keylen)
{
	switch (state->hashfunc)
	{
		case CMPH_HASH_JENKINS:
			return jenkins_hash((jenkins_state_t *)state, key, keylen);
		default:
			assert(0);
	}
	assert(0);
	return 0;
}

cmph_uint32 jenkins_hash(jenkins_state_t *state, const char *k, cmph_uint32 keylen)
{
	cmph_uint32 hashes[3];
	__jenkins_hash_vector(state->seed, k, keylen, hashes);
	return hashes[2];
/*	cmph_uint32 a, b, c;
	cmph_uint32 len, length;

	// Set up the internal state
	length = keylen;
	len = length;
	a = b = 0x9e3779b9;  // the golden ratio; an arbitrary value
	c = state->seed;   // the previous hash value - seed in our case

	// handle most of the key
	while (len >= 12)
	{
		a += (k[0] +((cmph_uint32)k[1]<<8) +((cmph_uint32)k[2]<<16) +((cmph_uint32)k[3]<<24));
		b += (k[4] +((cmph_uint32)k[5]<<8) +((cmph_uint32)k[6]<<16) +((cmph_uint32)k[7]<<24));
		c += (k[8] +((cmph_uint32)k[9]<<8) +((cmph_uint32)k[10]<<16)+((cmph_uint32)k[11]<<24));
		mix(a,b,c);
		k += 12; len -= 12;
	}

	// handle the last 11 bytes
	c  += length;
	switch(len)              /// all the case statements fall through
	{
		case 11:
			c +=((cmph_uint32)k[10]<<24);
		case 10:
			c +=((cmph_uint32)k[9]<<16);
		case 9 :
			c +=((cmph_uint32)k[8]<<8);
			// the first byte of c is reserved for the length
		case 8 :
			b +=((cmph_uint32)k[7]<<24);
		case 7 :
			b +=((cmph_uint32)k[6]<<16);
		case 6 :
			b +=((cmph_uint32)k[5]<<8);
		case 5 :
			b +=k[4];
		case 4 :
			a +=((cmph_uint32)k[3]<<24);
		case 3 :
			a +=((cmph_uint32)k[2]<<16);
		case 2 :
			a +=((cmph_uint32)k[1]<<8);
		case 1 :
			a +=k[0];
		// case 0: nothing left to add
	}

	mix(a,b,c);

	/// report the result

	return c;
	*/
}

static cmph_uint32 brz_fch_search(brz_data_t *brz, const char *key, cmph_uint32 keylen, cmph_uint32 * fingerprint)
{
	register cmph_uint32 h0;

	hash_vector(brz->h0, key, keylen, fingerprint);
	h0 = fingerprint[2] % brz->k;

	register cmph_uint32 m = brz->size[h0];
	register cmph_uint32 b = fch_calc_b(brz->c, m);
	register double p1 = fch_calc_p1(m);
	register double p2 = fch_calc_p2(b);
	register cmph_uint32 h1 = hash(brz->h1[h0], key, keylen) % m;
	register cmph_uint32 h2 = hash(brz->h2[h0], key, keylen) % m;
	register cmph_uint8 mphf_bucket = 0;
	h1 = mixh10h11h12(b, p1, p2, h1);
	mphf_bucket = (cmph_uint8)((h2 + brz->g[h0][h1]) % m);
	return (mphf_bucket + brz->offset[h0]);
}

static cmph_uint32 brz_bmz8_search(brz_data_t *brz, const char *key, cmph_uint32 keylen, cmph_uint32 * fingerprint)
{
	register cmph_uint32 h0;

	hash_vector(brz->h0, key, keylen, fingerprint);
	h0 = fingerprint[2] % brz->k;

	register cmph_uint32 m = brz->size[h0];
	register cmph_uint32 n = (cmph_uint32)ceil(brz->c * m);
	register cmph_uint32 h1 = hash(brz->h1[h0], key, keylen) % n;
	register cmph_uint32 h2 = hash(brz->h2[h0], key, keylen) % n;
	register cmph_uint8 mphf_bucket;

	if (h1 == h2 && ++h2 >= n) h2 = 0;
	mphf_bucket = (cmph_uint8)(brz->g[h0][h1] + brz->g[h0][h2]);
	DEBUGP("key: %s h1: %u h2: %u h0: %u\n", key, h1, h2, h0);
	DEBUGP("key: %s g[h1]: %u g[h2]: %u offset[h0]: %u edges: %u\n", key, brz->g[h0][h1], brz->g[h0][h2], brz->offset[h0], brz->m);
	DEBUGP("Address: %u\n", mphf_bucket + brz->offset[h0]);
	return (mphf_bucket + brz->offset[h0]);
}

static inline cmph_uint32 rank(cmph_uint32 b, cmph_uint32 * ranktable, cmph_uint8 * g, cmph_uint32 vertex)
{
	register cmph_uint32 index = vertex >> b;
	register cmph_uint32 base_rank = ranktable[index];
	register cmph_uint32 beg_idx_v = index << b;
	register cmph_uint32 beg_idx_b = beg_idx_v >> 2;
	register cmph_uint32 end_idx_b = vertex >> 2;
	while(beg_idx_b < end_idx_b)
	{
		base_rank += bdz_lookup_table[*(g + beg_idx_b++)];

	}
        DEBUGP("base rank %u\n", base_rank);
	beg_idx_v = beg_idx_b << 2;
        DEBUGP("beg_idx_v %u\n", beg_idx_v);
	while(beg_idx_v < vertex)
	{
		if(GETVALUE(g, beg_idx_v) != UNASSIGNED) base_rank++;
		beg_idx_v++;
	}

	return base_rank;
}

void hash_vector(hash_state_t *state, const char *key, cmph_uint32 keylen, cmph_uint32 * hashes)
{
	switch (state->hashfunc)
	{
		case CMPH_HASH_JENKINS:
			jenkins_hash_vector_((jenkins_state_t *)state, key, keylen, hashes);
			break;
		default:
			assert(0);
	}
}

void jenkins_hash_vector_(jenkins_state_t *state, const char *k, cmph_uint32 keylen, cmph_uint32 * hashes)
{
	__jenkins_hash_vector(state->seed, k, keylen, hashes);
}

double fch_calc_p1(cmph_uint32 m)
{
	return ceil(0.55*m);
}

double fch_calc_p2(cmph_uint32 b)
{
	return ceil(0.3*b);
}

cmph_uint32 mixh10h11h12(cmph_uint32 b, double p1, double p2, cmph_uint32 initial_index)
{
	register cmph_uint32 int_p2 = (cmph_uint32)p2;
	if (initial_index < p1 && int_p2 != 0)  initial_index %= int_p2;  /* h11 o h10 , condition int_p2 != 0 added by cf*/
	else { /* h12 o h10 */
		initial_index %= b;
		if(initial_index < p2) initial_index += int_p2;
	}
	return initial_index;
}

cmph_uint32 compressed_seq_query(compressed_seq_t * cs, cmph_uint32 idx)
{
	register cmph_uint32 enc_idx, enc_length;
	register cmph_uint32 rems_mask;
	register cmph_uint32 stored_value;
	register cmph_uint32 sel_res;

	assert(idx < cs->n); // FABIANO ADDED

	rems_mask = (1U << cs->rem_r) - 1U;
	
	if(idx == 0)
	{
		enc_idx = 0;
		sel_res = select_query(&cs->sel, idx);
	}
	else
	{
		sel_res = select_query(&cs->sel, idx - 1);
		
		enc_idx = (sel_res - (idx - 1)) << cs->rem_r;
		enc_idx += get_bits_value(cs->length_rems, idx-1, cs->rem_r, rems_mask);
		
		sel_res = select_next_query(&cs->sel, sel_res);
	};

	enc_length = (sel_res - idx) << cs->rem_r;
	enc_length += get_bits_value(cs->length_rems, idx, cs->rem_r, rems_mask);
	enc_length -= enc_idx;
	if(enc_length == 0)
		return 0;
		
	stored_value = get_bits_at_pos(cs->store_table, enc_idx, enc_length);
	return stored_value + ((1U << enc_length) - 1U);
}

cmph_uint32 select_query(select_t * sel, cmph_uint32 one_idx)
{
	return _select_query((cmph_uint8 *)sel->bits_vec, sel->select_table, one_idx);
}

cmph_uint32 select_next_query(select_t * sel, cmph_uint32 vec_bit_idx)
{
	return _select_next_query((cmph_uint8 *)sel->bits_vec, vec_bit_idx);
}

/** cmph_uint32 cmph_search(void *packed_mphf, const char *key, cmph_uint32 keylen);
 *  \brief Use the packed mphf to do a search.
 *  \param  packed_mphf pointer to the packed mphf
 *  \param key key to be hashed
 *  \param keylen key legth in bytes
 *  \return The mphf value
 */
cmph_uint32 cmph_search_packed(void *packed_mphf, const char *key, cmph_uint32 keylen)
{
	cmph_uint32 *ptr = (cmph_uint32 *)packed_mphf;
//	fprintf(stderr, "algo:%u\n", *ptr);
	switch(*ptr)
	{
		case CMPH_CHM:
			return chm_search_packed(++ptr, key, keylen);
		case CMPH_BMZ: /* included -- Fabiano */
			return bmz_search_packed(++ptr, key, keylen);
		case CMPH_BMZ8: /* included -- Fabiano */
			return bmz8_search_packed(++ptr, key, keylen);
		case CMPH_BRZ: /* included -- Fabiano */
			return brz_search_packed(++ptr, key, keylen);
		case CMPH_FCH: /* included -- Fabiano */
			return fch_search_packed(++ptr, key, keylen);
		case CMPH_BDZ: /* included -- Fabiano */
			return bdz_search_packed(++ptr, key, keylen);
		case CMPH_BDZ_PH: /* included -- Fabiano */
			return bdz_ph_search_packed(++ptr, key, keylen);
		case CMPH_CHD_PH: /* included -- Fabiano */
			return chd_ph_search_packed(++ptr, key, keylen);
		case CMPH_CHD: /* included -- Fabiano */
			return chd_search_packed(++ptr, key, keylen);
		default:
			assert(0);
	}
	return 0; // FAILURE
}

cmph_uint32 chm_search_packed(void *packed_mphf, const char *key, cmph_uint32 keylen)
{
	register cmph_uint8 *h1_ptr = (cmph_uint8 *)packed_mphf;
	register CMPH_HASH h1_type  = (CMPH_HASH)(*((cmph_uint32 *)h1_ptr));
	h1_ptr += 4;

	register cmph_uint8 *h2_ptr = h1_ptr + hash_state_packed_size(h1_type);
	register CMPH_HASH h2_type  = (CMPH_HASH)(*((cmph_uint32 *)h2_ptr));
	h2_ptr += 4;

	register cmph_uint32 *g_ptr = (cmph_uint32 *)(h2_ptr + hash_state_packed_size(h2_type));

	register cmph_uint32 n = *g_ptr++;
	register cmph_uint32 m = *g_ptr++;

	register cmph_uint32 h1 = hash_packed(h1_ptr, h1_type, key, keylen) % n;
	register cmph_uint32 h2 = hash_packed(h2_ptr, h2_type, key, keylen) % n;
	DEBUGP("key: %s h1: %u h2: %u\n", key, h1, h2);
	if (h1 == h2 && ++h2 >= n) h2 = 0;
	DEBUGP("key: %s g[h1]: %u g[h2]: %u edges: %u\n", key, g_ptr[h1], g_ptr[h2], m);
	return (g_ptr[h1] + g_ptr[h2]) % m;
}

cmph_uint32 bmz_search_packed(void *packed_mphf, const char *key, cmph_uint32 keylen)
{
	register cmph_uint8 *h1_ptr = (cmph_uint8 *)packed_mphf;
	register CMPH_HASH h1_type  = (CMPH_HASH)(*((cmph_uint32 *)h1_ptr));
	h1_ptr += 4;

	register cmph_uint8 *h2_ptr = h1_ptr + hash_state_packed_size(h1_type);
	register CMPH_HASH h2_type  = (CMPH_HASH)(*((cmph_uint32 *)h2_ptr));
	h2_ptr += 4;

	register cmph_uint32 *g_ptr = (cmph_uint32 *)(h2_ptr + hash_state_packed_size(h2_type));

	register cmph_uint32 n = *g_ptr++;

	register cmph_uint32 h1 = hash_packed(h1_ptr, h1_type, key, keylen) % n;
	register cmph_uint32 h2 = hash_packed(h2_ptr, h2_type, key, keylen) % n;
	if (h1 == h2 && ++h2 > n) h2 = 0;
	return (g_ptr[h1] + g_ptr[h2]);
}

/** cmph_uint8 bmz8_search(void *packed_mphf, const char *key, cmph_uint32 keylen);
 *  \brief Use the packed mphf to do a search.
 *  \param  packed_mphf pointer to the packed mphf
 *  \param key key to be hashed
 *  \param keylen key legth in bytes
 *  \return The mphf value
 */
cmph_uint8 bmz8_search_packed(void *packed_mphf, const char *key, cmph_uint32 keylen)
{
	register cmph_uint8 *h1_ptr = (cmph_uint8 *)packed_mphf;
	register CMPH_HASH h1_type  = (CMPH_HASH)(*((cmph_uint32 *)h1_ptr));
	h1_ptr += 4;

	register cmph_uint8 *h2_ptr = h1_ptr + hash_state_packed_size(h1_type);
	register CMPH_HASH h2_type  = (CMPH_HASH)(*((cmph_uint32 *)h2_ptr));
	h2_ptr += 4;

	register cmph_uint8 *g_ptr = h2_ptr + hash_state_packed_size(h2_type);

	register cmph_uint8 n = *g_ptr++;

	register cmph_uint8 h1 = (cmph_uint8)(hash_packed(h1_ptr, h1_type, key, keylen) % n);
	register cmph_uint8 h2 = (cmph_uint8)(hash_packed(h2_ptr, h2_type, key, keylen) % n);
	DEBUGP("key: %s h1: %u h2: %u\n", key, h1, h2);
	if (h1 == h2 && ++h2 > n) h2 = 0;
	return (cmph_uint8)(g_ptr[h1] + g_ptr[h2]);
}

/** cmph_uint32 brz_search(void *packed_mphf, const char *key, cmph_uint32 keylen);
 *  \brief Use the packed mphf to do a search.
 *  \param  packed_mphf pointer to the packed mphf
 *  \param key key to be hashed
 *  \param keylen key legth in bytes
 *  \return The mphf value
 */
cmph_uint32 brz_search_packed(void *packed_mphf, const char *key, cmph_uint32 keylen)
{
	register cmph_uint32 *ptr = (cmph_uint32 *)packed_mphf;
	register CMPH_ALGO algo = (CMPH_ALGO)*ptr++;
	cmph_uint32 fingerprint[3];
	switch(algo)
	{
		case CMPH_FCH:
			return brz_fch_search_packed(ptr, key, keylen, fingerprint);
		case CMPH_BMZ8:
			return brz_bmz8_search_packed(ptr, key, keylen, fingerprint);
		default: assert(0);
	}
}

/** cmph_uint32 fch_search(void *packed_mphf, const char *key, cmph_uint32 keylen);
 *  \brief Use the packed mphf to do a search.
 *  \param  packed_mphf pointer to the packed mphf
 *  \param key key to be hashed
 *  \param keylen key legth in bytes
 *  \return The mphf value
 */
cmph_uint32 fch_search_packed(void *packed_mphf, const char *key, cmph_uint32 keylen)
{
	register cmph_uint8 *h1_ptr = (cmph_uint8 *)packed_mphf;
	register CMPH_HASH h1_type  = (CMPH_HASH)*((cmph_uint32 *)h1_ptr);
	h1_ptr += 4;

	register cmph_uint8 *h2_ptr = h1_ptr + hash_state_packed_size(h1_type);
	register CMPH_HASH h2_type  = (CMPH_HASH)*((cmph_uint32 *)h2_ptr);
	h2_ptr += 4;

	register cmph_uint32 *g_ptr = (cmph_uint32 *)(h2_ptr + hash_state_packed_size(h2_type));

	register cmph_uint32 m = *g_ptr++;

	register cmph_uint32 b = *g_ptr++;

	register double p1 = (double)(*((cmph_uint64 *)g_ptr));
	g_ptr += 2;

	register double p2 = (double)(*((cmph_uint64 *)g_ptr));
	g_ptr += 2;

	register cmph_uint32 h1 = hash_packed(h1_ptr, h1_type, key, keylen) % m;
	register cmph_uint32 h2 = hash_packed(h2_ptr, h2_type, key, keylen) % m;

	h1 = mixh10h11h12 (b, p1, p2, h1);
	return (h2 + g_ptr[h1]) % m;
}

/** cmph_uint32 bdz_search(void *packed_mphf, const char *key, cmph_uint32 keylen);
 *  \brief Use the packed mphf to do a search.
 *  \param  packed_mphf pointer to the packed mphf
 *  \param key key to be hashed
 *  \param keylen key legth in bytes
 *  \return The mphf value
 */
cmph_uint32 bdz_search_packed(void *packed_mphf, const char *key, cmph_uint32 keylen)
{

	register cmph_uint32 vertex;
	register CMPH_HASH hl_type  = (CMPH_HASH)(*(cmph_uint32 *)packed_mphf);
	register cmph_uint8 *hl_ptr = (cmph_uint8 *)(packed_mphf) + 4;

	register cmph_uint32 *ranktable = (cmph_uint32*)(hl_ptr + hash_state_packed_size(hl_type));

	register cmph_uint32 r = *ranktable++;
	register cmph_uint32 ranktablesize = *ranktable++;
	register cmph_uint8 * g = (cmph_uint8 *)(ranktable + ranktablesize);
	register cmph_uint8 b = *g++;

	cmph_uint32 hl[3];
	hash_vector_packed(hl_ptr, hl_type, key, keylen, hl);
	hl[0] = hl[0] % r;
	hl[1] = hl[1] % r + r;
	hl[2] = hl[2] % r + (r << 1);
	vertex = hl[(GETVALUE(g, hl[0]) + GETVALUE(g, hl[1]) + GETVALUE(g, hl[2])) % 3];
	return rank(b, ranktable, g, vertex);
}

/** cmph_uint32 bdz_ph_search(void *packed_mphf, const char *key, cmph_uint32 keylen);
 *  \brief Use the packed mphf to do a search.
 *  \param  packed_mphf pointer to the packed mphf
 *  \param key key to be hashed
 *  \param keylen key legth in bytes
 *  \return The mphf value
 */
cmph_uint32 bdz_ph_search_packed(void *packed_mphf, const char *key, cmph_uint32 keylen)
{

	register CMPH_HASH hl_type  = (CMPH_HASH)*(cmph_uint32 *)packed_mphf;
	register cmph_uint8 *hl_ptr = (cmph_uint8 *)(packed_mphf) + 4;

	register cmph_uint8 * ptr = hl_ptr + hash_state_packed_size(hl_type);

	register cmph_uint32 r = *((cmph_uint32*) ptr);
	register cmph_uint8 * g = ptr + 4;

	cmph_uint32 hl[3];
	register cmph_uint8 byte0, byte1, byte2;
	register cmph_uint32 vertex;

	hash_vector_packed(hl_ptr, hl_type, key, keylen, hl);

	hl[0] = hl[0] % r;
	hl[1] = hl[1] % r + r;
	hl[2] = hl[2] % r + (r << 1);

	byte0 = g[hl[0]/5];
	byte1 = g[hl[1]/5];
	byte2 = g[hl[2]/5];

	byte0 = lookup_table[hl[0]%5][byte0];
	byte1 = lookup_table[hl[1]%5][byte1];
	byte2 = lookup_table[hl[2]%5][byte2];
	vertex = hl[(byte0 + byte1 + byte2)%3];

	return vertex;
}


cmph_uint32 chd_ph_search_packed(void *packed_mphf, const char *key, cmph_uint32 keylen)
{
	register CMPH_HASH hl_type  = (CMPH_HASH)*(cmph_uint32 *)packed_mphf;
	register cmph_uint8 *hl_ptr = (cmph_uint8 *)(packed_mphf) + 4;

	register cmph_uint32 * ptr = (cmph_uint32 *)(hl_ptr + hash_state_packed_size(hl_type));
	register cmph_uint32 n = *ptr++;
	register cmph_uint32 nbuckets = *ptr++;
	cmph_uint32 hl[3];

	register cmph_uint32 disp,position;
	register cmph_uint32 probe0_num,probe1_num;
	register cmph_uint32 f,g,h;

	hash_vector_packed(hl_ptr, hl_type, key, keylen, hl);

	g = hl[0] % nbuckets;
	f = hl[1] % n;
	h = hl[2] % (n-1) + 1;

	disp = compressed_seq_query_packed(ptr, g);
	probe0_num = disp % n;
	probe1_num = disp/n;
	position = (cmph_uint32)((f + ((cmph_uint64 )h)*probe0_num + probe1_num) % n);
	return position;
}


cmph_uint32 chd_search_packed(void *packed_mphf, const char *key, cmph_uint32 keylen)
{

	register cmph_uint32 * ptr = (cmph_uint32 *)packed_mphf;
	register cmph_uint32 packed_cr_size = *ptr++;
	register cmph_uint8 * packed_chd_phf = ((cmph_uint8 *) ptr) + packed_cr_size + sizeof(cmph_uint32);
	return _chd_search(packed_chd_phf, ptr, key, keylen);
}

cmph_uint32 hash_state_packed_size(CMPH_HASH hashfunc)
{
	cmph_uint32 size = 0;
	switch (hashfunc)
	{
		case CMPH_HASH_JENKINS:
			size += jenkins_state_packed_size();
			break;
		default:
			assert(0);
	}
	return size;
}

static cmph_uint32 brz_bmz8_search_packed(cmph_uint32 *packed_mphf, const char *key, cmph_uint32 keylen, cmph_uint32 * fingerprint)
{
	register CMPH_HASH h0_type = (CMPH_HASH)*packed_mphf++;
	register cmph_uint32 *h0_ptr = packed_mphf;
	packed_mphf = (cmph_uint32 *)(((cmph_uint8 *)packed_mphf) + hash_state_packed_size(h0_type));

	register cmph_uint32 k = *packed_mphf++;

	register double c = (double)(*((cmph_uint64*)packed_mphf));
	packed_mphf += 2;

	register CMPH_HASH h1_type = (CMPH_HASH)*packed_mphf++;

	register CMPH_HASH h2_type = (CMPH_HASH)*packed_mphf++;

	register cmph_uint8 * size = (cmph_uint8 *) packed_mphf;
	packed_mphf = (cmph_uint32 *)(size + k);

	register cmph_uint32 * offset = packed_mphf;
	packed_mphf += k;

	register cmph_uint32 h0;

	hash_vector_packed(h0_ptr, h0_type, key, keylen, fingerprint);
	h0 = fingerprint[2] % k;

	register cmph_uint32 m = size[h0];
	register cmph_uint32 n = (cmph_uint32)ceil(c * m);

	#if defined (__ia64) || defined (__x86_64__)
		register cmph_uint64 * g_is_ptr = (cmph_uint64 *)packed_mphf;
	#else
		register cmph_uint32 * g_is_ptr = packed_mphf;
	#endif

	register cmph_uint8 * h1_ptr = (cmph_uint8 *) g_is_ptr[h0];

	register cmph_uint8 * h2_ptr = h1_ptr + hash_state_packed_size(h1_type);

	register cmph_uint8 * g = h2_ptr + hash_state_packed_size(h2_type);

	register cmph_uint32 h1 = hash_packed(h1_ptr, h1_type, key, keylen) % n;
	register cmph_uint32 h2 = hash_packed(h2_ptr, h2_type, key, keylen) % n;

	register cmph_uint8 mphf_bucket;

	if (h1 == h2 && ++h2 >= n) h2 = 0;
	mphf_bucket = (cmph_uint8)(g[h1] + g[h2]);
	DEBUGP("key: %s h1: %u h2: %u h0: %u\n", key, h1, h2, h0);
	DEBUGP("Address: %u\n", mphf_bucket + offset[h0]);
	return (mphf_bucket + offset[h0]);
}

/** \fn cmph_uint32 jenkins_state_packed_size(jenkins_state_t *state);
 *  \brief Return the amount of space needed to pack a jenkins function.
 *  \return the size of the packed function or zero for failures
 */
cmph_uint32 jenkins_state_packed_size(void)
{
	return sizeof(cmph_uint32);
}

cmph_uint32 hash_packed(void *hash_packed, CMPH_HASH hashfunc, const char *k, cmph_uint32 keylen)
{
	switch (hashfunc)
	{
		case CMPH_HASH_JENKINS:
			return jenkins_hash_packed(hash_packed, k, keylen);
		default:
			assert(0);
	}
	assert(0);
	return 0;
}

/** \fn cmph_uint32 jenkins_hash_packed(void *jenkins_packed, const char *k, cmph_uint32 keylen);
 *  \param jenkins_packed is a pointer to a contiguous memory area
 *  \param key is a pointer to a key
 *  \param keylen is the key length
 *  \return an integer that represents a hash value of 32 bits.
 */
cmph_uint32 jenkins_hash_packed(void *jenkins_packed, const char *k, cmph_uint32 keylen)
{
	cmph_uint32 hashes[3];
	__jenkins_hash_vector(*((cmph_uint32 *)jenkins_packed), k, keylen, hashes);
	return hashes[2];
}

static cmph_uint32 brz_fch_search_packed(cmph_uint32 *packed_mphf, const char *key, cmph_uint32 keylen, cmph_uint32 * fingerprint)
{
	register CMPH_HASH h0_type = (CMPH_HASH)*packed_mphf++;

	register cmph_uint32 *h0_ptr = packed_mphf;
	packed_mphf = (cmph_uint32 *)(((cmph_uint8 *)packed_mphf) + hash_state_packed_size(h0_type));

	register cmph_uint32 k = *packed_mphf++;

	register double c = (double)(*((cmph_uint64*)packed_mphf));
	packed_mphf += 2;

	register CMPH_HASH h1_type = (CMPH_HASH)*packed_mphf++;

	register CMPH_HASH h2_type = (CMPH_HASH)*packed_mphf++;

	register cmph_uint8 * size = (cmph_uint8 *) packed_mphf;
	packed_mphf = (cmph_uint32 *)(size + k);

	register cmph_uint32 * offset = packed_mphf;
	packed_mphf += k;

	register cmph_uint32 h0;

	hash_vector_packed(h0_ptr, h0_type, key, keylen, fingerprint);
	h0 = fingerprint[2] % k;

	register cmph_uint32 m = size[h0];
	register cmph_uint32 b = fch_calc_b(c, m);
	register double p1 = fch_calc_p1(m);
	register double p2 = fch_calc_p2(b);

	#if defined (__ia64) || defined (__x86_64__)
		register cmph_uint64 * g_is_ptr = (cmph_uint64 *)packed_mphf;
	#else
		register cmph_uint32 * g_is_ptr = packed_mphf;
	#endif

	register cmph_uint8 * h1_ptr = (cmph_uint8 *) g_is_ptr[h0];

	register cmph_uint8 * h2_ptr = h1_ptr + hash_state_packed_size(h1_type);

	register cmph_uint8 * g = h2_ptr + hash_state_packed_size(h2_type);

	register cmph_uint32 h1 = hash_packed(h1_ptr, h1_type, key, keylen) % m;
	register cmph_uint32 h2 = hash_packed(h2_ptr, h2_type, key, keylen) % m;

	register cmph_uint8 mphf_bucket = 0;
	h1 = mixh10h11h12(b, p1, p2, h1);
	mphf_bucket = (cmph_uint8)((h2 + g[h1]) % m);
	return (mphf_bucket + offset[h0]);
}

/** \fn hash_vector_packed(void *hash_packed, CMPH_HASH hashfunc, const char *k, cmph_uint32 keylen, cmph_uint32 * hashes)
 *  \param hash_packed is a pointer to a contiguous memory area
 *  \param key is a pointer to a key
 *  \param keylen is the key length
 *  \param hashes is a pointer to a memory large enough to fit three 32-bit integers.
 */
void hash_vector_packed(void *hash_packed, CMPH_HASH hashfunc, const char *k, cmph_uint32 keylen, cmph_uint32 * hashes)
{
	switch (hashfunc)
	{
		case CMPH_HASH_JENKINS:
			jenkins_hash_vector_packed(hash_packed, k, keylen, hashes);
			break;
		default:
			assert(0);
	}
}

/** \fn jenkins_hash_vector_packed(void *jenkins_packed, const char *k, cmph_uint32 keylen, cmph_uint32 * hashes);
 *  \param jenkins_packed is a pointer to a contiguous memory area
 *  \param key is a pointer to a key
 *  \param keylen is the key length
 *  \param hashes is a pointer to a memory large enough to fit three 32-bit integers.
 */
void jenkins_hash_vector_packed(void *jenkins_packed, const char *k, cmph_uint32 keylen, cmph_uint32 * hashes)
{
	__jenkins_hash_vector(*((cmph_uint32 *)jenkins_packed), k, keylen, hashes);
}

cmph_uint32 compressed_seq_query_packed(void * cs_packed, cmph_uint32 idx)
{
	// unpacking cs_packed
	register cmph_uint32 *ptr = (cmph_uint32 *)cs_packed;
	register cmph_uint32 n = *ptr++;
	register cmph_uint32 rem_r = *ptr++;
	ptr++; // skipping total_length 
// 	register cmph_uint32 total_length = *ptr++;
	register cmph_uint32 buflen_sel = *ptr++;
	register cmph_uint32 * sel_packed = ptr;
	register cmph_uint32 * length_rems = (ptr += (buflen_sel >> 2)); 
	register cmph_uint32 length_rems_size = BITS_TABLE_SIZE(n, rem_r);
	register cmph_uint32 * store_table = (ptr += length_rems_size);

	// compressed sequence query computation
	register cmph_uint32 enc_idx, enc_length;
	register cmph_uint32 rems_mask;
	register cmph_uint32 stored_value;
	register cmph_uint32 sel_res;

	rems_mask = (1U << rem_r) - 1U;
	
	if(idx == 0)
	{
		enc_idx = 0;
		sel_res = select_query_packed(sel_packed, idx);
	}
	else
	{
		sel_res = select_query_packed(sel_packed, idx - 1);
		
		enc_idx = (sel_res - (idx - 1)) << rem_r;
		enc_idx += get_bits_value(length_rems, idx-1, rem_r, rems_mask);
		
		sel_res = select_next_query_packed(sel_packed, sel_res);
	};

	enc_length = (sel_res - idx) << rem_r;
	enc_length += get_bits_value(length_rems, idx, rem_r, rems_mask);
	enc_length -= enc_idx;
	if(enc_length == 0)
		return 0;
		
	stored_value = get_bits_at_pos(store_table, enc_idx, enc_length);
	return stored_value + ((1U << enc_length) - 1U);
}

cmph_uint32 select_query_packed(void * sel_packed, cmph_uint32 one_idx)
{
	register cmph_uint32 *ptr = (cmph_uint32 *)sel_packed;
	register cmph_uint32 n = *ptr++;
	register cmph_uint32 m = *ptr++;
        register cmph_uint32 nbits = n + m;
	register cmph_uint32 vec_size = (nbits + 31) >> 5; // (nbits + 31) >> 5 = (nbits + 31)/32
	register cmph_uint8 * bits_vec = (cmph_uint8 *)ptr;
	register cmph_uint32 * select_table = ptr + vec_size;
	
	return _select_query(bits_vec, select_table, one_idx);
}


cmph_uint32 select_next_query_packed(void * sel_packed, cmph_uint32 vec_bit_idx)
{
	register cmph_uint8 * bits_vec = (cmph_uint8 *)sel_packed;
	bits_vec += 8; // skipping n and m
	return _select_next_query(bits_vec, vec_bit_idx);
}