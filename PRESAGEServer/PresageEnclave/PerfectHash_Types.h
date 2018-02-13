#ifndef _PERFECT_HASH_TYPE
#define _PERFECT_HASH_TYPE

#define NBITS_STEP_SELECT_TABLE 7
#define MASK_STEP_SELECT_TABLE 0x7f
#define UNASSIGNED 3U

#define BITS_TABLE_SIZE(n, bits_length) ((n * bits_length + 31) >> 5)

typedef unsigned char cmph_uint8;
typedef unsigned int cmph_uint32;
typedef unsigned long long cmph_uint64;

static const cmph_uint32 bitmask32[] = { 1,       1 << 1,  1 << 2,  1 << 3,  1 << 4,  1 << 5,  1 << 6, 1 << 7,
                                         1 << 8,  1 << 9,  1 << 10, 1 << 11, 1 << 12, 1 << 13, 1 << 14, 1 << 15,
                                         1 << 16, 1 << 17, 1 << 18, 1 << 19, 1 << 20, 1 << 21, 1 << 22, 1 << 23,
                                         1 << 24, 1 << 25, 1 << 26, 1 << 27, 1 << 28, 1 << 29, 1 << 30, 1U << 31
				       };

/** \def GETBIT32(array, i)
 *  \brief get the value of an 1-bit integer stored in an array of 32-bit words. 
 *  \param array to get 1-bit integer values from. The entries are 32-bit words.
 *  \param i is the index in array to get the 1-bit integer value from
 * 
 * GETBIT32(array, i) is a macro that gets the value of an 1-bit integer stored in an array of 32-bit words.
 */
#define GETBIT32(array, i) (array[i >> 5] & bitmask32[i & 0x0000001f])



#define mix(a,b,c) \
{ \
	a -= b; a -= c; a ^= (c>>13); \
	b -= c; b -= a; b ^= (a<<8); \
	c -= a; c -= b; c ^= (b>>13); \
	a -= b; a -= c; a ^= (c>>12);  \
	b -= c; b -= a; b ^= (a<<16); \
	c -= a; c -= b; c ^= (b>>5); \
	a -= b; a -= c; a ^= (c>>3);  \
	b -= c; b -= a; b ^= (a<<10); \
	c -= a; c -= b; c ^= (b>>15); \
}

#define GETVALUE(array, i) ((cmph_uint8)((array[i >> 2] >> ((i & 0x00000003U) << 1U)) & 0x00000003U))

typedef enum { CMPH_BMZ, CMPH_BMZ8, CMPH_CHM, CMPH_BRZ, CMPH_FCH,
               CMPH_BDZ, CMPH_BDZ_PH,
               CMPH_CHD_PH, CMPH_CHD, CMPH_COUNT } CMPH_ALGO;




typedef struct 
{
        void *data;
        cmph_uint32 nkeys;
        int (*read)(void *, char **, cmph_uint32 *);
        void (*dispose)(void *, char *, cmph_uint32);
        void (*rewind)(void *);
} cmph_io_adapter_t;

struct __cmph_t
{
        CMPH_ALGO algo;
        cmph_uint32 size;
        cmph_io_adapter_t *key_source;
        void *data; // algorithm dependent data
};

typedef struct __cmph_t cmph_t;

//-------------------------------------------------------------
typedef enum { CMPH_HASH_JENKINS, CMPH_HASH_COUNT } CMPH_HASH;

typedef struct __jenkins_state_t
{
	CMPH_HASH hashfunc;
	cmph_uint32 seed;
} jenkins_state_t;

union __hash_state_t
{
	CMPH_HASH hashfunc;
	jenkins_state_t jenkins;
};

typedef union __hash_state_t hash_state_t;


struct _select_t
{
	cmph_uint32 n,m;
	cmph_uint32 * bits_vec;
	cmph_uint32 * select_table;
};

typedef struct _select_t select_t;

struct _compressed_seq_t
{
	cmph_uint32 n; // number of values stored in store_table
	// The length in bits of each value is decomposed into two compnents: the lg(n) MSBs are stored in rank_select data structure
	// the remaining LSBs are stored in a table of n cells, each one of rem_r bits.
	cmph_uint32 rem_r;
	cmph_uint32 total_length; // total length in bits of stored_table
	select_t sel;
	cmph_uint32 * length_rems;
	cmph_uint32 * store_table;
};

typedef struct _compressed_seq_t compressed_seq_t;

struct __chm_data_t
{
	cmph_uint32 m; //edges (words) count
	cmph_uint32 n; //vertex count
	cmph_uint32 *g;
	hash_state_t **hashes;
};

struct __bmz_data_t
{
	cmph_uint32 m; //edges (words) count
	cmph_uint32 n; //vertex count
	cmph_uint32 *g;
	hash_state_t **hashes;
};

struct __bmz8_data_t
{
	cmph_uint8 m; //edges (words) count
	cmph_uint8 n; //vertex count
	cmph_uint8 *g;
	hash_state_t **hashes;
};

struct __brz_data_t
{
	CMPH_ALGO algo;      // CMPH algo for generating the MPHFs for the buckets (Just CMPH_FCH and CMPH_BMZ8)
	cmph_uint32 m;       // edges (words) count
	double c;      // constant c
	cmph_uint8  *size;   // size[i] stores the number of edges represented by g[i][...]. 
	cmph_uint32 *offset; // offset[i] stores the sum: size[0] + size[1] + ... size[i-1].
	cmph_uint8 **g;      // g function. 
	cmph_uint32 k;       // number of components
	hash_state_t **h1;
	hash_state_t **h2;
	hash_state_t * h0;
};

struct __fch_data_t
{
	cmph_uint32 m;       // words count
	double c;      // constant c
	cmph_uint32  b;      // parameter b = ceil(c*m/(log(m)/log(2) + 1)). Don't need to be stored 
	double p1;     // constant p1 = ceil(0.6*m). Don't need to be stored 
	double p2;     // constant p2 = ceil(0.3*b). Don't need to be stored 
	cmph_uint32 *g;      // g function. 
	hash_state_t *h1;    // h10 function. 
	hash_state_t *h2;    // h20 function.
};

struct __bdz_data_t
{
	cmph_uint32 m; //edges (words) count
	cmph_uint32 n; //vertex count
	cmph_uint32 r; //partition vertex count
	cmph_uint8 *g;
	hash_state_t *hl; // linear hashing

	cmph_uint32 k; //kth index in ranktable, $k = log_2(n=3r)/\varepsilon$
	cmph_uint8 b; // number of bits of k
	cmph_uint32 ranktablesize; //number of entries in ranktable, $n/k +1$
	cmph_uint32 *ranktable; // rank table
};

struct __bdz_ph_data_t
{
	cmph_uint32 m; //edges (words) count
	cmph_uint32 n; //vertex count
	cmph_uint32 r; //partition vertex count
	cmph_uint8 *g;
	hash_state_t *hl; // linear hashing
};

struct __chd_ph_data_t
{
	compressed_seq_t * cs;	// compressed displacement values
	cmph_uint32 nbuckets;	// number of buckets
	cmph_uint32 n;		// number of bins
	hash_state_t *hl;	// linear hash function
};

struct __chd_data_t
{
	cmph_uint32 packed_cr_size;
	cmph_uint8 * packed_cr; // packed compressed rank structure to control the number of zeros in a bit vector
	
	cmph_uint32 packed_chd_phf_size;
	cmph_uint8 * packed_chd_phf;
};

typedef struct __chm_data_t chm_data_t;
typedef struct __bmz_data_t bmz_data_t;
typedef struct __bmz8_data_t bmz8_data_t;
typedef struct __brz_data_t brz_data_t;
typedef struct __fch_data_t fch_data_t;
typedef struct __bdz_data_t bdz_data_t;
typedef struct __bdz_ph_data_t bdz_ph_data_t;
typedef struct __chd_ph_data_t chd_ph_data_t;
typedef struct __chd_data_t chd_data_t;

#endif