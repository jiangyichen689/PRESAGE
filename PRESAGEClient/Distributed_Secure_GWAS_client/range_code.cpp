#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <memory.h>
#include <math.h>
#include <string.h>

#include "range_code.h"

///////Data generation functions///////////////////////////////
template <class T>
double calculate_entropy(T* data, int data_size) {
	int min, max, counter, buffer_size;
	int* buffer;
	double entropy;
	double log2 = log(2.0);
	double prob;

	min = data[0];
	max = data[0];
	for (counter=0; counter<data_size; ++counter) {
		if (data[counter] < min)
			min = data[counter];
		if (data[counter] > max)
			max = data[counter];
	}

	buffer_size = max - min + 1;
	buffer = (int*)malloc(buffer_size * sizeof(int));
	memset(buffer, 0x00, buffer_size * sizeof(int));
	for (counter=0; counter<data_size; ++counter) {
		++buffer[data[counter]-min];
	}

	entropy = 0.0;
	for (counter=0; counter<buffer_size; ++counter) {
		if (buffer[counter] > 0) {
			prob = (double)(buffer[counter]);
			prob /= (double)(data_size);
			entropy += log(prob)/log2*prob;
		}
	}
	entropy *= -1.0;

	if (buffer)
		free(buffer);
	return  entropy;
}

static __inline double round(double x) {
	if ((x - floor(x)) >= 0.5)
		return ceil(x);
	else
		return floor(x);
}

double makeData(int* data, int data_size, int min, int max, int redundancy_factor) {
	int counter, cnt, high, low;
	double buf;

	if (redundancy_factor <= 1)
		redundancy_factor = 1;

	if (max <= min)
		max = min + 1;

	srand((unsigned)(time(0))); 
	for (counter=0; counter<data_size; counter++) {
		buf = 0;
		for (cnt=0; cnt<redundancy_factor; cnt++) {
			buf += (double)(rand());
		}
		data[counter] = ((int)(buf))/redundancy_factor;
	}
	low  = data[0];
	high = data[0];
	for (counter=0; counter<data_size; counter++) {
		if (data[counter] > high)
			high = data[counter];
		if (data[counter] < low)
			low = data[counter];
	}
	for (counter=0; counter<data_size; counter++) {
		buf = (double)(data[counter] - low);
		buf /= (double)(high - low);
		buf *= (double)(max - min);
		buf = round(buf);
		data[counter] = (int)(buf) + min;
	}
	return calculate_entropy(data, data_size);
}
//end of data generation functions

//global data buffer for round trip
unsigned char* g_buffer = 0;
int current_byte = 0;

//input/output functions
static __inline void writeByte(unsigned char byte) {
	g_buffer[current_byte++] = byte;
}

static __inline unsigned char readByte() {
	return g_buffer[current_byte++];
}

static __inline int findInterval(int* cm, int size, int point) {
	int index = -1;
	int left  = 0; 
	int right = size-2;
	int cnt = 0;
	while (true) {	
		int mid = (right + left)>>1;
		if (point >= cm[mid] && point < cm[mid+1]) {
			index = mid;
			break;
		}
		if (point >= cm[mid+1]) left = mid + 1;
		else right = mid;
		if (cnt++ >= size) break;
	}
	return index;
}



void RangeMapper::updateModel(int cmin, int cmax) {
	unsigned long long range = HIGH - LOW;
	HIGH = LOW + ((range * cmax) >> RANGE_SIZE);
	LOW += ((range * cmin) >> RANGE_SIZE) + 1;
}

int RangeMapper::getMidPoint() {
	return (int)(((MID - LOW) << RANGE_SIZE) / (HIGH - LOW)); 
}

void RangeMapper::encodeRange(int cmin, int cmax) {
	updateModel(cmin, cmax);
	if ((HIGH - LOW) < RANGE_LIMIT) HIGH = LOW; //preventing narrowing range
	while (((LOW ^ HIGH) >> SHIFT) == 0) {
		writeByte((unsigned char)(LOW >> SHIFT));
		LOW <<= 8;
		HIGH = (HIGH << 8) | 0xff;
	}
	HIGH &= MASK;
	LOW  &= MASK;
}

void RangeMapper::decodeRange(int cmin, int cmax) { 
	updateModel(cmin, cmax);
	if ((HIGH - LOW) < RANGE_LIMIT)  HIGH = LOW; 
	while (((LOW ^ HIGH) >> SHIFT) == 0) {
		LOW <<= 8;
		HIGH = (HIGH << 8) | 0xff;
		MID =  (MID << 8)  | readByte();
	}
	HIGH &= MASK;
	LOW  &= MASK;
	MID  &= MASK;
}

void RangeMapper::flush() { 
	LOW += 1;
	for (int i=0; i<BYTES_IN_BUFFER; i++) {
		writeByte((unsigned char)(LOW >> SHIFT));
		LOW <<= 8;
	}
}

void RangeMapper::init() { 
	for (int i=0; i<BYTES_IN_BUFFER; ++i) {
		MID = (MID << 8) + readByte();
	}
}

void makeRanges(unsigned char* data, int data_size, int* cm, int alphabet_size, int PRECISION) {
	//we make ranges for data
	int* freq = (int*)malloc(alphabet_size * sizeof(int));
	memset(freq, 0x00, alphabet_size * sizeof(int));
	for (int i=0; i<data_size; ++i) {
		++freq[data[i]];
	}

	cm[0] = 0;
	for (int i=0; i<alphabet_size; ++i) {
		cm[i+1] = cm[i] + freq[i];
	}

	int total = cm[alphabet_size];
	int upper_limit = (1<<PRECISION) - 2;
	for (int i=0; i<alphabet_size + 1; ++i) {
		cm[i] = (int)((long long)(cm[i]) * (long long)(upper_limit) / (long long)(total));
	}
	cm[alphabet_size+1] = (1<<PRECISION) - 1;
	//ranges are ready

	//correction of ranges
	for (int i=0; i<alphabet_size; ++i) {
		if (cm[i+1] <= cm[i]) cm[i+1] = cm[i] + 1;
	}
	for (int i=alphabet_size; i>=0; --i) {
		if (cm[i] >= cm[i+1]) cm[i] = cm[i+1] - 1;
	}
	//end of correction
	if (freq) free(freq);
}

void makeLookupTable(int* cm, int size, short* lookup) {
	for (int i=0; i<size-1; ++i) {
		for (int j=cm[i]; j<cm[i+1]; ++j) {
			lookup[j] = i;
		}
	}
}