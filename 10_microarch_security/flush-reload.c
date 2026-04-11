#include <emmintrin.h>
#include <x86intrin.h>
#include <stdint.h>
#include <stdio.h>

uint8_t array[256 * 4096];
int temp;
unsigned char secret = 94;

/* cache hit time threshold assumed */
#define CACHE_HIT_THRESHOLD (80)
#define DELTA 1024

#include "flush-reload.h"

void victim() {
	temp = array[secret*4096 + DELTA];
}

int main(int argc, const char **argv) {
	flushSideChannel();
	victim();
	reloadSideChannel();
	return (0);
}
