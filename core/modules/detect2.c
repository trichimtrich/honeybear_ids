#include <stdio.h>
#include <stdlib.h>

int mod_init()
{
	printf("Detector 2 - Module Loaded!\n");
	return 1;
}

int mod_detect(char *pkt, size_t len)
{
	printf("Detector 2 - Checking false\n");
	return 0;
}