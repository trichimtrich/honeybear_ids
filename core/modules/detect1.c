#include <stdio.h>
#include <stdlib.h>

int mod_init()
{
	printf("Detector 1 - Module Loaded!\n");
	return 1;
}

int mod_detect(char* pkt, size_t len)
{
	printf("Detector 1 - Checking true\n");
	return 1;
}