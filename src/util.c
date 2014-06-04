#include "util.h"
#include <stdlib.h>
#include <stdio.h>

//caller must call free
unsigned char * sprintfVector(unsigned char a[], int aLen){
	int k = 3; //2hex + space
	int i;
	char *v = malloc(aLen * k + 1);

	for(i=0;i<aLen;i++){
		sprintf(v + i * k, "%.2X ", a[i] & 0xFF);
	}

	v[aLen * k] = 0;

	return v;
}

int isEqual(unsigned char a[], unsigned char b[], int len){
	//assume size of a = size of b
	int i;
	for(i=0; i<len; i++){
		if(a[i] != b[i])
			return 0;
	}
	return 1;
}

void clearTerminal(int consoleWidth){
	int i;
	for(i=0;i<consoleWidth;i++)
		printf(" ");
	printf("\r");
	fflush(stdout);
}
