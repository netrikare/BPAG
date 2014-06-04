#include "address.h"
#include "util.h"
#include <stdio.h>
#include <sys/ioctl.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <math.h>
#include <openssl/bn.h>

#define THREADCOUNT 8

pthread_t tid[THREADCOUNT];
static volatile int abortThread = 0;
static volatile long long int hashCount = 0; //this is not thread safe, and doesn't need to be, we just need to display approximate value
unsigned char *address;
unsigned char LEN;
unsigned char STEP;

struct THINFO{
	unsigned char id;
	long long int currentIteration;
	long long int threadIterations;
};
struct THINFO threadInfo[THREADCOUNT];

void *threadFun(void *);
void *printProgress(void *);
void clearTerminal();

void cracker(unsigned char len, unsigned char step, unsigned char *addrToCrack){
	printf("\n\nSimulation of bruteforcing (assuming attacker knows step and len):\n");
	LEN = len;
	STEP = step;
	address = addrToCrack;

	long i;
	//int cpus = sysconf(_SC_NPROCESSORS_ONLN);


	for(i=0;i<THREADCOUNT;i++){
		threadInfo[i].id = (unsigned char)(i & 0xFF);
		pthread_create(&tid[i], NULL, &threadFun, (void *)&threadInfo[i]);
	}

	pthread_t progressTid;
	pthread_create(&progressTid, NULL, &printProgress, NULL);

	for(i=0;i<THREADCOUNT;i++)
		pthread_join(tid[i], NULL);

	//free(address);
	abortThread = 1;
	pthread_join(progressTid, NULL);

	pthread_exit(NULL);
}

void *threadFun(void *v_thInfo){
	int i;
	struct THINFO *thInfo = (struct THINFO*)v_thInfo;
	int f = 256 / STEP * STEP;
	unsigned char delta = f/THREADCOUNT;
	unsigned char from = thInfo->id * delta;
	unsigned char to = (thInfo->id + 1) * delta - 1;
	unsigned char *c = malloc(LEN);

	memset(c, 0, LEN);
	c[LEN-1] = from;

	//calculate number of all steps
	double numOfAllSteps = pow(STEP, LEN);
	double r = 1;

	thInfo->threadIterations = 1;
	for(i=0;i<LEN-1;i++)
		r *= 256;
	r *= (to - from + 1);

	r /= numOfAllSteps;
	thInfo->threadIterations = r;
	thInfo->currentIteration = 0;

	int k=0;

	while(thInfo->currentIteration < thInfo->threadIterations)
	{
		thInfo->currentIteration++;

		//char *f = sprintfVector(c);		printf("ID: %.0lf, %s\n", thInfo->current, f); free(f);
		char * md = malloc(SHA256_DIGEST_LENGTH);
		sha256(md, c, LEN);
		unsigned char *a = createAddress(md, SHA256_DIGEST_LENGTH, BITCOIN_PUB);
		//unsigned char *a = malloc(34);

		if(isEqual(address, a, 34) == 1){
			abortThread = 1;

			char *privKeyStr = sprintfVector(c, LEN);
			char *wif = privateKeyToWIF(md, SHA256_DIGEST_LENGTH, BITCOIN_PRV);

			printf("\n!!! FOUND !!!\nTID: %d\nRANDOM:  %s\nADDRESS: %s\nPRIVKEY: %s [wallet import format]\n", thInfo->id, privKeyStr, a, wif);
			free(wif);
			free(privKeyStr);
		}

		free(md);
		free(a);

		if(abortThread == 1)
			break;

		while(k < LEN-1 && c[k] == (256 - STEP)){
			c[k]=0;
			k++;
		}
		if(k == LEN-1 && c[k] == (to + 1 - STEP)){
			c[k]=0;
			k++;
		}

		c[k] += STEP;
		k = 0;
		hashCount++;
	}
	free(c);
	//printf("%d: %d -> %d\t[range: %lld] [current:%lld]\n", thInfo->id, from, to, thInfo->threadIterations, thInfo->currentIteration);
	pthread_exit(NULL);
}

void *printProgress(void *v){
	struct winsize wsize;
	int i, len, prevHashCount=0;
	ioctl(0, TIOCGWINSZ, &wsize);

	char *c = malloc(wsize.ws_col);


	double lastPerCentDone = 0;
	long long int currentIterationSum;
	double maxIterations = pow(2, LEN * 8)/pow(STEP, LEN);
	double sleepMS = 1000;
	double timeFactor = 1000/sleepMS;
	double sleepTime = sleepMS * 1000;

	while(!abortThread){
		len = 0;
		currentIterationSum = 0;

		for(i=0;i<THREADCOUNT;i++){
			double p = threadInfo[i].currentIteration * 100;
			sprintf(c + len, "%.1f\t", p/threadInfo[i].threadIterations);

			currentIterationSum += p;
			len = strlen(c);
		}
		double perCentDone = currentIterationSum/maxIterations;
		double maxTimeToGo = (100.0-perCentDone)/(perCentDone-lastPerCentDone) / timeFactor;
		lastPerCentDone = perCentDone;

		int t = hashCount;
		double aps = (t-prevHashCount)/sleepTime * 1000 * 1000;
		prevHashCount = t;

		if(!abortThread){
			if(maxTimeToGo < 86400)
				sprintf(c + len, "TOTAL: %3.8f %%\tMax remaining time: %3.0f s.\tAPS: %.0lf\r", perCentDone, maxTimeToGo, aps);
			else
				sprintf(c + len, "TOTAL: %3.8f %%\tMax remaining time: %3.0f days.\tAPS: %.0lf\r", perCentDone, maxTimeToGo/(3600*24), aps);

			printf("%s", c);
			fflush(stdout);
			usleep(sleepTime);
			clearTerminal(wsize.ws_col);
			memset(c, 0, wsize.ws_col);
		}else
			break;
	}
	free(c);
	pthread_exit(NULL);
}

