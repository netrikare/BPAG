#include "NBase58.h"
#include "address.h"
#include <stdio.h>
#include <string.h>
#include <openssl/bn.h>

void test1(){
	BIGNUM b;
	BN_init(&b);

	char *address = (char*)malloc(sizeof(char) * 35);
	int i;
	for(i=0;i<10;i++){
		int outLen;
		char *address = createAddressBN(b, BITCOIN_PUB);
		printf("%s\n", address);
		free(address);
		BN_add(&b, BN_value_one(), &b);
	}
	BN_free(&b);
}

void test2(){
	char *d = "ABC";
	int mdLen = 32;

	unsigned char *md = malloc(mdLen);
	sha256(md, d, strlen(d));

	char *a = createAddress(md, mdLen, BITCOIN_PUB);
	printf("%s\n", a);
	free(a);
	free(md);
}

void test3(){
	char *privKey = "A";

	int str = -1;
	unsigned char * wif = privateKeyToWIF(privKey, strlen(privKey), BITCOIN_PRV);
	unsigned char * address = createAddress(privKey, strlen(privKey), BITCOIN_PUB);

	str = strcmp(wif, "26sHB9WRN");	if(str) printf("ERROR wif\n");
	str = strcmp(address, "1FHcYth4LRJMwNx2y8NR5DH7sYCiVzXs3Y");	if(str) printf("ERROR addres\n");
	printf("%s : %s\n", address, wif);

	free(wif);
	free(address);

	int mdLen = 32;
	unsigned char *md = malloc(mdLen);
	sha256(md, privKey, strlen(privKey));
	wif = privateKeyToWIF(md, mdLen, BITCOIN_PRV);
	address = createAddress(md, mdLen, BITCOIN_PUB);


	str = strcmp(wif, "5JTzFTSfF27cqHqy1HcqxWGhdso9JCykPEbTiwfraNN74v1yxvk");	if(str) printf("ERROR wif\n");
	str = strcmp(address, "1KWeNLvHnsDvr4PWp9ZSnjWPcuudGx4icf");	if(str) printf("ERROR addres\n");
	printf("%s : %s\n", address, wif);

	free(wif);
	free(address);

	free(md);

}

void test4(){
	char *c = "ABC";
	int inLen = strlen(c);

	int outLen;
	unsigned char *enc = NBase58Encode(c, inLen, &outLen);
	unsigned char *dec = NBase58Decode(enc, outLen);
	printf("BASE58: %d len, %s:%s:%s\n", outLen, c, enc, dec);

	free(enc);
	free(dec);
}
