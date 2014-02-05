#ifndef ADDRESS_H_
#define ADDRESS_H_

#include "NBase58.h"
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <string.h>
#include <openssl/ripemd.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>

enum NET {
	BITCOIN_PUB=0, BITCOIN_PRV=128,
	BITCOINTEST_PUB=111, BITCOINTEST_PRV=239,
	LITECOIN_PUB=48, LITECOIN_PRV=176,
	LITECOINTEST_PUB=111, LITECOINTEST_PRV=239,
	NAMECOIN_PUB=52, NAMECOIN_PRV=180,
	DOGECOIN_PUB=30, DOGECOIN_PRV=158,
	PEERCOIN_PUB=55, PEERCOIN_PRV=183
};

int sha256(unsigned char* out, unsigned char *in, int inLen);
int ripemd160(unsigned char *out, unsigned char *in, int inLen);

unsigned char * createAddressBN(BIGNUM privKeyBN, unsigned char networkPrv);
unsigned char * createAddress(const unsigned char *privKey, int privKeyLen, unsigned char networkPrv);
unsigned char * privateKeyToWIF(const unsigned char *privKey, int privKeyLen, unsigned char networkPrv);
unsigned char * generateRandomAddress(unsigned char len, unsigned char step);

#endif /* ADDRESS_H_ */
