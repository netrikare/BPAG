#include "address.h"
#include "util.h"

#define NETWORK_BYTE_LENGTH 1
#define CHECKSUM_LENGTH 4
#define RNC (RIPEMD160_DIGEST_LENGTH + NETWORK_BYTE_LENGTH + CHECKSUM_LENGTH)


void printBytes(unsigned char *in, int inLen){
	int i;
	for(i=0;i<inLen;i++)
		printf("%2X", in[i]);
	printf("\n");
}

int sha256(unsigned char* out, unsigned char *in, int inLen){
	SHA256_CTX ctxSHA256;
	SHA256_Init(&ctxSHA256);
	SHA256_Update(&ctxSHA256, in, inLen);
	SHA256_Final(out, &ctxSHA256);

	return SHA256_DIGEST_LENGTH;
}

int ripemd160(unsigned char *out, unsigned char *in, int inLen){
	RIPEMD160_CTX ctxRIPEMD160;
	RIPEMD160_Init(&ctxRIPEMD160);
	RIPEMD160_Update(&ctxRIPEMD160, in, inLen);
	RIPEMD160_Final(out, &ctxRIPEMD160);

	return RIPEMD160_DIGEST_LENGTH;
}

unsigned char * createAddressBN(BIGNUM privKeyBN, unsigned char network){

	EC_KEY *eckey = EC_KEY_new_by_curve_name(NID_secp256k1);
	const EC_GROUP *group = EC_KEY_get0_group(eckey);

	BN_CTX *ctxBN = BN_CTX_new();
	EC_POINT *pubKeyPoint = EC_POINT_new(group);

	EC_POINT_mul(group, pubKeyPoint, &privKeyBN, NULL, NULL, ctxBN);

	BIGNUM pub;
	BN_init(&pub);
	EC_POINT_point2bn(group, pubKeyPoint, POINT_CONVERSION_UNCOMPRESSED, &pub, ctxBN);

	int sizeX = BN_num_bytes(&pub);
	char *pubMD = malloc(sizeof(char) * (sizeX + SHA256_DIGEST_LENGTH + SHA256_DIGEST_LENGTH + RNC));
	char *shaMD = pubMD + sizeX; //shaMD length = 32 bytes
	char *ripMD = pubMD + sizeX + SHA256_DIGEST_LENGTH; //sha256(ripMD) = 32 bytes
	char *step4 = pubMD + sizeX + SHA256_DIGEST_LENGTH  + SHA256_DIGEST_LENGTH; //ripemd160 + 1 network byte + 4 bytes checksum

	BN_bn2bin(&pub, pubMD);
	sha256(shaMD, pubMD, sizeX); //sha of privkey

	char *ripMD1 = ripMD + NETWORK_BYTE_LENGTH;
	ripemd160(ripMD1, shaMD, SHA256_DIGEST_LENGTH); //rip of sha of privkey
	ripMD[0] = network; //add network byte

	memcpy(step4, ripMD, RIPEMD160_DIGEST_LENGTH + NETWORK_BYTE_LENGTH); //save ripemd160

	sha256(ripMD, ripMD, RIPEMD160_DIGEST_LENGTH + NETWORK_BYTE_LENGTH); //hash of ripemd160
	sha256(ripMD, ripMD, SHA256_DIGEST_LENGTH);

	memcpy(step4 + RIPEMD160_DIGEST_LENGTH + NETWORK_BYTE_LENGTH, ripMD, CHECKSUM_LENGTH); //copy checksum

	int outLen;
	unsigned char *address = NBase58Encode(step4, RNC, &outLen);

	free(pubMD);
	BN_free(&pub);
	EC_POINT_free(pubKeyPoint);
	BN_CTX_free(ctxBN);
	EC_KEY_free(eckey);

	return address;
}

/* Private key must be sha256'ed before generating Bitcoin address*/
unsigned char * createAddress(const unsigned char *privKey, int privKeyLen, unsigned char networkPriv){

	BIGNUM privKeyBN;
	BN_init(&privKeyBN);
	BN_bin2bn(privKey, privKeyLen, &privKeyBN);

	unsigned char *c = createAddressBN(privKeyBN, networkPriv);

	BN_free(&privKeyBN);
	return c;
}

unsigned char * privateKeyToWIF(const unsigned char *privKey, int privKeyLen, unsigned char networkPriv){

	unsigned char *c = malloc(sizeof(char) * (NETWORK_BYTE_LENGTH + privKeyLen + CHECKSUM_LENGTH + SHA256_DIGEST_LENGTH));
	unsigned char *md = c + NETWORK_BYTE_LENGTH + privKeyLen + CHECKSUM_LENGTH;

	c[0] = networkPriv;
	memcpy(c + 1, privKey, privKeyLen);

	sha256(md, c, privKeyLen + 1); //sha of networkPriv + privKey
	sha256(md, md, SHA256_DIGEST_LENGTH);

	memcpy(c + privKeyLen + 1, md, 4); //checksum = first 4 bytes of md

	int outLen;
	unsigned char *wif = NBase58Encode(c, privKeyLen + 1 + 4, &outLen);

	free(c);

	return wif;
}

unsigned char* generateRandomAddress(unsigned char len, unsigned char step){

	int i;
	unsigned char *b = malloc(len);

	srand(time(NULL));
	for(i=0; i<len; i++){
		unsigned char c = rand() & 0xFF;
		c = ( c/step * step ) & 0xFF;
		b[i] =  c & (0xFF/step*step);
		//b[i] =  (0xFF/step*step); //change this to get worst case scenario (search all space) during bruteforcing
	}

	char *md = malloc(SHA256_DIGEST_LENGTH);
	sha256(md, b, len);
	char * wif = privateKeyToWIF(md, SHA256_DIGEST_LENGTH, BITCOIN_PRV);
	unsigned char *address = createAddress(md, SHA256_DIGEST_LENGTH, BITCOIN_PUB);


	unsigned char *d = sprintfVector(b, len);
	unsigned char *c = malloc(1024 + strlen(d));

	sprintf(c, "RND BYTES:\t%s\nADDRESS:\t%s\nPRIVKEY:\t%s [Wallet Import Format]\n", d, address, wif);
	printf("%s", c);

	free(c);
	free(d);
	free(wif);
	free(md);
	free(b);

	return address;
}
