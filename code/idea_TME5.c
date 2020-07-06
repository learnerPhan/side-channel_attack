#include "idea.h"
#include <stdint.h>
#include <stdlib.h>

#define IDLE 0
#define KEY 1
#define PLAIN 2



void key_schedule(uint8_t * tmp){

	int i;
	uint16_t  key[8];

	//uint8_t array to uint16_t array
	for(i=0;i<8;i++)
	   key[i] = (uint16_t)(tmp[2*i])<<8 ^ tmp[2*i+1];

	/* Insert the 8 first subkeys */
	for(i=0 ; i<8 ; i++) fullKey[i] = key[i];

	/* Insert the rotated subkeys line by line */
	for (i=8 ; i<52 ; i++) {
	    
	/* last case */
	if ( i%8 == 7 ) fullKey[i] = (fullKey[i-8-7] << 9) ^ (fullKey[i-8-6] >> 7);

	/* penultimate case */
	else if ( i%8 == 6 ) fullKey[i] = (fullKey[i-8+1] << 9) ^ (fullKey[i-8-6] >> 7);

	     /* general cases */
	     else fullKey[i] = (fullKey[i-8+1] << 9) ^ (fullKey[i-8+2] >> 7);
	    
	}

	//array uint16_t to array uint8_t
	for (i=0 ; i<52; i++){
	    tmp[2*i] = fullKey[i] >> 8;
	    tmp[2*i+1] = fullKey[i] & 0xff;

	}
	    
}


/* Print the full extended key */
void print_fullKey(void){

	printf("The full extended key used for encryption is :\n");

	int i,j;
	for (i=0; i<8; i++){
	    for (j=0 ; j<6; j++)  printf("0x%4.4x ",fullKey[6*i+j]);
            printf("\n");
	}	
	for (j=0 ; j<4; j++)  printf("0x%4.4x ",fullKey[6*i+j]);
	printf("\n");

}

uint16_t hi(uint16_t x) {
    return x >> 8;
}

uint16_t lo(uint16_t x) {
    return ((1L << 8) - 1) & x;
}

uint16_t multiply(uint16_t a, uint16_t b) {
    // actually uint32_t would do, but the casting is annoying
    uint16_t s0, s1, s2, s3; 

    uint16_t x = lo(a) * lo(b);
    s0 = lo(x);

    x = hi(a) * lo(b) + hi(x);
    s1 = lo(x);
    s2 = hi(x);

    x = s1 + lo(a) * hi(b);
    s1 = lo(x);

    x = s2 + hi(a) * hi(b) + hi(x);
    s2 = lo(x);
    s3 = hi(x);

    uint16_t result = s1 << 8 | s0;
    uint16_t carry = s3 << 8 | s2;

  return result;
}


uint16_t multMod (uint32_t a, uint32_t b) {       

	int64_t p;
	uint64_t q;

	uint32_t mod = (1<<16) + 1;

	 if (a==0) p = mod-b;
	     else if(b==0) p=p-a;
	          else {
		     q = a*b;
		     p = (q & 0xffff) - (q>>16);
		     if (p<0) p = p + mod;
		}

	return (uint16_t)(p & 0xffff);

}

uint16_t * blockCipher(uint16_t *cipher){

	int i;
	uint16_t d1,d2;
	
	for (i=0 ; i <=8; i++) {


	if(i==8)  // The last round condition : be a half round
	{
	    d1 = cipher[1];
	    cipher[0] = multMod(cipher[0], fullKey[6*i+0]);
	    cipher[1] = cipher[2] + fullKey[6*i+1];
	    cipher[2] = d1 + fullKey[6*i+2];
	    cipher[3] = multMod(cipher[3], fullKey[6*i+3]);
	
	    break;
	}
	    /* asm volatile(
		"nop"       "\n\t"
		"nop"       "\n\t"
		"nop"       "\n\t"
		"nop"       "\n\t"
		"nop"       "\n\t"
		"nop"       "\n\t"
		"nop"       "\n\t"
		"nop"       "\n\t"
		"nop"       "\n\t"
		"nop"       "\n\t"
"nop"       "\n\t"
		"nop"       "\n\t"
		"nop"       "\n\t"
		"nop"       "\n\t"
		"nop"       "\n\t"
		"nop"       "\n\t"
		"nop"       "\n\t"
		"nop"       "\n\t"
		"nop"       "\n\t"
		"nop"       "\n\t"
		::
		);
 asm volatile(
		"nop"       "\n\t"
		"nop"       "\n\t"
		"nop"       "\n\t"
		"nop"       "\n\t"
		"nop"       "\n\t"
		"nop"       "\n\t"
		"nop"       "\n\t"
		"nop"       "\n\t"
		"nop"       "\n\t"
		"nop"       "\n\t"
		"nop"       "\n\t"
		"nop"       "\n\t"
		"nop"       "\n\t"
		"nop"       "\n\t"
		"nop"       "\n\t"
		"nop"       "\n\t"
		"nop"       "\n\t"
		"nop"       "\n\t"
		"nop"       "\n\t"
		"nop"       "\n\t"
		::
		);*/
	    cipher[0] = multMod(cipher[0], fullKey[6*i+0]);
/*asm volatile(
		"nop"       "\n\t"
		"nop"       "\n\t"
		"nop"       "\n\t"
		"nop"       "\n\t"
		"nop"       "\n\t"
		"nop"       "\n\t"
		"nop"       "\n\t"
		"nop"       "\n\t"
		"nop"       "\n\t"
		"nop"       "\n\t"
"nop"       "\n\t"
		"nop"       "\n\t"
		"nop"       "\n\t"
		"nop"       "\n\t"
		"nop"       "\n\t"
		"nop"       "\n\t"
		"nop"       "\n\t"
		"nop"       "\n\t"
		"nop"       "\n\t"
		"nop"       "\n\t"
		::
		);
 asm volatile(
		"nop"       "\n\t"
		"nop"       "\n\t"
		"nop"       "\n\t"
		"nop"       "\n\t"
		"nop"       "\n\t"
		"nop"       "\n\t"
		"nop"       "\n\t"
		"nop"       "\n\t"
		"nop"       "\n\t"
		"nop"       "\n\t"
"nop"       "\n\t"
		"nop"       "\n\t"
		"nop"       "\n\t"
		"nop"       "\n\t"
		"nop"       "\n\t"
		"nop"       "\n\t"
		"nop"       "\n\t"
		"nop"       "\n\t"
		"nop"       "\n\t"
		"nop"       "\n\t"
		::
		);*/
	    cipher[1] += fullKey[6*i+1];
	    cipher[2] += fullKey[6*i+2];
	    cipher[3] = multMod(cipher[3], fullKey[6*i+3]);
	
	    d1 = cipher[0] ^ cipher[2];
	    d2 = cipher[1] ^ cipher[3];

	    /* Multiplication addition structure (MA) */
	    
d1 = multMod(d1,fullKey[6*i+4]);
	    
	    d2 += d1;
	    d2 = multMod(d2,fullKey[6*i+5]);
	    d1 += d2;

	    /* Conclusion of the round */
            cipher[0] ^= d2;
	    cipher[3] ^= d1;
	
	    d1 ^= cipher[1];
	    d2 ^= cipher[2];
	    
	    cipher[1] = d2; // cipher[2] = cipher[1] ^ d2
            cipher[2] = d1; // cipher[1] = cipher[2] ^ d1

	}
	
	
}

void IDEA_enc(uint8_t *pt, uint8_t* tmp){

	int i;
	uint16_t  plaintext[8], ciphertext[8];
	
	//array uint8_t to array uin55 34 f3 63 72 c0 9c f1t16_t de plaintext
	for(i=0;i<8;i++)
	   plaintext[i] = (uint16_t)(pt[2*i])<<8 ^ pt[2*i+1];
	

	//array uint8_t to array uint16_t de clef
	for(i=0;i<52;i++)
	   fullKey[i] = (uint16_t)(tmp[2*i])<<8 ^ tmp[2*i+1];

	
	blockCipher(&plaintext[4]);
	blockCipher(&plaintext[0]);

	//array uint16_t to array uint8_t
	for (i=0 ; i<8; i++){
	    pt[2*i] = plaintext[i] >> 8;
	    pt[2*i+1] = plaintext[i] & 0xff;

	}
	    
}


/*
int main(void){
	int i;
	uint8_t pt[16] = {'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p'};
	//
	uint8_t key[104] = {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
			    0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};

	key_schedule(key);
	
	for(i=0;i<104;++i)
		printf("%2.2x ", key[i]);

	printf("\n");

	IDEA_enc(pt, key);

	for(i=0;i<16;++i)
		printf("%2.2x ", pt[i]);

	printf("\n");


	return 0;
}*/



void usage(char* programename){
	printf("[!!] Usage : %s Not enought data\n", programename);
	exit(0);
}

void fatal(char* message){
	char error_message[75];
	strcpy(error_message, "[!!] Fatal Error in ");
	strncat(error_message, message, 50);
	//perror(error_message);
	exit(-1);
}

void* ec_malloc(unsigned int size){
	void * ptr;
	ptr=malloc(size);
	if(ptr==NULL)
		fatal("ec_malloc on allocation memory");
	return ptr;
}
