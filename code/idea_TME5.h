#ifndef IDEA_
#define IDEA_


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <stdint.h>

//uint16_t key[8] = {0x0064, 0x00c8, 0x012c, 0x0190, 0x01f4, 0x0258, 0x02bc, 0x0320};
//uint16_t key[8] = {0x0011, 0x2233, 0x4455, 0x6677, 0x8899, 0xaabb, 0xccdd, 0xeeff};
uint16_t fullKey[52];


void key_schedule(uint8_t * tmp);

uint16_t multMod (uint32_t r1, uint32_t r2);

uint16_t * blockCipher(uint16_t *plaintext);

void usage(char*);

void fatal(char*);

void* ec_malloc(unsigned int);

void IDEA_enc(uint8_t *pt, uint8_t *tmp);
#endif
