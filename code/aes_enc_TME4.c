/* aes_enc.c */
/*
    This file is part of the AVR-Crypto-Lib.
    Copyright (C) 2008  Daniel Otte (daniel.otte@rub.de)

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
/**
 * \file     aes_enc.c
 * \email    daniel.otte@rub.de
 * \author   Daniel Otte 
 * \date     2008-12-30
 * \license  GPLv3 or later
 * 
 */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "aes.h"
#include "gf256mul.h"
#include "aes_sbox.h"
#include "aes_enc.h"
#include <avr/pgmspace.h>
//#include <time.h>
#include "/root/TME3/firmware/hal/hal.h"

//srand(time(NULL));
uint8_t X;
const uint8_t *newSbox;

/*
=> Ecrire le code dans FPGA
=> Capturer les traces, 1000
=> Attaquer avec CPA
=> Si K^X trouvé, faire varier X_i pour chaque exécution d'AES
=> changer FPGA, faire CPA, trouver clef??
*/

const uint8_t* generate_newSbox (uint8_t X_alea){

	uint8_t* new_aes_sbox;
	new_aes_sbox = (uint8_t*)malloc(256*sizeof(uint8_t));

	uint16_t i;

	for(i=0; i<256; ++i){
		//new_aes_sbox[i^X_alea] = aes_sbox[i]^X_alea;
		new_aes_sbox[i^X_alea] = pgm_read_byte(aes_sbox+i)^X_alea;

	}

	return new_aes_sbox;

}


void aes_shiftcol(void* data, uint8_t shift){
	uint8_t tmp[4];
	tmp[0] = ((uint8_t*)data)[ 0];
	tmp[1] = ((uint8_t*)data)[ 4];
	tmp[2] = ((uint8_t*)data)[ 8];
	tmp[3] = ((uint8_t*)data)[12];
	((uint8_t*)data)[ 0] = tmp[(shift+0)&3];
	((uint8_t*)data)[ 4] = tmp[(shift+1)&3];
	((uint8_t*)data)[ 8] = tmp[(shift+2)&3];
	((uint8_t*)data)[12] = tmp[(shift+3)&3];
}
#define GF256MUL_1(a) (a)
#define GF256MUL_2(a) (gf256mul(2, (a), 0x1b))
#define GF256MUL_3(a) (gf256mul(3, (a), 0x1b))


void aes_enc_round(aes_cipher_state_t* state, const aes_roundkey_t* k){
	uint8_t tmp[16], t;
	uint8_t i;

	/* subBytes */
	for(i=0; i<16; ++i){
		
		//tmp[i] = pgm_read_byte(aes_sbox+state->s[i]) ^ X;
		tmp[i] = newSbox[state->s[i]];
		
	}
	
	uint8_t sum = 0;
	
	/* shiftRows */
	aes_shiftcol(tmp+1, 1);
	aes_shiftcol(tmp+2, 2);
	aes_shiftcol(tmp+3, 3);
	/* mixColums */
	for(i=0; i<4; ++i){
		t = tmp[4*i+0] ^ tmp[4*i+1] ^ tmp[4*i+2] ^ tmp[4*i+3];
		state->s[4*i+0] =
			  GF256MUL_2(tmp[4*i+0]^tmp[4*i+1])
			^ tmp[4*i+0]
			^ t;
		state->s[4*i+1] =
			  GF256MUL_2(tmp[4*i+1]^tmp[4*i+2])
			^ tmp[4*i+1]
			^ t;
		state->s[4*i+2] =
			  GF256MUL_2(tmp[4*i+2]^tmp[4*i+3])
			^ tmp[4*i+2]
			^ t;
		state->s[4*i+3] =
			  GF256MUL_2(tmp[4*i+3]^tmp[4*i+0])
			^ tmp[4*i+3]
			^ t;
	}

	/* addKey */
	for(i=0; i<16; ++i){
		state->s[i] ^= k->ks[i];
		//state->s[i] ^= X;
	}
	
}


static
void aes_enc_lastround(aes_cipher_state_t* state,const aes_roundkey_t* k){
	uint8_t i;
	/* subBytes */
	for(i=0; i<16; ++i){
		//state->s[i] = pgm_read_byte(aes_sbox+state->s[i]) ^ X;
		state->s[i] = newSbox[state->s[i]] ;

	}
	/* shiftRows */
	aes_shiftcol(state->s+1, 1);
	aes_shiftcol(state->s+2, 2);
	aes_shiftcol(state->s+3, 3);
	/* keyAdd */
	for(i=0; i<16; ++i){
		state->s[i] ^= k->ks[i];
		state->s[i] ^= X;
	}
}

void aes_encrypt_core(aes_cipher_state_t* state, const aes_genctx_t* ks, uint8_t rounds){

	uint8_t i;	
	
	//X = rand();
	X = 30;
	newSbox = generate_newSbox(X);
	
	for(i=0; i<16; ++i)
		state->s[i] = state->s[i] ^ ks->key[0].ks[i] ^ X ; // state masked

		
	i=1;
	
	for(;rounds>1;--rounds){

		aes_enc_round(state, &(ks->key[i]));
		++i;
		
	}
	aes_enc_lastround(state, &(ks->key[i]));
}
