/*
    This file is part of the ChipWhisperer Example Targets
    Copyright (C) 2012-2015 NewAE Technology Inc.

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

#include "hal.h"
#include <stdint.h>
#include <stdlib.h>
#include "idea.h"

#include "aes-independant.h"

#define IDLE 0
#define KEY 1
#define PLAIN 2

char hex_lookup[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};

uint8_t* hex_decode(const char *in, int len,uint8_t *out)
{
        unsigned int i, t, hn, ln;

        for (t = 0,i = 0; i < len; i+=2,++t) {

                hn = in[i] > '9' ? (in[i]|32) - 'a' + 10 : in[i] - '0';
                ln = in[i+1] > '9' ? (in[i+1]|32) - 'a' + 10 : in[i+1] - '0';
                out[t] = (hn << 4 ) | ln;
        }
        return out;
}


void hex_print(const uint8_t * in, int len, char *out)
{
		unsigned int i,j;
		j=0;
		for (i=0; i < len; i++) {
			out[j++] = hex_lookup[in[i] >> 4];
			out[j++] = hex_lookup[in[i] & 0x0F];			
		}
		
		out[j] = 0;
}

#define BUFLEN KEY_LENGTH*4
//#define BUFLEN 16

uint8_t memory[BUFLEN];
char asciibuf[555];
uint8_t pt[16];
//Default key
//uint8_t tmp[KEY_LENGTH] = {DEFAULT_KEY};
uint8_t tmp[200]= {0};
char equals='e';

uint8_t testKey_idea[104] = {
 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
 0xcc, 0xdd, 0xee, 0xff, 0x66, 0x88, 0xaa, 0xcc, 0xef, 0x11, 0x33, 0x55,
 0x77, 0x99, 0xbb, 0xdd, 0xfe, 0x00, 0x22, 0x44, 0x99, 0xde, 0x22, 0x66,
 0xaa, 0xef, 0x33, 0x77, 0xbb, 0xfc, 0x00, 0x44, 0x88, 0xcd, 0x11, 0x55,
 0xcd, 0x55, 0xde, 0x66, 0xef, 0x77, 0xf8, 0x00, 0x89, 0x11, 0x9a, 0x22,
 0xab, 0x33, 0xbc, 0x44, 0xcd, 0xde, 0xef, 0xf0, 0x01, 0x12, 0x23, 0x34,
 0x45, 0x56, 0x67, 0x78, 0x89, 0x9a, 0xab, 0xbc, 0xe0, 0x02, 0x24, 0x46,
 0x68, 0x8a, 0xac, 0xce, 0xf1, 0x13, 0x35, 0x57, 0x79, 0x9b, 0xbd, 0xdf,
 0x8c, 0xd1, 0x15, 0x59, 0X9d, 0xe2, 0x26, 0x6a  
};

uint8_t testCipher_idea[16] = 
{
	0x09, 0x27, 0x0a, 0x21, 0xda, 0x8f, 0x52, 0x0a,
	0x7c, 0x22, 0x75, 0xaf, 0xa7, 0x55, 0xd9, 0x74
};

uint8_t testPt_idea[16] = {'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p'};

int main
	(
	void
	)
	{
        platform_init();
	init_uart();	
	trigger_setup();
	
 	/* Uncomment this to get a HELLO message for debug */
	
	/*
	putch('h');
	putch('e');
	putch('l');
	putch('l');
	putch('o');
	putch('\n');
	*/	

	/* Super-Crappy Protocol works like this:
	
	Send kKEY
	Send pPLAINTEXT
	*** Encryption Occurs ***
	receive rRESPONSE
	
	e.g.:
	
    kE8E9EAEBEDEEEFF0F2F3F4F5F7F8F9FA\n
	p014BAF2278A69D331D5180103643E99A\n
	r6743C3D1519AB4F2C0094 0048 006d 00f9 0008 004f 0006 006fD9A78AB09A511BD\n
    */
		
	char c;
	int ptr = 0;
    int p;
		
	char state = 0;
	 
	while(1){
	
		c = getch();
		
		if (c == 'x') {
			ptr = 0;
			state = IDLE;
			continue;		
		}
		
		if (c == 'k') {
			ptr = 0;
			state = KEY;			
			continue;
		}
		
		else if (c == 'p') {
			ptr = 0;
			state = PLAIN;
			continue;
		}
		
		
		else if (state == KEY) {
			if ((c == '\n') || (c == '\r')) {
				asciibuf[ptr] = 0;
				hex_decode(asciibuf, ptr, tmp);
				
				/*IDEA key schedule*/
				key_schedule(tmp);
				
				state = IDLE;
			} else {
				asciibuf[ptr++] = c;
			}
		}
		
		else if (state == PLAIN) {
			if ((c == '\n') || (c == '\r')) {
				asciibuf[ptr] = 0;
				hex_decode(asciibuf, ptr, pt);

				/* Do Encryption */	
				for(p=0;p<16;++p)
				{
					if(pt[p] != testPt_idea[p])
					{
						equals = 'n';
						break;
					}
				}
				putch(equals); 

				trigger_high();
//				aes_indep_enc(pt); /* encrypting the data block */
				IDEA_enc(pt,tmp); //tmp: clef etendue auparavant.
				trigger_low();

			       
				/* Print Results */
				hex_print(pt, 16, asciibuf);
				

				putch('r');
				for(int i = 0; i < 32; i++){
					putch(asciibuf[i]);
				}
				putch('\n');
				
				state = IDLE;
			} else {
                if (ptr >= BUFLEN){
        
                    state = IDLE;
                } else {
                    asciibuf[ptr++] = c;
                }
			}
		}
	}
		
	return 1;
	}
	
	
