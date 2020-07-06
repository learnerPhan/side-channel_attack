#include "sca.h"

void data_recovery(result_t * result, FILE * entree){

   char ligne[LGMAX]; 

   int i=0; // indexing the structure

   while(fgets(ligne, 70, entree) && i<NRES){

      /* convert the string to uint8_t tab for the plaintext */
      int j=0;
      char *c=&ligne[0];
      result[i].plaintext[j++]=atoi(c);

      while(*c!='\0'){
	 if(*c==',') {
	   result[i].plaintext[j++]=atoi(c+1);
          }
          c++;
      }
	
      if(!fgets(ligne, LGMAX, entree))
         fatal("datapoints recovery");

      /* convert the string to float tab for the datapoints */   
  
      j=0;
      c=&ligne[0];
      char *cc=ec_malloc(sizeof(double)); // buffer for saving characters step by step
      result[i].datapoints=ec_malloc(sizeof(double)*NSAMP);

      while(*c!='\0'){
	 if(*c==',' || *c=='\n') {
           result[i].datapoints[j++]=atof(cc);
	   cc=ec_malloc(sizeof(double));    
      
          }else strncat(cc,c,1);
          c++;
      }
      i++;
   }
}

/* DPA ATTACK functions FOR AES */
void classification(double * datapoints,double * G){
    int i;
    for(i=0;i<NSAMP; i++){
       G[i]+=datapoints[i];
    }
}  


double update_dpa(double * G0,int size0, double *G1, int size1){

    int i;
    double mavg[NSAMP], k;

    for(i=0; i<NSAMP; i++)
	mavg[i] = fabs(G0[i]/size0 - G1[i]/size1);

    k=mavg[0];

    for(i=1; i<NSAMP; i++){
	if(mavg[i]>k)
           k=mavg[i];
    }

    return k;
}


/* CPA ATTACK functions  */
int hamming_weigth(uint8_t k){
	int i, w_H=0;

	for(i=0; i<8; i++){
           w_H+=k&1;
	   k=k>>1;
	}

	return w_H;
}

int hamming_weigth16(uint16_t k){
	int i, w_H=0;

	for(i=0; i<16; i++){
           w_H+=k&1;
	   k=k>>1;
	}

	return w_H;
}

double getCorCoef(double *X, double *Y, int size)
{
	double a=0,b=0,c=0,d=0,e=0;
	int i;
	for (i=0; i<size; ++i)
	{
		a+=X[i]*Y[i];
		b+=X[i];
		c+=Y[i];
		d+=X[i]*X[i];
		e+=Y[i]*Y[i];
	}
	return fabs(size*a - b*c)/((b*b-size*d)*(c*c-size*e));
}

double correlationCoefficient(double ** actualPower, double *hammingVector){

	int s;
        double coeff_Pearson[NSAMP];

	for(s=0 ; s<NSAMP; s++)	
	    coeff_Pearson[s] = getCorCoef(actualPower[s],hammingVector,NRES);

	/* extract the maximum */
	double max_coeff=coeff_Pearson[0];

	for(s=1; s<NSAMP; s++)
	   if(fabs(coeff_Pearson[s])>(max_coeff))
	      max_coeff=coeff_Pearson[s];

	return fabs(max_coeff);

}

/* This function extracts the maximum from a table */
int give_us_the_key(double * tab){

   int i,k=0;

   for(i=1 ; i<256 ; i++)
       if(tab[i]>=tab[k])
          k=i;

   return k;
}

/* DPA ATTACK ON AES */
void dpa_attack(result_t * result, FILE * sortie){

        class_t class[2];
	class[0].G = ec_malloc(sizeof(double)*NSAMP);
	class[0].size=0;
	class[1].G = ec_malloc(sizeof(double)*NSAMP);
	class[1].size=0;

	uint8_t key[NBLK];
        int i,j,m;

	char *buf, *lines;
	lines=ec_malloc(10000);
	buf=ec_malloc(10000);

	strncat(lines, "# data given after dpa attack for each key guess for each byte\n", 100);

	for(i=0; i<NBLK;i++){

	   sprintf(buf, "# block %i\n",i);
	   strncat(lines, buf, 30);

	   double dpa[256]={0};
	   m=0;

	   for(key[i]=0 ; key[i]<256 ; key[i]++){	
	      sprintf(buf, "%i ",key[i]);
	      strncat(lines, buf, 30);  

              /* Reset the classes */
	      class[0].G = ec_malloc(sizeof(double)*NSAMP);
              class[1].G = ec_malloc(sizeof(double)*NSAMP);
	      class[0].size=0;
	      class[1].size=0;

	      for(j=0 ; j<NRES ; j++){
	         uint8_t k = ((Sbox[key[i] ^ result[j].plaintext[i]])>>7); 
		 classification(result[j].datapoints,class[k].G); 
	         class[k].size++;
              }

              dpa[key[i]]=update_dpa(class[0].G,class[0].size,class[1].G,class[1].size); 

	      sprintf(buf, "%f\n",dpa[key[i]]*100000);
	      strncat(lines, buf, 30);  

  	      ++m;
              if (m==256)
		break;
	   }

           key[i]=give_us_the_key(dpa);


	   printf("Bloc %i : 0x%2.2x\n",i,key[i]);

	   strncat(lines, "\n\n", 30); 
	   if(!fputs(lines,sortie))
	      fatal("writting file");

	   lines=ec_malloc(10000);	   
        }


	printf("Secret key found :\n[");
        for(i=0; i<NBLK; i++)
           printf("0x%4.4x ",key[i]);
	printf("]\n");
}

/* CPA ATTACK ON AES */
void cpa_attack(result_t * result, FILE * sortie){

	uint8_t key[NBLK];
	double * actualPower[NSAMP];
        int i,j,s,m;

	char *buf, *lines;
	lines=ec_malloc(10000);
	buf=ec_malloc(10000);

	strncat(lines, "# data given after dpa attack for each key guess for each byte\n", 100);

	for(s=0; s<NSAMP; s++)
	   actualPower[s]=calloc(NRES,sizeof(double)); 

	for(s=0; s<NSAMP; s++)
	   for(j=0; j<NRES; j++)
	       actualPower[s][j] = result[j].datapoints[s];


	for(i=0; i<NBLK;i++){

	   sprintf(buf, "# block %i\n",i);
	   strncat(lines, buf, 30);

	   double cpa[256]={0};
	   m=0;

	   for(key[i]=0 ; key[i]<256 ; key[i]++){	

	      sprintf(buf, "%i ",key[i]);
	      strncat(lines, buf, 30);


	      double hammingVector[NRES]={0};

	      for(j=0 ; j<NRES ; j++){
		 uint8_t k = Sbox[key[i] ^ result[j].plaintext[i]];
		 hammingVector[j] = hamming_weigth(k);		 
              }

	      cpa[key[i]] = correlationCoefficient(&actualPower[0],hammingVector);

	      sprintf(buf, "%f\n",cpa[key[i]]*100000);
	      strncat(lines, buf, 30); 

  	      ++m;
              if (m==256)
		break;

	   }

           key[i]=give_us_the_key(cpa);

	   printf("Bloc %i : 0x%2.2x\n",i,key[i]);

	   strncat(lines, "\n\n", 30); 
	   if(!fputs(lines,sortie))
	      fatal("writting file");

	   lines=ec_malloc(10000);
        }

	printf("Secret key found :\n[");
        for(i=0; i<NBLK; i++)
           printf("0x%2.2x ",key[i]);
	printf("]\n");
}

int main(int argc, char* argv[]){

	if(argc<1)
		usage(argv[0]);

	if(argc<2) { /* CPA ATTACK ON IDEA */

		int i;

		result_t result[4][NRES];

		for (i=0; i<4; i++){

		    FILE* entree = fopen(idea_filename[i],"r");
		    printf("[i:%i] Loading file %i : %s *****\n",i,i,idea_filename[i]);
		    data_recovery(result[i], entree);
		    fclose(entree);

		}

		printf("[i:4] Plaintexts and datapoints corresponding recovered *****\n");
		printf("[i:5] We will print the results of CPA attack on IDEA *******\n\n");

		cpa_attack_idea(result[0],0);

		printf(" Key found is : [ 0x ");
		for(i=0 ; i<8 ; i++) printf("%4.4x ",idea_key_found[i]);
		printf("]\n\n");

		return 0;
	}

	/* ATTACKS ON AES */
	
	char* filename=ec_malloc(100);
	char* cpa_scores=ec_malloc(100);
	char* dpa_scores=ec_malloc(100);

	strncat(filename, argv[1], 20);

	FILE* entree = fopen(filename,"r");
	printf("[i:0] Loading file : %s *****\n",filename);	

	result_t result[NRES];
	data_recovery(result, entree);
	fclose(entree);

	printf("[i:1] Plaintexts and datapoints corresponding recovered *****\n");
	printf("[i:2] We will print the results of Power analysis attacks on AES *******\n");
	
	if(filename[0] == 'X'){
		strncat(dpa_scores, "Xdpa_", 50);
		strncat(cpa_scores, "Xcpa_", 50);
	
	}else {	
		strncat(dpa_scores, "dpa_", 50);
		strncat(cpa_scores, "cpa_", 50);
	}

	char buf[30];

	sprintf(buf, "_t%u_s%u",NRES,NSAMP);

	strncat(dpa_scores, argv[1], strlen(argv[1])-4);
	strncat(dpa_scores, buf, strlen(buf));
	strncat(cpa_scores, argv[1], strlen(argv[1])-4);
	strncat(cpa_scores, buf, strlen(buf));

	clock_t t1,t2;

	/* Execute sequentially dpa_attack function */

	char *graphname=ec_malloc(100);

	sprintf(graphname,"./scores.sh %s",dpa_scores);

	FILE* output1 = fopen(dpa_scores, "w");
	printf("[i:3] DPA attack is run\n");
	t1=clock();
	dpa_attack(result, output1);
	t2=clock();
	printf("Run time  : %f s\n",(float)(t2-t1)/CLOCKS_PER_SEC);
	system(graphname);
        fclose(output1);

	/* Execute sequentially cpa_attack function */

	sprintf(graphname,"./scores.sh %s",cpa_scores);

	FILE* output2 = fopen(cpa_scores, "w");	
	printf("[i:4] CPA attack is run\n");
	t1=clock();
	cpa_attack(result, output2); 
	t2=clock();
	printf("Run time : %f s\n",(float)(t2-t1)/CLOCKS_PER_SEC);
	system(graphname);
	fclose(output2);

	return 0;
}



/* Multiplication mod 2^16 + 1 */

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

uint16_t *  OneRoundCipher(uint16_t * pt, uint16_t * subkey, int tag){

	int i,j;
	uint16_t d1,d2, *cipher, *k;

	cipher = ec_malloc(4*sizeof(uint16_t));
	k=ec_malloc(sizeof(uint16_t));

	    /* First steps of the round for X1 and X3 */
	    *k = cipher[0] = multMod(pt[0], subkey[0]);
	    //printf("pt0 = %u , subkey : %u--> k = %u , c = %u\n",pt[0],subkey[0],*k,cipher[0]);
	    if(tag == Mattack1) return k;

	    cipher[2] = pt[2] + subkey[2];
	    d1 = cipher[0] ^ cipher[2];

	    /* MA for d1 */
	    *k = d1 = multMod(d1,subkey[4]);
	    if(tag == MAattack1) return k; 
	
	    /* First steps of the round for X2 and X4 */
	    cipher[1] = pt[1] + subkey[1];
	    cipher[3] = multMod(pt[3], subkey[3]);
	    d2 = cipher[1] ^ cipher[3];

	    /* MA for d2 */
	    d2 += d1;
	    *k = d2 = multMod(d2,subkey[5]);
	    if(tag == MAattack2) return k;	

	    d1 += d2;

	    /* Conclusion of the round */
            cipher[0] ^= d2;
	    cipher[3] ^= d1;
	
	    d1 ^= cipher[1];
	    d2 ^= cipher[2];
	    
	    cipher[1] = d2; // cipher[2] = cipher[1] ^ d2
            cipher[2] = d1; // cipher[1] = cipher[2] ^ d1
	
	return cipher;

}

/* CPA ATTACK  ON IDEA for subkeys 1 3 5 over the round round */

void cpa_attack_idea(result_t * result, int round){

	printf(" We attack on the first part of MA of the round %i\n",round);

	uint16_t subkey[6]={0};
	double * actualPower[NSAMP];
        int i,j,s,m;

	for(s=0; s<NSAMP; s++)
	   actualPower[s]=calloc(NRES,sizeof(double)); 

	for(s=0; s<NSAMP; s++)
	   for(j=0; j<NRES; j++)
	       actualPower[s][j] = result[j].datapoints[s];

	//for(i=0; i<6;i+=2){
	for(i=0; i<1;i+=2){ // just for K1

	   double cpa[65536]={0};
	   m=0;

	   for(subkey[i]=0 ; subkey[i]<65536 ; subkey[i]++){	

	      double hammingVector[NRES]={0};

	      for(j=0 ; j<NRES ; j++){

		uint16_t *k, *pt=ec_malloc(4*sizeof(uint16_t));

		pt[0] = (uint16_t)(result[j].plaintext[0])<<8 ^ result[j].plaintext[1]; // X1
		pt[1] = (uint16_t)(result[j].plaintext[2])<<8 ^ result[j].plaintext[3]; // X2
		pt[2] = (uint16_t)(result[j].plaintext[4])<<8 ^ result[j].plaintext[5]; // X3
		pt[3] = (uint16_t)(result[j].plaintext[6])<<8 ^ result[j].plaintext[7]; // X4

		if(round==1) pt = OneRoundCipher(pt, idea_key_found, JustCipher);	// At the second round we have to cipher the block

	        //k=OneRoundCipher(pt, subkey, MAattack1); // output of MultMod for F1
	        k=OneRoundCipher(pt, subkey, Mattack1); // output of MultMod for F1
		hammingVector[j] = hamming_weigth16(*k);	
	 
              }

	      cpa[subkey[i]] = correlationCoefficient(&actualPower[0],hammingVector); // For each sample compute the rho and return the max

  	      ++m;
              if (m==65536)
		break;

	   }
           idea_key_found[i+6*round] = subkey[i]=give_us_the_key(cpa); // Return the max of the cpa table
        }

	printf(" Subkeys found are : 0x ");
	for (i=0; i<6 ; i++) printf("%4.4x ",subkey[i]);
	printf("\n\n");

	/* We hope found K1, K3 and K5 */
	//cpa_attack_idea2(result+NRES,subkey,round);

}

/* CPA ATTACK  ON IDEA for subkeys 2 4 6 */

void cpa_attack_idea2(result_t * result, uint16_t * subkey, int round){

	printf(" We attack on the second part of MA of the round %i\n",round);

	double * actualPower[NSAMP];
        int i,j,s,m;

	for(s=0; s<NSAMP; s++)
	   actualPower[s]=calloc(NRES,sizeof(double)); 

	for(s=0; s<NSAMP; s++)
	   for(j=0; j<NRES; j++)
	       actualPower[s][j] = result[j].datapoints[s];

	for(i=1; i<6;i+=2){

	   double cpa[65536]={0};
	   m=0;

	   for(subkey[i]=0 ; subkey[i]<65536 ; subkey[i]++){	

	      double hammingVector[NRES]={0};

	      for(j=0 ; j<NRES ; j++){

		uint16_t *k, *pt=ec_malloc(4*sizeof(uint16_t));
		pt[0] = (uint16_t)(result[j].plaintext[0])<<8 ^ result[j].plaintext[1]; // X1
		pt[1] = (uint16_t)(result[j].plaintext[2])<<8 ^ result[j].plaintext[3]; // X2
		pt[2] = (uint16_t)(result[j].plaintext[4])<<8 ^ result[j].plaintext[5]; // X3
		pt[3] = (uint16_t)(result[j].plaintext[6])<<8 ^ result[j].plaintext[7]; // X4

		k = OneRoundCipher(pt, subkey, MAattack2);
		hammingVector[j] = hamming_weigth16(*k);
		if(round==1) pt = OneRoundCipher(pt, idea_key_found, JustCipher);    // At the second round we have to cipher the block

		/*if(round==1 && i == 1 && subkey[i] ==0){ // For verifying the good encrytion round

			pt[0] = 0x0532;
			pt[1] = 0x0a64;
			pt[2] = 0x14c8;
			pt[3] = 0x19fa;
	
			subkey[0] = 0x0064;
			subkey[1] = 0x00c8;
			subkey[2] = 0x012c;
			subkey[3] = 0x0190;
			subkey[4] = 0x01f4;
			subkey[5] = 0x0258;

			pt = OneRoundCipher(pt, subkey, JustCipher);

			int p;printf("Chiffrement du bloc : 0x");
			for(p=0; p<4; p++) printf("%4.4x", pt[p]);
			printf("\n");

		}*/

	     }
	      cpa[subkey[i]] = correlationCoefficient(&actualPower[0],hammingVector);

  	      ++m;
              if (m==65536)
		break;

	   }

           if(i+6*round<8) idea_key_found[i+6*round] = subkey[i]=give_us_the_key(cpa);

        }

	printf(" Subkeys found are : 0x ");
	for (i=0; i<6 ; i++) printf("%4.4x ",subkey[i]);
	printf("\n\n");

	if(round == 1) return;

	cpa_attack_idea(result+NRES,round+1);

}

void usage(char* programename){
	printf("[!!] Usage : %s Not enought data\n", programename);
	exit(0);
}

void fatal(char* message){
	char error_message[75];
	strcpy(error_message, "[!!] Fatal Error in ");
	strncat(error_message, message, 50);
	perror(error_message);
	exit(-1);
}

void* ec_malloc(unsigned int size){
	void * ptr;
	ptr=malloc(size);
	if(ptr==NULL)
		fatal("ec_malloc on allocation memory");
	return ptr;
}
