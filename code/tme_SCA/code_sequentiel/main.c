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


int hamming_weigth(uint8_t k){
	int i, w_H=0;

	for(i=0; i<8; i++){
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


double correlationCoefficient(double ** actualPower, double *hammingPower){

	int s;
        double coeff_Pearson[NSAMP];

	for(s=0 ; s<NSAMP; s++)	
	    coeff_Pearson[s] = getCorCoef(actualPower[s],hammingPower,NRES);

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



/* DPA ATTACK */
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
           printf("0x%2.2x ",key[i]);
	printf("]\n");
}

/* CPA ATTACK */
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


	      double hammingPower[NRES]={0};

	      for(j=0 ; j<NRES ; j++){
		 uint8_t k = Sbox[key[i] ^ result[j].plaintext[i]];
		 hammingPower[j] = hamming_weigth(k);		 
              }

	      cpa[key[i]] = correlationCoefficient(&actualPower[0],hammingPower);

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

	if(argc<2)
		usage(argv[0]);

	char* filename=ec_malloc(100);
	char* cpa_scores=ec_malloc(100);
	char* dpa_scores=ec_malloc(100);

	strncat(filename, argv[1], 20);

	FILE* entree = fopen(filename,"r");
	printf("[i:0] Lecture du fichier %s *****\n",filename);	

	result_t result[NRES];
	data_recovery(result, entree);
	fclose(entree);

	printf("[i:1] Plaintexts and datapoints corresponding recovered *****\n");

	strncat(dpa_scores, "dpa_scores_", 50);
	strncat(cpa_scores, "cpa_scores_", 50);

	strncat(dpa_scores, argv[1], strlen(argv[1])-4);
	strncat(cpa_scores, argv[1], strlen(argv[1])-4);

	
	/* Execute sequentially dpa_attack function */

	char *graphname=ec_malloc(100);

	sprintf(graphname,"./scores.sh %s",dpa_scores);

	FILE* output1 = fopen(dpa_scores, "w");
	dpa_attack(result, output1);
	system(graphname);
        fclose(output1);

	/* Execute sequentially cpa_attack function */

	sprintf(graphname,"./scores.sh %s",cpa_scores);

	FILE* output2 = fopen(cpa_scores, "w");	
	cpa_attack(result, output2);
	system(graphname);
	fclose(output2);

	return 0;
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
