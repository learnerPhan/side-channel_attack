#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <stdint.h>
#include <pthread.h>

#define LGMAX 2000000
#define NSAMP 2200
#define NRES 6000
#define NBLK 16
/*
LGMAX : upper bound to retrieve a line of data
NSAMP : number of samples
NRES :  number of plaintexts (and datapoints results)
NBLK :  size of key and plaintext in byte
*/




/****************************************************************************************************
*** This structure will be used to list all the plaintexts and the datapoints corresponding *********
*****************************************************************************************************/

typedef struct {
   uint8_t plaintext[NBLK];
   double  * datapoints;
} result_t;


/***************************************************************************************
*** This structure will be used to differenciate the curves G0 and G1*******************
****************************************************************************************/

typedef struct {
   double * G;
   int size;
} class_t;




/**** global variables shared among threads****/
uint8_t key[NBLK];
result_t result[NRES];



/******************************************************************
*** The famous Sbox in AES, the star ******************************
*******************************************************************/

static const uint8_t Sbox[256] = {
  //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, // 0
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, // 1
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, // 2
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, // 3
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, // 4
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, // 5
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, // 6
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, // 7
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, // 8
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, // 9
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, // A
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, // B
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, // C
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, // D
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, // E
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16  // F

};


void usage(char*);
void fatal(char*);
void* ec_malloc(unsigned int);


/****************************************************************************************************************************
*** Given the results of Ghostwhisperer and the plaintext corresponding, this fuction puts them in the table of structure ***
*****************************************************************************************************************************/

void data_recovery(result_t * result, FILE * entree){

   char ligne[LGMAX]; 

   int i=0; // indexing the structure

   while(fgets(ligne, 70, entree)){

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


/*******************************************************************************************************
*** Given datapoints and its corresponding group G. The function adds the data to the group ************
********************************************************************************************************/

void classification(double * datapoints,double * G){
    int i;
    for(i=0;i<NSAMP; i++){
       G[i]+=datapoints[i];
    }
}  


/**************************************************************
*** This function gives the dpa table ************************
***************************************************************/

double update_dpa(double * G0,int size0, double *G1, int size1){

    int i;
    double mavg[NSAMP], k;

    for(i=0; i<NSAMP; i++){
	mavg[i] = fabs(G0[i]/size0 - G1[i]/size1);
    }

    k=mavg[0];

    for(i=1; i<NSAMP; i++){
	if(mavg[i]>k)
           k=mavg[i];
    }

   /* k=0;
    for(i=0; i<NSAMP; i++){
       k+=mavg[i]; 
   }*/

    return k;
}


/**************************************************************
*** This function gives the average of the  dpa table *********
***************************************************************/

double average(double * dpa){
     double avg=0;
     int i;

     for(i=0 ; i<NSAMP ; i++){
        avg+= dpa[i];
     }
     return fabs(avg)/NSAMP;
}


/**************************************************************
*** This function extracts the maximum in dpa_average table ***
***************************************************************/
int give_us_the_key(double * dpa_average){

   int i,k=0;

   for(i=1 ; i<256 ; i++)
       if(dpa_average[i]>=dpa_average[k])
          k=i;

   return k;
}

void* thread_task(void* idx)
{

  int *idd = (int*)idx; 
  int id = *idd; 

  double dpa[0xff]={0};
  class_t class[2];
  int j;
  class[0].G = ec_malloc(sizeof(double)*NSAMP);
  class[0].size=0;
  class[1].G = ec_malloc(sizeof(double)*NSAMP);
  class[1].size=0;
  int l,m=0;
  for(key[id]=0 ; key[id]<=0xff ; key[id]++)
  {   

        /* Reset the classes */
      class[0].size=0;
      class[1].size=0;
      for (l=0; l<NSAMP; ++l)
      {
	class[0].G[l] = 0;
	class[1].G[l] = 0;
      }

      for(j=0 ; j<NRES ; j++)
      {
        //get the first bit of the first round Sbox's output
        uint8_t ko = ((Sbox[key[id] ^ result[j].plaintext[id]])>>7);  
        //classfy the data according to this bit 
        classification(result[j].datapoints,class[ko].G);
        class[ko].size++;
      }

      dpa[key[id]]=update_dpa(class[0].G,class[0].size,class[1].G,class[1].size);    
      ++m;
      if (m==256)
       break;
  
  }
  int k =give_us_the_key(dpa);
  key[id]=k; 
  return NULL;
}


int main(int argc, char* argv[]){

  /************ File reading********/
	if(argc<2)
		usage(argv[0]);

	char* filename=ec_malloc(21);
	strncat(filename, argv[1], 20);

	FILE* entree = fopen(filename,"r");
	printf("[i:0] Lecture du fichier %s *****\n",filename);	

	data_recovery(result, entree);
	fclose(entree);

	printf("[i:1] Plaintexts and datapoints corresponding recovered *****\n");


  int i;
  int ids[NBLK];                          //threads id
  pthread_t threads_array[NBLK];          //array of threads

  /******** Threads creating *********/
	for(i=0; i<NBLK;i++)
  {
     ids[i] = i;
     if((pthread_create(&(threads_array[i]), NULL, thread_task, &(ids[i]))) != 0)
     {
      fatal("thread creating");
     }

   }

  /*
  Join threads, such that main thread waits the end
  of all child-threads to continue
  */
  for(i=0;i<NBLK;++i)
  {
    if(pthread_join(threads_array[i],NULL) != 0)
    {
      fatal("thread joining");
    }
  }

  for(i=0;i<NBLK;++i)
    printf("key[%d] = %.2x\n", i, key[i]);

  return 0;
}

void usage(char* programename){
	printf("Usage : %s [!!] Not enought data\n", programename);
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
