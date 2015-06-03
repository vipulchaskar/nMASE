//Sample usage - $./bitmap_search_comp.o 192 168 -1 -1 80 <slot path>
//This is equivalent to searching for 192.168.*.*:80
//Port number 0 stands for 'any'
//e.g. $./bitmap_search_comp.o 192 168 1 100 0 2014/9/4/21/
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#include "include/bitmaps.h"
#include "include/bitmaps.c"

void search_comp_bitmap(char *ipfilename, char *portfilename, u_int8_t IP[], u_int16_t portno, int no_octets)
{
	int i,j,k,ipfile,portfile,flag;
	u_int32_t pStartLoc[65536];						//Structure to store offsets of 65k bit vectors of port bitmap
	u_int32_t iStartLoc[4][256];					//Structure to store offsets of 256x4 bit vectors of IP bitmap
	u_int32_t iselected[4][NO_FLOWS/BYTES_IN_WORD];	//Structure to hold selected bit vectors to be ANDed (from IP bitmap)
	u_int32_t pselected[NO_FLOWS/BYTES_IN_WORD];	//Structure to hold selected bit vector to be ANDed (from port bitmap)
	u_int32_t curIPWord[4],curPortWord=0,result;	//pointers to the currently considered words in IP bit vector and port bit vector
	
	if((ipfile = open(ipfilename,O_RDONLY)) == -1)
	{
		printf("\nError opening IP file %s",ipfilename);
		return;
	}
	if((portfile = open(portfilename,O_RDONLY)) == -1)
	{
		printf("\nError opening port file %s",portfilename);
		return;
	}
	
	printf("Header bytes from IP file : %d\n",(int)read(ipfile,iStartLoc,sizeof(iStartLoc)));//Read offset values of IP bitmap
	printf("Header bytes from port file : %d\n",(int)read(portfile,pStartLoc,sizeof(pStartLoc)));//Read offset values of port bitmap
	
	for(i=0; i<no_octets; i++)		//Read the selected IP bit vectors into iselected
	{
		lseek(ipfile,sizeof(iStartLoc)+iStartLoc[i][IP[i]],SEEK_SET);
		printf("\nFor octet %d read %d bytes",i,(int)read(ipfile,iselected[i],(iStartLoc[i][IP[i]+1] - iStartLoc[i][IP[i]])));
	}
	
	if(portno != 0)				//Read the selected port bit vector into pselected, if any
	{
		lseek(portfile,sizeof(pStartLoc)+pStartLoc[portno],SEEK_SET);
		printf("\nFor port %" PRIu16 " read %d bytes",portno,(int)read(portfile,pselected,(pStartLoc[portno+1] - pStartLoc[portno])));
	}
	
	/*printf("\nSelected candidates:");
	for(i=0; i<no_octets; i++)
	{
		printf(" %" PRIu32 " %" PRIu32 " %" PRIu32 " %" PRIu32 "\n",iselected[i][0],iselected[i][1],iselected[i][2],iselected[i][3]);
	}
	printf(" %" PRIu32 " %" PRIu32 " %" PRIu32 " %" PRIu32 "\n",pselected[0],pselected[1],pselected[2],pselected[3]);*/
	
	for(j=0; j<(NO_FLOWS/BYTES_IN_WORD); j++)		//Iterate through all words in bitmap
	{
		flag=0;
		//printf("\nIteration number : %d",j);
		
		for(i=0; i<no_octets; i++)			//Check if any current word from selected bit vectors is fill word
		{
			if(isFill(iselected[i][curIPWord[i]]))
			{
				//printf("\nOctet no %d spoiled the party.",i);
				flag=1;
			}
		}
		if(portno != 0)
		{
			if(isFill(pselected[curPortWord]))
			{
				//printf("\nPort no. spoiled the party."); 
				flag=1;
			}
		}
		
		if(flag==1)			//If any of the current words is fill word, no point in proceeding
		{
			for(i=0; i<no_octets; i++)
			{
				if(isFill(iselected[i][curIPWord[i]]))	//Decrement the value inside fill word
				{
					//printf("\n%d is a fill word.",i);
					if((iselected[i][curIPWord[i]] & 0x7FFFFFFF) == 1)//If value reaches 1, increment to next word in bit vector
					{
						//printf("\nIt was the only one. no merged.");
						curIPWord[i]++;
					}
					else			//Else, decrement value inside fill word by 1
					{
						//printf("\nIt was merged. one removed.");
						iselected[i][curIPWord[i]]--;
					}
				}
				else				//If literal word, directly increment to next word
				{
					//printf("\n%d turned out to be a literal word.",i);
					curIPWord[i]++;
				}
			}
			
			if(portno != 0)
			{
				if(isFill(pselected[curPortWord]))	//If current word in port bit vector is fill word,
				{
					//printf("\nPort word %d is a fill word. Which is %" PRIu32,curPortWord,pselected[curPortWord]);
					
					//printf("\nThat expression is %u",(~(1<<(BYTES_IN_WORD-1)) ));
					if((pselected[curPortWord] & 0x7FFFFFFF ) == 1)	//If value in fill word reaches 1, take next word
					{
						//printf("\nIt was the only one. no merged.");
						curPortWord++;
					}
					else				//Otherwise reduce value in fill word by 1
					{
						//printf("\nPort no. It was merged. one removed.");
						pselected[curPortWord]--;
					}
				}
				else				//Otherwise, jump over literal
				{
					//printf("\nTurned out to be literal word.. port");
					curPortWord++;
				}
			}
		}
		else		//All of the currently pointed words are literals
		{
			//printf("\nParty is on.");
			//printf("\nguests are : %" PRIu32 " %" PRIu32 " %" PRIu32 " %" PRIu32 " %" PRIu32,iselected[0][curIPWord[0]],iselected[1][curIPWord[1]],iselected[2][curIPWord[2]],iselected[3][curIPWord[3]],pselected[curPortWord]);
			result = 0xFFFFFFFF;
			
			for(i=0; i<no_octets; i++)			//AND them one by one
				result = result & iselected[i][curIPWord[i]];
				
			if(portno != 0)
				result = result & pselected[curPortWord];
			
			if(result != 0)					//If some bits in result is set,
			{
				//printf("\nResult has some bits set.");
				for(k=(BITS_IN_WORD-2); k>=0; k--)	//find out which bit is set
					if((result & 1<<k) != 0)	//and display corresponding flow number
					{
						printf("\nMatching flow no. %d found!",j*(BITS_IN_WORD-1) + (BITS_IN_WORD-1-k)); 
					}
			}
			
			curIPWord[0]++;					//Increment the current word pointers
			curIPWord[1]++;
			curIPWord[2]++;
			curIPWord[3]++;
			curPortWord++;
		}
		
	}
	
	
	close(ipfile);
	close(portfile);
}



int main(int argc, char *argv[])
{
	u_int8_t IP[4] = {0};
	u_int16_t portno;
	int no_octets=0,i;
	char basepath[20],ipath[50],ppath[50];
	
	if(argc != 7)	//Program name + 4 Octets + Port number + Slot path
	{
		printf("\nIncorrect no. of arguments supplied. %d",argc);
		return 0;
	}
	
	for(i=0; i<4; i++)			//Parse the IP address
		if(strcmp(argv[i+1],"-1") != 0)
		{
			IP[i] = (u_int8_t)atoi(argv[i+1]);
			no_octets++;
		}
	
	portno = (u_int16_t)atoi(argv[5]);	//Parse the port number

	strcpy(basepath,argv[6]);
		
	printf("\nInput given : %" PRIu8 " %" PRIu8 " %" PRIu8 " %" PRIu8 " : %" PRIu16 " in %s\n",IP[0],IP[1],IP[2],IP[3],portno,basepath);	

	sprintf(ipath,"%sIP_src-comp.bitmap",basepath);
	sprintf(ppath,"%sport_src-comp.bitmap",basepath);
	printf("\n\nSearch in compressed bitmap : \n");
	search_comp_bitmap(ipath,ppath,IP,portno,no_octets);
	
	return 0;
}
