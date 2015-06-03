//Sample usage - $./bitmap_search_comp.o 192 168 -1 -1 80 192 168 1 100 0 <slot path>
//format - $./bitmap_search_comp.o <sip1> <sip2> <sip3> <sip4> <sprt> <dip1> <dip2> <dip3> <dip4> <dprt> <slot path>
//This is equivalent to searching for 192.168.*.*:80
//Port number 0 stands for 'any'
//e.g. $./bitmap_search_comp.o 192 168 1 100 0 -1 -1 -1 -1 0 2014/9/4/21/
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#include "include/bitmaps.h"
#include "include/bitmaps.c"

int smatched[NO_FLOWS*8],sptr=0;
int dmatched[NO_FLOWS*8],dptr=0;

/*	This function takes the output of two or more matching bitmaps and performs
	AND operation on them to select only the flow records matching at both the places.
*/
void merge()
{
	int i=0,j=0;
	
	while((i<sptr) && (j<dptr)) {
		
		if(smatched[i]==dmatched[j])
		{
			printf("%d\n",smatched[i]);
			i++;
			j++;
		}
		else if(smatched[i] < dmatched[j])
			i++;
		else if(smatched[i] > dmatched[j])
			j++;

	}	

}

/*
	Accepts path to an IP bitmap, port bitmap, IP to search, port to search and performs
	Search operation.
*/
void search_comp_bitmap(char *ipfilename, char *portfilename, u_int8_t IP[], u_int16_t portno, int no_octets, int sord)
{
	int i,j,k,ipfile,portfile,flag;
	u_int32_t pStartLoc[65536] = {0};						//Structure to store offsets of 65k bit vectors of port bitmap
	u_int32_t iStartLoc[4][256] = {0};					//Structure to store offsets of 256x4 bit vectors of IP bitmap
	u_int32_t iselected[4][NO_FLOWS/BYTES_IN_WORD] = {0};	//Structure to hold selected bit vectors to be ANDed (from IP bitmap)
	u_int32_t pselected[NO_FLOWS/BYTES_IN_WORD] ={0};	//Structure to hold selected bit vector to be ANDed (from port bitmap)
	u_int32_t curIPWord[4]={0},curPortWord=0,result;	//pointers to the currently considered words in IP bit vector and port bit vector
	
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
	
	///printf("Header bytes from IP file : %d\n",(int)read(ipfile,iStartLoc,sizeof(iStartLoc)));//Read offset values of IP bitmap
	read(ipfile,iStartLoc,sizeof(iStartLoc));	
	///printf("Header bytes from port file : %d\n",(int)read(portfile,pStartLoc,sizeof(pStartLoc)));//Read offset values of port bitmap
	read(portfile,pStartLoc,sizeof(pStartLoc));

	for(i=0; i<no_octets; i++)		//Read the selected IP bit vectors into iselected
	{
		lseek(ipfile,sizeof(iStartLoc)+iStartLoc[i][IP[i]],SEEK_SET);
		///printf("\nFor octet %d read %d bytes",i,(int)read(ipfile,iselected[i],(iStartLoc[i][IP[i]+1] - iStartLoc[i][IP[i]])));
		read(ipfile,iselected[i],(iStartLoc[i][IP[i]+1] - iStartLoc[i][IP[i]]));
	}
	
	if(portno != 0)				//Read the selected port bit vector into pselected, if any
	{
		lseek(portfile,sizeof(pStartLoc)+pStartLoc[portno],SEEK_SET);
		///printf("\nFor port %" PRIu16 " read %d bytes",portno,(int)read(portfile,pselected,(pStartLoc[portno+1] - pStartLoc[portno])));
		read(portfile,pselected,(pStartLoc[portno+1] - pStartLoc[portno]));
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
						if(sord==0)
						{
							smatched[sptr] = j*(BITS_IN_WORD-1) + (BITS_IN_WORD-1-k);
							///printf("\nMatching flow no. %d found!",smatched[sptr]);
							sptr++;
						}
						else if(sord==1)
						{
							dmatched[dptr] = j*(BITS_IN_WORD-1) + (BITS_IN_WORD-1-k);
							///printf("\nMatching flow no. %d found!",dmatched[dptr]);
							dptr++;
						}
 
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
	u_int8_t IPs[4] = {0};
	u_int8_t IPd[4] = {0};
	u_int16_t portnos;
	u_int16_t portnod;
	int no_octetss=0,no_octetsd=0,i;
	char basepath[20],ispath[50],pspath[50],idpath[50],pdpath[50];
	
	if(argc != 12)	//Program name + 4 Octets + Port number + 4 Octets + Port number + Slot path
	{
		printf("\nIncorrect no. of arguments supplied. %d",argc);
		return 0;
	}
	
	for(i=0; i<4; i++)			//Parse the IP address
	{
		if(strcmp(argv[i+1],"-1") != 0)
		{
			IPs[i] = (u_int8_t)atoi(argv[i+1]);
			no_octetss++;
		}
		if(strcmp(argv[i+6],"-1") != 0)
		{
			IPd[i] = (u_int8_t)atoi(argv[i+6]);
			no_octetsd++;
		}
	}
	
	portnos = (u_int16_t)atoi(argv[5]);	//Parse the port number
	portnod = (u_int16_t)atoi(argv[10]);

	strcpy(basepath,argv[11]);
		
	///printf("\nInput given : %" PRIu8 " %" PRIu8 " %" PRIu8 " %" PRIu8 " : %" PRIu16 " in %s\n",IPs[0],IPs[1],IPs[2],IPs[3],portnos,basepath);	
	///printf("\nInput given : %" PRIu8 " %" PRIu8 " %" PRIu8 " %" PRIu8 " : %" PRIu16 " in %s\n",IPd[0],IPd[1],IPd[2],IPd[3],portnod,basepath);

	sprintf(ispath,"%sIP_src-comp.bitmap",basepath);
	sprintf(pspath,"%sport_src-comp.bitmap",basepath);
	sprintf(idpath,"%sIP_dest-comp.bitmap",basepath);
	sprintf(pdpath,"%sport_dest-comp.bitmap",basepath);
	
	///printf("\n\nSearch in compressed bitmap : \n");
	///printf("%s\n%s\n%s\n%s\n",ispath,pspath,idpath,pdpath);
	search_comp_bitmap(ispath,pspath,IPs,portnos,no_octetss,0);
	search_comp_bitmap(idpath,pdpath,IPd,portnod,no_octetsd,1);
	merge();
	
	return 0;
}
