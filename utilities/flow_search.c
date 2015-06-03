#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#include "include/bitmaps.h"
#include "include/bitmaps.c"

typedef struct flow_record
{
	char ip_src[16],ip_dst[16];
	u_int16_t sport,dport;
	u_int32_t offset;
}flow_record;

char flowrecfilename[] = "flow_rec";

void search_comp_bitmap(char *ipfilename, char *portfilename, u_int8_t IP[], u_int16_t portno, int no_octets)
{
	int i,j,k,ipfile,portfile,flowrecfile,flag,flowno;
	u_int32_t pStartLoc[65536];
	u_int32_t iStartLoc[4][256];
	u_int32_t iselected[4][NO_FLOWS/BYTES_IN_WORD];
	u_int32_t pselected[NO_FLOWS/BYTES_IN_WORD];
	u_int32_t curIPWord[4],curPortWord=0,result;
	flow_record record;
	
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
	
	if((flowrecfile = open(flowrecfilename,O_RDONLY)) == -1)
	{
		printf("\nError opening flow record file %s",flowrecfilename);
		return;
	}
	
	printf("Header bytes from IP file : %d\n",(int)read(ipfile,iStartLoc,sizeof(iStartLoc)));
	printf("Header bytes from port file : %d\n",(int)read(portfile,pStartLoc,sizeof(pStartLoc)));
	
	for(i=0; i<no_octets; i++)
	{
		lseek(ipfile,sizeof(iStartLoc)+iStartLoc[i][IP[i]],SEEK_SET);
		printf("\nFor octet %d read %d bytes",i,(int)read(ipfile,iselected[i],(iStartLoc[i][IP[i]+1] - iStartLoc[i][IP[i]])));
	}
	
	if(portno != 0)
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
	
	for(j=0; j<(NO_FLOWS/BYTES_IN_WORD); j++)
	{
		flag=0;
		//printf("\nIteration number : %d",j);
		
		for(i=0; i<no_octets; i++)
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
		
		if(flag==1)
		{
			for(i=0; i<no_octets; i++)
			{
				if(isFill(iselected[i][curIPWord[i]]))
				{
					//printf("\n%d is a fill word.",i);
					if((iselected[i][curIPWord[i]] & 0x7FFFFFFF) == 1)
					{
						//printf("\nIt was the only one. no merged.");
						curIPWord[i]++;
					}
					else
					{
						//printf("\nIt was merged. one removed.");
						iselected[i][curIPWord[i]]--;
					}
				}
				else
				{
					//printf("\n%d turned out to be a literal word.",i);
					curIPWord[i]++;
				}
			}
			
			if(portno != 0)
			{
				if(isFill(pselected[curPortWord]))
				{
					//printf("\nPort word %d is a fill word. Which is %" PRIu32,curPortWord,pselected[curPortWord]);
					
					//printf("\nThat expression is %u",(~(1<<(BYTES_IN_WORD-1)) ));
					if((pselected[curPortWord] & 0x7FFFFFFF ) == 1)
					{
						//printf("\nIt was the only one. no merged.");
						curPortWord++;
					}
					else
					{
						//printf("\nPort no. It was merged. one removed.");
						pselected[curPortWord]--;
					}
				}
				else
				{
					//printf("\nTurned out to be literal word.. port");
					curPortWord++;
				}
			}
		}
		else
		{
			//printf("\nParty is on.");
			//printf("\nguests are : %" PRIu32 " %" PRIu32 " %" PRIu32 " %" PRIu32 " %" PRIu32,iselected[0][curIPWord[0]],iselected[1][curIPWord[1]],iselected[2][curIPWord[2]],iselected[3][curIPWord[3]],pselected[curPortWord]);
			result = 0xFFFFFFFF;
			
			for(i=0; i<no_octets; i++)
				result = result & iselected[i][curIPWord[i]];
				
			if(portno != 0)
				result = result & pselected[curPortWord];
			
			if(result != 0)
			{
				//printf("\nResult has some bits set.");
				for(k=(BITS_IN_WORD-2); k>=0; k--)
					if((result & 1<<k) != 0)
					{
						flowno = j*(BITS_IN_WORD-1) + (BITS_IN_WORD-1-k);
						lseek(flowrecfile,sizeof(flow_record)*(flowno-1),SEEK_SET);
						read(flowrecfile,&record,sizeof(flow_record));
						printf("\nMatching flow no. %d found!",flowno);
						printf(" %s:%" PRIu16 "<--> %s:%" PRIu16 " - %" PRIu32,record.ip_src,record.sport,record.ip_dst,record.dport,record.offset); 
					}
			}
			
			curIPWord[0]++;
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
	
	if(argc != 6)
	{
		printf("\nIncorrect no. of arguments supplied. %d",argc);
		return 0;
	}
	
	for(i=0; i<4; i++)
		if(strcmp(argv[i+1],"-1") != 0)
		{
			IP[i] = (u_int8_t)atoi(argv[i+1]);
			no_octets++;
		}
	
	portno = (u_int16_t)atoi(argv[5]);
		
	printf("\nInput given : %" PRIu8 " %" PRIu8 " %" PRIu8 " %" PRIu8 " : %" PRIu16 " \n",IP[0],IP[1],IP[2],IP[3],portno);
	
	printf("\n\nSearch in compressed bitmap : \n");
	search_comp_bitmap("IP_src-comp.bitmap","port_src-comp.bitmap",IP,portno,no_octets);
	
	return 0;
}
