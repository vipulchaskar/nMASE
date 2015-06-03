//Sample usage - $./bitmap_search_uncomp.o 192 168 -1 -1 80 <slot path>
//This is equivalent to searching for 192.168.*.*:80
//Port number 0 stands for 'any'
//e.g. $./bitmap_search_uncomp.o 192 168 1 100 0 2014/9/4/21/
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#include "include/bitmaps.h"
#include "include/bitmaps.c"

void search_uncompr_bitmap(char *ipfilename, char *portfilename, u_int8_t IP[], u_int16_t portno, int no_octets)
{
	int ipfile,portfile;
	IP_bitmap *ipbm = (IP_bitmap *)calloc(1,sizeof(IP_bitmap));
	port_bitmap *prbm = (port_bitmap *)calloc(1,sizeof(port_bitmap));
	int i,j;
	u_int8_t *selected[4],*pselected;
	u_int8_t result = 0;
		
	if((ipfile = open(ipfilename,O_RDONLY)) == -1)
	{
		printf("\nError opening file for loading. %s",ipfilename);
		return;
	}
	
	read(ipfile,ipbm,sizeof(IP_bitmap));	//Read the whole IP bitmap
	close(ipfile);
	
	if((portfile = open(portfilename,O_RDONLY)) == -1)
	{
		printf("\nError opening file for loading. %s",portfilename);
		return;
	}
	
	read(portfile,prbm,sizeof(port_bitmap));	//Read the whole port bitmap
	close(portfile);
		
	for(i=0; i<no_octets; i++)			//Select the required bit vectors from all 4 octets
	{
		switch(i)
		{
			case 0:
			selected[0] = ipbm->octet1[IP[0]];
			break;
			
			case 1:
			selected[1] = ipbm->octet2[IP[1]];
			break;
			
			case 2:
			selected[2] = ipbm->octet3[IP[2]];
			break;
			
			case 3:
			selected[3] = ipbm->octet4[IP[3]];
			break;
		}			
		
	}
	
	if(portno != 0)					//Select the required bit vector from port bitmap
	{
		pselected = prbm->port[portno];
	}
		
	for(i=0; i<NO_FLOWS; i++)			//Take one byte from selected bit vectors
	{
		result = 0xFF;
		for(j=0; j<no_octets; j++)		//AND them all
			result = result & *selected[j];
			
		if(portno != 0)
			result = result & *pselected;
			
		if(result != 0)				//If result has some bits set, display them
		{
			for(j=7; j>=0; j--)
				if((result & 1<<j) > 0)
					printf("\nMatching flow no %d found!",8*i + (8-j));
		}
		
		selected[0]++;				//Increment the pointers into bit vector
		selected[1]++;
		selected[2]++;
		selected[3]++;
		
		if(portno != 0)
			pselected++;
	}
	
	free(ipbm);
	free(prbm);
	
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

	sprintf(ipath,"%sIP_src.bitmap",basepath);
	sprintf(ppath,"%sport_src.bitmap",basepath);
	printf("\n\nSearch in compressed bitmap : \n");
	search_uncompr_bitmap(ipath,ppath,IP,portno,no_octets);
	
	return 0;
}
