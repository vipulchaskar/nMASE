
#include <pcap.h>
#include <pfring.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/ether.h>
#include <fcntl.h>
#include <inttypes.h>

#define ETHERNET_HDR_LEN 14

typedef struct packet_record {
	u_int32_t timestamp;
	u_int32_t ID;
	u_int32_t next_offset;
	u_int16_t length;
}packet_record;

char filename[] = "packetcap.capture";			// global file name (combination of prefix + number)
pfring *handle;									// pfring Session handle
int fp;
u_int32_t ID = 1;
u_int32_t currByte = 0;

void sigproc(int sig) {
	printf("pfring closed.");
	close(fp);
 	exit(0);
}


int main(int argc, char *argv[])
{
	int offset,addition;
	packet_record *pr;
	signal(SIGINT,sigproc);

	if((fp=open(filename,O_RDONLY))==-1)
	{
		printf("\nError opening file for writing.");
		exit(1);
	}
	
	while((offset=read(fp,pr,sizeof(packet_record))) > 0)
	{
		printf("\n ID is %" PRId32,pr->ID);
		addition = pr->length;
		lseek(fp,addition,SEEK_CUR);
	}

	close(fp);
	
	return 0;
}
