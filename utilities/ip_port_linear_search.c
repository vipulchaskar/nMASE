/**********************************************************
to search in packet.capture file linearly

TO compile :: gcc ip_port.c -o i.out

suppose the compiled file is i.out

then 
./i.out <options> <related feild>

where options are :
SI = source IP address
DI = destination IP address
SP = source PORT
DP = destination PORT

eg

./i.out SI 192.168.10.20 DP 2000
./i.out DI 192.186.29.34 SI 192.100.20.40 SP 100
******************************************************/
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
	u_int16_t length;
	u_int8_t dir; //dir = 0 s->d else d->s
	u_int32_t next_offset;
}packet_record;

char filename[] = "packetcap.capture";			// global file name 

int match_ip(char *ip,int ip1,int ip2,int ip3,int ip4)
{
char temp[4];
	int i,j;
	if(ip1==-2)
		return 1;
	i=j=0;
	if(ip1!=-1){
	while(ip[i]!='.')
		temp[j++]=ip[i++];
	temp[j]='\0';
	if(ip1!=atoi(temp))
		return 0;
	}
	i++;j=0;
	if(ip2!=-1){
	while(ip[i]!='.')
		temp[j++]=ip[i++];
	temp[j]='\0';
	if(ip2!=atoi(temp))
		return 0;
	}
	i++;j=0;
	if(ip3!=-1){
	while(ip[i]!='.')
		temp[j++]=ip[i++];
	temp[j]='\0';
	if(ip3!=atoi(temp))
		return 0;
	}
	i++;j=0;
	if(ip4!=-1){
	while(ip[i]!='\0')
		temp[j++]=ip[i++];
	temp[j]='\0';
	if(ip4!=atoi(temp))
		return 0;
	}
	return 1;
}

int match_port(int real_port,int wanted_port)
{
	if(wanted_port == -2 || wanted_port == -1)
		return 1;
	if(wanted_port != real_port)
		return 0;
}

void search_for(int sport,int ips1,int ips2,int ips3,int ips4,int dport,int ipd1,int ipd2,int ipd3,int ipd4)
{
	FILE *fp;
	char *pchar;
	u_int32_t addition,offset;
	struct ip *iphdr;
	struct icmphdr *icmphdr;
	struct udphdr *udphdr;
	struct tcphdr *tcphdr;
	struct ether_header *ehdr;
	u_int32_t count=0;
	pchar = (char *)malloc(sizeof(char) * 5000);
	packet_record *pr=(packet_record *)malloc(sizeof(packet_record));
	if((fp=fopen(filename,"rb"))==NULL)
	{
		printf("\nError opening file for writing.");
		exit(1);
	}
	pchar = (char *)malloc(sizeof(char ) * 3000);
	
	while(fread(pr,sizeof(packet_record),1,fp) > 0)
	{
		addition = pr->length;
	   	fread(pchar,addition,1,fp);
		ehdr = (struct ehter_header *)pchar;
	   	pchar += ETHERNET_HDR_LEN;
		iphdr = (struct ip *)pchar;
	   	pchar +=4*iphdr->ip_hl;
			printf("\n yo yo %"PRId32,count);
		switch(iphdr->ip_p){
		case IPPROTO_TCP:
			
			tcphdr = (struct tcphdr*)pchar;
			pchar += 4*tcphdr->doff;
		if(match_ip(inet_ntoa(iphdr->ip_src),ips1,ips2,ips3,ips4) &&			match_ip(inet_ntoa(iphdr->ip_dst),ipd1,ipd2,ipd3,ipd4) && match_port(ntohs(tcphdr->source),sport) && match_port(ntohs(tcphdr->dest),dport))
	
//			printf("\nIPSRC %d:%s ",ntohs(tcphdr->source),inet_ntoa(iphdr->ip_src));
//			printf(" IPDST %d:%s ",ntohs(tcphdr->dest),inet_ntoa(iphdr->ip_dst));
			break;
		case IPPROTO_UDP:
//			printf("\n\t-----------UDP---------------");
			udphdr = (struct udphdr*)pchar;			
			if(match_ip(inet_ntoa(iphdr->ip_src),ips1,ips2,ips3,ips4) &&			match_ip(inet_ntoa(iphdr->ip_dst),ipd1,ipd2,ipd3,ipd4) && match_port(ntohs(udphdr->source),sport) && match_port(ntohs(udphdr->dest),dport))
			
//			printf("\nIPSRC %d:%s ",(udphdr->uh_sport),inet_ntoa(iphdr->ip_src));
//			printf(" IPDST %d:%s ",(udphdr->uh_dport),inet_ntoa(iphdr->ip_dst));
			break;
		}
		count = count + sizeof(packet_record) + addition;
		if(pr->ID % 100 == 0)
			getchar();
	}
	printf("hello");
	fclose(fp);
	

}

void break_ip(char ip[],int *ip1, int *ip2,int *ip3,int *ip4 )
{
	char temp[4];
	int i,j;
	i=j=0;
	while(ip[i]!='.')
		temp[j++]=ip[i++];
	temp[j]='\0';
	if(ip[i-1]!='*')
		*ip1=atoi(temp);
	else
		*ip1=-1;
	i++;j=0;
	while(ip[i]!='.')
		temp[j++]=ip[i++];
	temp[j]='\0';
	if(ip[i-1]!='*')
		*ip2=atoi(temp);
	else
		*ip2=-1;
	i++;j=0;
	while(ip[i]!='.')
		temp[j++]=ip[i++];
	temp[j]='\0';
	if(ip[i-1]!='*')
		*ip3=atoi(temp);
	else
		*ip3=-1;
	i++;j=0;
	while(ip[i]!='\0')
		temp[j++]=ip[i++];
	temp[j]='\0';
	if(ip[i-1]!='*')
		*ip4=atoi(temp);
	else
		*ip4=-1;
}


int main(int argc ,char *argv[])
{
	int i,j;
	int ips1,ips2,ips3,ips4,ipd1,ipd2,ipd3,ipd4,sport,dport;
	i=1;
	ips1=ips2=ips3=ips4=ipd1=ipd2=ipd3=ipd4=sport=dport=-2;
	while(i<argc){
		printf("\n");
		if(strcmp(argv[i],"SI")==0){
			i++;
			break_ip(argv[i],&ips1,&ips2,&ips3,&ips4);
			printf(" source %d.%d.%d.%d",ips1,ips2,ips3,ips4);
		}
		else if(strcmp(argv[i],"DI")==0){
			i++;
			break_ip(argv[i],&ipd1,&ipd2,&ipd3,&ipd4);
			printf(" dest %d.%d.%d.%d",ipd1,ipd2,ipd3,ipd4);
		}
		else if(strcmp(argv[i],"SP")==0){
			i++;
			sport=atoi(argv[i]);
			printf(" sport : %d",sport);
		}
		else if(strcmp(argv[i],"DP")==0){
			i++;
			dport=atoi(argv[i]);
			printf(" dpost : %d",dport);
		}
		i++;
	}
	search_for(sport,ips1,ips2,ips3,ips4,dport,ipd1,ipd2,ipd3,ipd4);
	return 0;
}
