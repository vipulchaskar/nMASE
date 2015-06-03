//Reads and extracts the packets from "import.pcap" file present in the same directory. Passes the input of
//these packets to first module, similar to packetlogger.
//The generated files are stored in 0/0/ directory.

#include "include/custom_header.h"
#include <ctype.h>
#include <dirent.h> 
#include <errno.h>
#include <sys/stat.h>
#include <semaphore.h>

#define ETHERNET_HDR_LEN 14
#define SECONDS 60*60
#define BITMAP_THRESHOLD_LIMIT 1000

//Call back function for changing folder
typedef void (*sighandler_t)(int);

//This structure is used for prefixing complete packet
//before storing the packet in packet_cpature file
typedef struct packet_record {
	u_int32_t timestamp;
	u_int32_t ID;
	u_int16_t length;
	u_int8_t dir; //dir = 0 s->d else d->s
	u_int32_t next_offset;
}packet_record;

//The following record get stored in flow_rec file
//when we observe 1st packet of new flow
typedef struct flow_record
{
	char ip_src[16],ip_dst[16];
	u_int16_t sport,dport;
	u_int32_t offset;
}flow_record;


pfring *handle;				// pfring Session handle
tree *roott,*rootu;         // These are roots of TCP and UDP flows seperately
char filename[] = "packetcap.capture";			// global file name (combination of prefix + number)
char filename1[]= "flow_rec";
u_int32_t ID = 1;          // ID for packets 
u_int32_t currByte = 0;    
FILE *fp;                  //File descriptor for packet_capture
FILE *fp1;                 //File descriptor for flow_rec

int day,slot;              //Variables storing Current day and corresponding Hour in it
char buffer[32];           
char *my_cwd;              //Stores current working directory
int day_interval,slot_interval;
u_int32_t struct_off=0,packet_off=0; 
int flowcount=1;				//Used to keep track of number of flows encountered till now. Reset to 1 after
						//each slot change.

IP_bitmap *sipbm;				//Pointers to bitmap indexes
port_bitmap *sprbm;				
tproto_bitmap *tpbm;			
IP_bitmap *dipbm;				
port_bitmap *dprbm;				

pthread_t thread1,thread2;

sem_t sem,sem2;

int wait_handle = 0,wait_parse = 0;


void sigproc(int sig) {
	fclose(fp);
	fclose(fp1);
	printf("im last id %"PRId32,ID);
	pfring_close(handle);

	save_IP_bitmap(sipbm,"IP_src.bitmap");			//Save uncompressed bitmaps
	save_port_bitmap(sprbm,"port_src.bitmap");		
	save_tproto_bitmap(tpbm,"tproto.bitmap");		
	save_IP_bitmap(dipbm,"IP_dest.bitmap");			
	save_port_bitmap(dprbm,"port_dest.bitmap");		
	
	compress_IP_bitmap(sipbm,"IP_src-comp.bitmap");		//Compress bitmaps and save
	compress_port_bitmap(sprbm,"port_src-comp.bitmap");	
	compress_tproto_bitmap(tpbm,"tproto-comp.bitmap");	
	compress_IP_bitmap(dipbm,"IP_dest-comp.bitmap");	
	compress_port_bitmap(dprbm,"port_dest-comp.bitmap");	
	
	
	exit(0);
}

/*
 * A faster replacement for inet_ntoa().
 */
char* _intoa(unsigned int addr, char* buf, u_short bufLen) {
	char *cp, *retStr;
	u_int byte;
	int n;
	
	cp = &buf[bufLen];
	*--cp = '\0';
	
	n = 4;
	do {
		byte = addr & 0xff;
		*--cp = byte % 10 + '0';
		byte /= 10;
		if (byte > 0) {
			*--cp = byte % 10 + '0';
			byte /= 10;
			if (byte > 0)
				*--cp = byte + '0';
		}
		*--cp = '.';
		addr >>= 8;
	} while (--n > 0);
	
	/* Convert the string to lowercase */
	retStr = (char*)(cp+1);
	
	return(retStr);
}

/* ************************************ */

char* intoa(unsigned int addr) {
	static char buf[sizeof "ff:ff:ff:ff:ff:ff:255.255.255.255"];
	
	return(_intoa(addr, buf, sizeof(buf)));
}

//Accept IP address as a string and store it into four octets
void break_IP(char ip[],int *ip1, int *ip2,int *ip3,int *ip4 )
{
	char temp[4];
	int i,j;
	i=j=0;
	while(ip[i]!='.')
		temp[j++]=ip[i++];
	temp[j]='\0';
	*ip1=atoi(temp);
	i++;j=0;
	while(ip[i]!='.')
		temp[j++]=ip[i++];
	temp[j]='\0';
	*ip2=atoi(temp);
	i++;j=0;
	while(ip[i]!='.')
		temp[j++]=ip[i++];
	temp[j]='\0';
	*ip3=atoi(temp);
	i++;j=0;
	while(ip[i]!='\0')
		temp[j++]=ip[i++];
	temp[j]='\0';
	*ip4=atoi(temp);
}

//Call back function for processing each packet
void parse_packet(struct pcap_pkthdr *h, const u_char *packetptr)
{
	struct ip *iphdr;
	struct icmphdr *icmphdr;
	struct tcphdr *tcphdr;
	struct udphdr *udphdr;
	struct ether_header *ehdr;
	u_char *temp;

	packet_record newPacket;
	flow_record flow_rec;
	
	const u_char *pchar = packetptr;
	int p_type = -1;
	char ip_src[16],ip_dst[16];
	int port_src,port_dst,ips1,ips2,ips3,ips4;
	int ipd1,ipd2,ipd3,ipd4;
	int len=0;	
	
	u_int8_t dir;
	u_int32_t to_jump;
	tree *roots,*rootd;
	node *packet_node;
	//number of packets written;
	static int count;	

  	wait_handle = 1;
	ehdr = (struct ether_header *) packetptr;
	if (ntohs (ehdr->ether_type) != ETHERTYPE_IP) {
		printf("\nim returning");
		return;
	}
	else if(h->caplen >= 1500)
		return;
	
	packetptr +=ETHERNET_HDR_LEN;
	len = ETHERNET_HDR_LEN;
	temp = packetptr;

	if(ntohs(ehdr->ether_type)==ETHERTYPE_IP){
		iphdr=(struct ip*)packetptr;
		packetptr += 4*iphdr->ip_hl;
		len += 4*iphdr->ip_hl;
		
		switch(iphdr->ip_p){
			case IPPROTO_TCP:{
				p_type = 1;
				tcphdr = (struct tcphdr *)packetptr;
				break;
			}
			case IPPROTO_UDP:{
				p_type = 2;
				udphdr = (struct udphdr *)packetptr;
				break;
			}
		}
	}

	packetptr -= len ;

	newPacket.timestamp = (u_int32_t)h->ts.tv_sec;
	newPacket.ID = (u_int32_t)ID;
	newPacket.length = (u_int16_t)h->caplen;
	newPacket.dir = -1;
	struct_off = packet_off;
	newPacket.next_offset = struct_off;
	packet_off = packet_off + sizeof(packet_record) + newPacket.length;
//	fwrite(&newPacket,sizeof(packet_record),1,fp);fwrite(packetptr,newPacket.length,1,fp);
	printf("\n\t packet offset is %d %"PRIu32" %" PRIu32 , sizeof(packet_record),newPacket.length,packet_off);
	
	ID++;
	//memset((void *)&h->extended_hdr.parsed_pkt,0,sizeof(struct pkt_parsing_info));
	//pfring_parse_pkt((u_char *)packetptr,(struct pfring_pkthdr *)h,4,1,1);
	//strcpy(ip_src, intoa(h->extended_hdr.parsed_pkt.ipv4_src));
	strcpy(ip_src,inet_ntoa(iphdr->ip_src));
	//port_src = h->extended_hdr.parsed_pkt.l4_src_port;
	if (p_type==1)
		port_src=ntohs(tcphdr->source);
	else if(p_type ==2)
		port_src = ntohs(udphdr->source);	
	//strcpy(ip_dst,intoa(h->extended_hdr.parsed_pkt.ipv4_dst));
	strcpy(ip_dst,inet_ntoa(iphdr->ip_dst));	
	//port_dst=h->extended_hdr.parsed_pkt.l4_dst_port;
	if (p_type == 1)	
		port_dst=ntohs(tcphdr->dest);
	else if(p_type==2)
		port_dst = ntohs(udphdr->dest);	
	strcpy(flow_rec.ip_src,ip_src);
	strcpy(flow_rec.ip_dst,ip_dst);
	flow_rec.sport = port_src;
	flow_rec.dport = port_dst;
	//flow_rec.offset = newPacket.next_offset;
	flow_rec.offset = struct_off ;	
	//preparation for insertion in tree
	break_IP(ip_src,&ips1,&ips2,&ips3,&ips4);
	break_IP(ip_dst,&ipd1,&ipd2,&ipd3,&ipd4);	    				   
	
	packetptr +=ETHERNET_HDR_LEN;
	if(ntohs(ehdr->ether_type)==ETHERTYPE_IP){
		iphdr=(struct ip*)packetptr;
		packetptr += 4*iphdr->ip_hl;
		switch(iphdr->ip_p){
		
		case IPPROTO_TCP:{
			tcphdr = (struct tcphdr *)packetptr;
			roots=insert_tree(roott,port_src,ips1,ips2,ips3,ips4);
			rootd=insert_tree(roott,port_dst,ipd1,ipd2,ipd3,ipd4);
			to_jump=check_make_node(struct_off,&dir,roots,port_src,ips1,ips2,ips3,ips4,rootd,port_dst,ipd1,ipd2,ipd3,ipd4);
			newPacket.dir = dir;
			fwrite(&newPacket,sizeof(packet_record),1,fp);fwrite(pchar,newPacket.length,1,fp);
			//if(tcphdr->fin || tcphdr->rst){		
			//printf("\n\t i need to delte");
			//check_delete_node(roots,port_src,ips1,ips2,ips3,ips4,rootd,port_dst,ipd1,ipd2,ipd3,ipd4);
			//}
			
			if(to_jump == 0){
				printf("\nyes im new node");
				u_int8_t sIP[4],dIP[4];				//Structures to pass to the add_bitmap function calls
				u_int16_t sportno,dportno;				
				u_int8_t tproto = TPROTO_TCP;		
				
				sIP[0] = (u_int8_t)ips1;			
				sIP[1] = (u_int8_t)ips2;
				sIP[2] = (u_int8_t)ips3;
				sIP[3] = (u_int8_t)ips4;
				sportno = (u_int16_t)port_src;
				dIP[0] = (u_int8_t)ipd1;
				dIP[1] = (u_int8_t)ipd2;
				dIP[2] = (u_int8_t)ipd3;
				dIP[3] = (u_int8_t)ipd4;
				dportno = (u_int16_t)port_dst;
				
				if(flowcount <= BITMAP_THRESHOLD_LIMIT)        //Current threshold limit for number of flows which bitmap can index
				{				
					add_IP_bitmap(sipbm,sIP,flowcount);
					add_port_bitmap(sprbm,sportno,flowcount);
					add_IP_bitmap(dipbm,dIP,flowcount);
					add_port_bitmap(dprbm,dportno,flowcount);
					add_tproto_bitmap(tpbm,tproto,flowcount);
					
					flowcount++;
				}
				
				fwrite(&flow_rec,sizeof(flow_record),1,fp1);
			}
			else {
				printf("\nsame old same old %" PRIu32 , to_jump);
				fflush(fp);
				fseek(fp,to_jump,SEEK_SET);
				fread(&newPacket,sizeof(packet_record),1,fp);
				fseek(fp,-sizeof(packet_record),SEEK_CUR);
				newPacket.next_offset=struct_off;
				newPacket.dir=dir;
				fwrite(&newPacket,sizeof(packet_record),1,fp);
				fseek(fp,0,SEEK_END);	
			}
			
			
			break;
		}
		case IPPROTO_UDP:{
			udphdr = (struct udphdr *)packetptr;
			printf("\n\t*********i got udp");
			printf("\n\t %d %d || %d %d",ntohs(udphdr->source),port_src,ntohs(udphdr->dest),port_dst);
			roots=insert_tree(rootu,port_src,ips1,ips2,ips3,ips4);
			rootd=insert_tree(rootu,port_dst,ipd1,ipd2,ipd3,ipd4);
			to_jump=check_make_node(struct_off,&dir,roots,port_src,ips1,ips2,ips3,ips4,rootd,port_dst,ipd1,ipd2,ipd3,ipd4);
			flow_rec.sport = port_src;
			flow_rec.dport = port_dst;
			flow_rec.offset = newPacket.next_offset;	
			newPacket.dir=dir;
			fwrite(&newPacket,sizeof(packet_record),1,fp);fwrite(pchar,newPacket.length,1,fp);
			if(to_jump == 0){
				u_int8_t sIP[4],dIP[4];				//Structures to pass to the add_bitmap function calls
				u_int16_t sportno,dportno;					
				u_int8_t tproto = TPROTO_UDP;		
				
		  		printf("\nyes im new node");
				
				sIP[0] = (u_int8_t)ips1;			
				sIP[1] = (u_int8_t)ips2;
				sIP[2] = (u_int8_t)ips3;
				sIP[3] = (u_int8_t)ips4;
				sportno = (u_int16_t)port_src;
				dIP[0] = (u_int8_t)ipd1;
				dIP[1] = (u_int8_t)ipd2;
				dIP[2] = (u_int8_t)ipd3;
				dIP[3] = (u_int8_t)ipd4;
				dportno = (u_int16_t)port_dst;
				
				if(flowcount <= BITMAP_THRESHOLD_LIMIT)        //Current threshold limit for number of flows which bitmap can index
				{				
					add_IP_bitmap(sipbm,sIP,flowcount);
					add_port_bitmap(sprbm,sportno,flowcount);
					add_IP_bitmap(dipbm,dIP,flowcount);
					add_port_bitmap(dprbm,dportno,flowcount);
					add_tproto_bitmap(tpbm,tproto,flowcount);
					
					flowcount++;
				}
				
	  			fwrite(&flow_rec,sizeof(flow_record),1,fp1);
				
			}
			else {
				printf("\nsame old same old %" PRIu32 , to_jump);
				fflush(fp);
				fseek(fp,to_jump,SEEK_SET);
				fread(&newPacket,sizeof(packet_record),1,fp);
				fseek(fp,-sizeof(packet_record),SEEK_CUR);
				newPacket.next_offset=struct_off;
				fwrite(&newPacket,sizeof(packet_record),1,fp);
				fseek(fp,0,SEEK_END);	
			}
			
			break;
		}
	
		}
	}
	if(iphdr->ip_p != IPPROTO_TCP && iphdr->ip_p!=IPPROTO_UDP)
		packet_off = struct_off;

	//increment packet count;
	count++;
	fflush(fp);
	fflush(fp1);
	fflush(stdout);
  	wait_handle = 0;
}

void *do_substract_one(void *data)
{
	int interval = *(int *)data;
	for (;;) {
		substract_one(roott);
		substract_one(rootu);
		usleep(interval);
	}
}

//To save current bitmaps and create space for new ones.
void save_reset_bitmaps()
{
	sem_wait(&sem);
	save_IP_bitmap(sipbm,"IP_src.bitmap");
	save_port_bitmap(sprbm,"port_src.bitmap");
	save_tproto_bitmap(tpbm,"tproto.bitmap");
	save_IP_bitmap(dipbm,"IP_dest.bitmap");	
	save_port_bitmap(dprbm,"port_dest.bitmap");	
	
	compress_IP_bitmap(sipbm,"IP_src-comp.bitmap");	
	compress_port_bitmap(sprbm,"port_src-comp.bitmap");
	compress_tproto_bitmap(tpbm,"tproto-comp.bitmap");
	compress_IP_bitmap(dipbm,"IP_dest-comp.bitmap");
	compress_port_bitmap(dprbm,"port_dest-comp.bitmap");
	
	memset(sipbm,0,sizeof(IP_bitmap));
	memset(sprbm,0,sizeof(port_bitmap));	
	memset(tpbm,0,sizeof(tproto_bitmap));
	memset(dipbm,0,sizeof(IP_bitmap));
	memset(dprbm,0,sizeof(port_bitmap));
	flowcount=1;
	sem_post(&sem);
	
}

void handle_now()
{
/*
  wait_parse = 0;
  while(wait_handle)
  printf("1");
*/
	printf("\n*       GOING IN    ");
	wait_parse = 0;
	fclose(fp);
	fclose(fp1);
	fflush(stdout);
	if((fp=fopen(filename,"wb+"))==NULL)
	{
		printf("\nError opening file for writing.");
		exit(1);
	}
	if((fp1=fopen(filename1,"wb+"))==NULL)
	{
		printf("\nError opening file for writing.");
		exit(1);
	}
//	make_all_offset_zero(roott);
//	make_all_offset_zero(rootu);
	if(roott!=NULL){
		roott=delete_whole_tree(roott);
		//	roott=allo_tree();
	}
	if(rootu!=NULL){
		rootu=delete_whole_tree(rootu);
		//rootu=allo_tree();
	}
	roott = allo_tree();
	rootu = allo_tree();
	ID = 0;
	struct_off = packet_off = 0;
	printf("going out");
	wait_parse = 1;
}

void do_smth()
{
	char temp[1000];
	DIR* dir;
	int res1,res2;
	snprintf(buffer,32,"%d",day);
	strcpy(temp,my_cwd);
	res1=chdir(temp);
	printf("\n*\n*\n*");
	printf("\n******i changed to root :: %s ********",temp);
	strcat(temp,"/");
	strcat(temp,buffer);
	dir = opendir(buffer);
	//if directory is present
	if (dir)
	{
		chdir(temp); 
		snprintf(buffer,32,"%d",slot);
		strcat(temp,"/");
		strcat(temp,buffer);
		res1=mkdir(buffer,0777);
		
		printf("\n\t res1 :: %d %s %s",res1,buffer,temp);
		chdir(temp);
		handle_now();
	}
	//if directory is not present
	else if (ENOENT == errno)
	{
		res1=mkdir(buffer,0777);
		res2=chdir(temp);
		printf("\n**i changed to %s",temp);
		snprintf(buffer,32,"%d",slot);
		strcat(temp,"/");
		strcat(temp,buffer);
		res2=mkdir(buffer,0777);
		
		printf("\n\t res1 :: %d res2 :: %d",res1,res2);
		chdir(temp);
		handle_now();
	}
	//opendir failed
	else
	{
		printf("\ni failed to do open dir");
	}	
	closedir(dir);			
	printf("\n*\n*\n*");
	fflush(stdout);
}

do_smth_periodically()
{
	static int i=0;
	if(i)			
		save_reset_bitmaps();
	else
		i++;
	do_smth();
	slot++;
	if(slot == slot_interval){
		day++;
		slot = 0;
	}
	if(i!=1)
	        alarm(SECONDS);
}


int main(int argc, char *argv[])
{
	char *dev,ebf[256];			// The device to sniff on
	int flags;					// Flags to pass for opening pfring instance
	int interval = 5000000;
	struct pcap_pkthdr *hdr;
	const u_char *packet;
	time_t t = time(NULL);
	struct tm tm = *localtime(&t);
	pcap_t *pt=NULL;

	sipbm = (IP_bitmap *)calloc(1,sizeof(IP_bitmap));			//Initialize bitmaps
	sprbm = (port_bitmap *)calloc(1,sizeof(port_bitmap));			
	tpbm = (tproto_bitmap *)calloc(1,sizeof(tproto_bitmap));		
	dipbm = (IP_bitmap *)calloc(1,sizeof(IP_bitmap));			
	dprbm = (port_bitmap *)calloc(1,sizeof(port_bitmap));			
	interval = tm.tm_min * 60 + tm.tm_sec; 

/*	struct timeval my_value={SECONDS,0};
	struct timeval my_interval={interval,0};
	struct itimerval my_timer={my_interval,my_value};
	setitimer(ITIMER_REAL, &my_timer, 0);
	printf("\n---------the time is %d",interval);
*/	
	slot = 0;
	day = 0;
	//alarm(SECONDS - interval);
	//printf("here is the difference %d",SECONDS - interval);
	//signal(SIGALRM, (sighandler_t) do_smth_periodically);
/*
  initialize the root of tree
*/
	//roott=allo_tree();
	//rootu=allo_tree();
	signal(SIGINT,sigproc);
	
	dev = argv[1];			// Set the device manually to arg[1]
	printf("\nCapture device: %s\n", dev);
	if((fp=fopen(filename,"wb+"))==NULL)
	{
		printf("\nError opening file for writing.");
		exit(1);
	}
	if((fp1=fopen(filename1,"wb+"))==NULL)
	{
		printf("\nError opening file for writing.");
		exit(1);
	}
	
	/*
	flags = PF_RING_PROMISC;
	if((handle = pfring_open(dev, 1500, flags)) == NULL) {
   		printf("pfring_open error");
    		return(-1);
  	} else {
		pfring_set_application_name(handle, "packetcapture");
	}
	*/
	pt = pcap_open_offline("import.pcap",ebf);

    day_interval = 3;
	slot_interval = 4;
	my_cwd = (char *)malloc(sizeof(char) * 1000);
	getcwd(my_cwd,1000);
	
	printf("alo");	
	fflush(stdout);
	
	do_smth_periodically();
	
	do{
		if(pcap_next_ex(pt,&hdr,&packet) > 0){
				
				parse_packet(hdr,packet);	
		}
		else
			break;
	}while(1);
	sigproc(1);

  	free(my_cwd);

	fclose(fp);	
	return 0;
}
