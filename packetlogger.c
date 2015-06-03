//Usage : sudo ./packetlogger <interface_name> <day_interval> <slot_interval>

#include "include/custom_header.h"
#include <ctype.h>
#include <dirent.h> 
#include <errno.h>
#include <sys/stat.h>
#include <semaphore.h>

#define ETHERNET_HDR_LEN 14
#define SECONDS 60*60

//Call back function for changing folder
typedef void (*sighandler_t)(int);

/* Structure is prefixed with every packet to get timestamp ID length of packet.
Direction is used as flows are chained bi directionally and next_offset is pointing to next packet of same flow.
*/
typedef struct packet_record {
	u_int32_t timestamp;
	u_int32_t ID;
	u_int16_t length;
	u_int8_t dir; //dir = 0 s->d else d->s
	u_int32_t next_offset;
}packet_record;

/* Structure is used to create 5 tuple record which contains the offset to the 1st packet in the captured packet file. */
typedef struct flow_record
{
	char ip_src[16],ip_dst[16];
	u_int16_t sport,dport;
	u_int32_t offset;
}flow_record;


pfring *handle;									// pfring Session handle
tree *roott,*rootu;         					// Two trees for TCP and UDP flows
char filename[] = "packetcap.capture";			// File which stores packets
char filename1[]= "flow_rec";					// File which stores flow records
u_int32_t ID = 1;          						// Global packet counter    
FILE *fp;                  						// File descriptor for packet_capture
FILE *fp1;                 						// File descriptor for flow_rec

int day,slot;              		//Variables storing Current day and corresponding Hour in it
char buffer[32];           
char *my_cwd;              		//Stores current working directory
int day_interval,slot_interval;
u_int32_t struct_off=0,packet_off=0;
int flowcount=1;				// Used to keep track of number of flows encountered till now. Reset to 1 after
								//each slot change.

IP_bitmap *sipbm;				//Bitmap on source IP
port_bitmap *sprbm;				//Bitmap on source port
tproto_bitmap *tpbm;			//Bitmap on transport protocol
IP_bitmap *dipbm;				//Bitmap on destination IP
port_bitmap *dprbm;				//Bitmap on destination port

pthread_t thread1,thread2;

sem_t sem,sem2;

int wait_handle = 0,wait_parse = 0;


void sigproc(int sig) {
	//close file descriptors
	fclose(fp);
	fclose(fp1);
	printf("im last id %"PRId32,ID);
	pfring_close(handle);

	//Save all uncompressed bitmaps
	save_IP_bitmap(sipbm,"IP_src.bitmap");			
	save_port_bitmap(sprbm,"port_src.bitmap");		
	save_tproto_bitmap(tpbm,"tproto.bitmap");		
	save_IP_bitmap(dipbm,"IP_dest.bitmap");			
	save_port_bitmap(dprbm,"port_dest.bitmap");		
	
	//Compress and save bitmaps
	compress_IP_bitmap(sipbm,"IP_src-comp.bitmap");		
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

//Splits string IP address into four integers
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

//Main callback function (called after receiving each packet)
void parse_packet(struct pfring_pkthdr *h, const u_char *packetptr)
{
	struct ip *iphdr;				//Headers required to parse packet upto transport layer
	struct icmphdr *icmphdr;
	struct tcphdr *tcphdr;
	struct udphdr *udphdr;
	struct ether_header *ehdr;
	
	packet_record newPacket;		//Packet_record will hold the packet prefix structure
	flow_record flow_rec;			//used for creating 5 tuple flow records
	const u_char *pchar = packetptr;//Storing the starting address of current packet
	
	char ip_src[16],ip_dst[16];		//Structures to hold parts of IP address and port numbers
	int port_src,port_dst,ips1,ips2,ips3,ips4;
	int ipd1,ipd2,ipd3,ipd4;
	
	u_int8_t dir;					//Direction bit
	u_int32_t to_jump;
	tree *roots,*rootd;				//Different pointers for source and destination path into the tree
	node *packet_node;				//Node of current packet in the tree
	static int count;				//Number of packets written
  	wait_handle = 1;

	ehdr = (struct ether_header *) packetptr;
	if (ntohs (ehdr->ether_type) != ETHERTYPE_IP) {	//If not IP, then return
		printf("\nim returning");
		return;
	}
	else if(h->caplen >= 1500)						//If packet size exceeds maximum allowed, return
		return;
	
	newPacket.timestamp = (u_int32_t)h->ts.tv_sec;	//Fill additional information about packet
	newPacket.ID = (u_int32_t)ID;
	newPacket.length = (u_int16_t)h->caplen;
	newPacket.dir = -1;

	struct_off = packet_off;						//Adjust and increment offsets of packet and prefix structure
	newPacket.next_offset = struct_off;
	packet_off = packet_off + sizeof(packet_record) + newPacket.length;
	printf("\n\t packet offset is %d %"PRIu32" %" PRIu32 , sizeof(packet_record),newPacket.length,packet_off);
	
	ID++;

	//Extract src/dest IP addr and port number information. Store it in flow record structure
	memset((void *)&h->extended_hdr.parsed_pkt,0,sizeof(struct pkt_parsing_info));
	pfring_parse_pkt((u_char *)packetptr,(struct pfring_pkthdr *)h,4,1,1);
	strcpy(ip_src, intoa(h->extended_hdr.parsed_pkt.ipv4_src));
	port_src = h->extended_hdr.parsed_pkt.l4_src_port;
	strcpy(ip_dst,intoa(h->extended_hdr.parsed_pkt.ipv4_dst));
	port_dst=h->extended_hdr.parsed_pkt.l4_dst_port;
	strcpy(flow_rec.ip_src,ip_src);
	strcpy(flow_rec.ip_dst,ip_dst);
	flow_rec.sport = port_src;
	flow_rec.dport = port_dst;
	flow_rec.offset = struct_off ;	
	
	//Convert IP address from string format to integer, for inserting in tree
	break_IP(ip_src,&ips1,&ips2,&ips3,&ips4);
	break_IP(ip_dst,&ipd1,&ipd2,&ipd3,&ipd4);	    				   
	
	packetptr +=ETHERNET_HDR_LEN;					//Jump to network layer header
	if(ntohs(ehdr->ether_type)==ETHERTYPE_IP) {		//verify it is IP header
		
		iphdr=(struct ip*)packetptr;				//Place IP header structure on packet
		packetptr += 4*iphdr->ip_hl;				//Increment pointer
		
		switch(iphdr->ip_p) {						//Check transport layer protocol
		
			case IPPROTO_TCP:{						//Transport layer protocol is TCP

			tcphdr = (struct tcphdr *)packetptr;	//Place TCP header structure on packet pointer
			roots=insert_tree(roott,port_src,ips1,ips2,ips3,ips4);//Insert the IP and port details in the tree
			rootd=insert_tree(roott,port_dst,ipd1,ipd2,ipd3,ipd4);
			to_jump=check_make_node(struct_off,&dir,roots,port_src,ips1,ips2,ips3,ips4,rootd,port_dst,ipd1,ipd2,ipd3,ipd4);
			newPacket.dir = dir;

			fwrite(&newPacket,sizeof(packet_record),1,fp);
			fwrite(pchar,newPacket.length,1,fp);
			
			if(to_jump == 0){					//If packet corresponds to a new flow
				printf("\nyes im new node");
				u_int8_t sIP[4],dIP[4];			//Structures of src/dest IP addr and port number
				u_int16_t sportno,dportno;		//Used in passing to bitmap functions	
				u_int8_t tproto = TPROTO_TCP;	
				
				sIP[0] = (u_int8_t)ips1;		//Fill the structures with src/dest IP addr and port numbers
				sIP[1] = (u_int8_t)ips2;
				sIP[2] = (u_int8_t)ips3;
				sIP[3] = (u_int8_t)ips4;
				sportno = (u_int16_t)port_src;
				dIP[0] = (u_int8_t)ipd1;
				dIP[1] = (u_int8_t)ipd2;
				dIP[2] = (u_int8_t)ipd3;
				dIP[3] = (u_int8_t)ipd4;
				dportno = (u_int16_t)port_dst;
				
				if(flowcount <= NO_FLOWS)        //It is the current threshold limit for number of flows which bitmap can index
				{
					add_IP_bitmap(sipbm,sIP,flowcount);			//Make entries in corresponding bitmaps
					add_port_bitmap(sprbm,sportno,flowcount);
					add_IP_bitmap(dipbm,dIP,flowcount);
					add_port_bitmap(dprbm,dportno,flowcount);
					add_tproto_bitmap(tpbm,tproto,flowcount);
					
					flowcount++;
				}
	
				fwrite(&flow_rec,sizeof(flow_record),1,fp1);	//Write the new flow record to file
			}
			else {								//If packet is from an old flow
					/*Jump to the prefix structure of previous packet belonging to same flow,
					Replace its next_offset value with the offset value of current packet*/
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
		case IPPROTO_UDP:{						//Transport layer header is UDP
			
			udphdr = (struct udphdr *)packetptr;//Place UDP structure on packet
			printf("\n\t*********i got udp");
			printf("\n\t %d %d || %d %d",ntohs(udphdr->source),port_src,ntohs(udphdr->dest),port_dst);
			roots=insert_tree(rootu,port_src,ips1,ips2,ips3,ips4);	//Insert IP addr and port no into UDP tree
			rootd=insert_tree(rootu,port_dst,ipd1,ipd2,ipd3,ipd4);
			to_jump=check_make_node(struct_off,&dir,roots,port_src,ips1,ips2,ips3,ips4,rootd,port_dst,ipd1,ipd2,ipd3,ipd4);
			flow_rec.sport = port_src;
			flow_rec.dport = port_dst;
			flow_rec.offset = newPacket.next_offset;	
			newPacket.dir=dir;

			fwrite(&newPacket,sizeof(packet_record),1,fp);	//Write prefix structure and packet to the file
			fwrite(pchar,newPacket.length,1,fp);
			
			if(to_jump == 0){						//If packet corresponds to a new flow
				u_int8_t sIP[4],dIP[4];				//Structures to pass to the add_bitmap function calls
				u_int16_t sportno,dportno;				
				u_int8_t tproto = TPROTO_UDP;		
				
		  		printf("\nyes im new node");
				
				sIP[0] = (u_int8_t)ips1;			//Fill the structures with src/dest IP addr and port numbers
				sIP[1] = (u_int8_t)ips2;
				sIP[2] = (u_int8_t)ips3;
				sIP[3] = (u_int8_t)ips4;
				sportno = (u_int16_t)port_src;
				dIP[0] = (u_int8_t)ipd1;
				dIP[1] = (u_int8_t)ipd2;
				dIP[2] = (u_int8_t)ipd3;
				dIP[3] = (u_int8_t)ipd4;
				dportno = (u_int16_t)port_dst;
				
				if(flowcount <= NO_FLOWS)        //It is the current threshold limit for number of flows which bitmap can index
				{				
					add_IP_bitmap(sipbm,sIP,flowcount);		//Make entries in corresponding bitmaps
					add_port_bitmap(sprbm,sportno,flowcount);
					add_IP_bitmap(dipbm,dIP,flowcount);
					add_port_bitmap(dprbm,dportno,flowcount);
					add_tproto_bitmap(tpbm,tproto,flowcount);
					
					flowcount++;
				}
				
	  			fwrite(&flow_rec,sizeof(flow_record),1,fp1);//Write the new flow record to file
				
			}
			else {								//If the packet is from an old flow
				/*Jump to the prefix structure of previous packet belonging to same flow,
				Replace its next_offset value with the offset value of current packet*/
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

	//No transport layer protocols other than TCP or UDP supported
	if(iphdr->ip_p != IPPROTO_TCP && iphdr->ip_p!=IPPROTO_UDP)
		packet_off = struct_off;

	count++;		//Increment packet count
	fflush(fp);		//Flush new data to files
	fflush(fp1);
	fflush(stdout);
  	wait_handle = 0;
}

//Reduce one time interval in timeouts for termination of flows
/*currently not required */
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

	printf("Save reset called.");
	//Save all uncompressed bitmaps
	save_IP_bitmap(sipbm,"IP_src.bitmap");
	save_port_bitmap(sprbm,"port_src.bitmap");
	save_tproto_bitmap(tpbm,"tproto.bitmap");
	save_IP_bitmap(dipbm,"IP_dest.bitmap");	
	save_port_bitmap(dprbm,"port_dest.bitmap");	
	
	//Compress and save bitmaps
	compress_IP_bitmap(sipbm,"IP_src-comp.bitmap");	
	compress_port_bitmap(sprbm,"port_src-comp.bitmap");
	compress_tproto_bitmap(tpbm,"tproto-comp.bitmap");
	compress_IP_bitmap(dipbm,"IP_dest-comp.bitmap");
	compress_port_bitmap(dprbm,"port_dest-comp.bitmap");
	
	//Clear bitmap memory for new slot
	memset(sipbm,0,sizeof(IP_bitmap));
	memset(sprbm,0,sizeof(port_bitmap));	
	memset(tpbm,0,sizeof(tproto_bitmap));
	memset(dipbm,0,sizeof(IP_bitmap));
	memset(dprbm,0,sizeof(port_bitmap));

	flowcount=1;
	
	sem_post(&sem);
	printf("Save reset ended.");
}

void handle_now()
{
	//activate semaphore
	sem_wait(&sem);
	printf("\n*       GOING IN    ");
	wait_parse = 0;

	//Close the files and reopen them
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

	//delete whole trees, i.e. one of TCP and other of UDP
	if(roott!=NULL){
		roott=delete_whole_tree(roott);
	}
	if(rootu!=NULL){
		rootu=delete_whole_tree(rootu);
	}

	//reallocate tree
	roott = allo_tree();
	rootu = allo_tree();
	ID = 0;
	struct_off = packet_off = 0;
	printf("going out");
	wait_parse = 1;
	sem_post(&sem);
}

void do_smth()
{
	char temp[1000];
	DIR* dir;
	int res1,res2;

	//Change directory to root of our folder
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
		//change the directory
		chdir(temp); 
		
		//create a new slot folder and change directory
		snprintf(buffer,32,"%d",slot);
		strcat(temp,"/");
		strcat(temp,buffer);
		res1=mkdir(buffer,0777);
		
		printf("\n\t res1 :: %d %s %s",res1,buffer,temp);
		chdir(temp);
		
		//handle the events
		handle_now();
	}
	//if directory is not present
	else if (ENOENT == errno)
	{
		//create a new day entry
		res1=mkdir(buffer,0777);
		res2=chdir(temp);
		
		//create a new slot and change directory
		printf("\n**i changed to %s",temp);
		snprintf(buffer,32,"%d",slot);
		strcat(temp,"/");
		strcat(temp,buffer);
		res2=mkdir(buffer,0777);
		
		printf("\n\t res1 :: %d res2 :: %d",res1,res2);
		chdir(temp);
		
		//handle the event
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

void *do_smth_periodically(void *theint)
{
	static int i=0;
	/*
		following if condition makes generate data and then once a slot is completed
		before changing the slot ,bitmaps for current slots are created and then slot is 
		changed.
	*/
	if(i)			
		save_reset_bitmaps();
	else
		i++;
	
	do_smth();
	slot++;
	
	//if the slots for a day are over then increment day and make slot to 0
	if(slot == slot_interval){
		day++;
		slot = 0;
	}
	if(i!=1)
	        alarm(SECONDS);
}


int main(int argc, char *argv[])
{
	char *dev;					// The device to sniff on
	int flags;					// Flags to pass for opening pfring instance
	int interval = 5000000;		// Packet interval
	struct pfring_pkthdr hdr;	// Additional PCAP header of a packet
	u_char *packet;				// Pointer to the packet captured
	time_t t = time(NULL);		// Time instances
	struct tm tm = *localtime(&t);
	
	sipbm = (IP_bitmap *)calloc(1,sizeof(IP_bitmap));			// Memory allocation for bitmaps
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
	slot = tm.tm_hour;											//Initialization of kernel timers
	day = tm.tm_mday;
	alarm(SECONDS - interval);
	printf("here is the difference %d",SECONDS - interval);

	signal(SIGALRM, (sighandler_t) do_smth_periodically);		//Handle termination signal
	signal(SIGINT,sigproc);
	
	dev = argv[1];							// Set the device manually to arg[1]
	printf("\nCapture device: %s\n", dev);
	
	if((fp=fopen(filename,"wb+"))==NULL)	// Open packet storage file
	{
		printf("\nError opening file for writing.");
		exit(1);
	}
	if((fp1=fopen(filename1,"wb+"))==NULL)	// Open flow record file
	{
		printf("\nError opening file for writing.");
		exit(1);
	}
	
	
	flags = PF_RING_PROMISC;
	if((handle = pfring_open(dev, 1500, flags)) == NULL) {	// Open instance of PF_RING to capture packets
   		printf("pfring_open error");
    	return(-1);
  	}
  	else {
		pfring_set_application_name(handle, "packetcapture");
	}
	
	if(sem_init(&sem,0,1)==0){								// Initialize semaphores
		printf("\n\tyes semphore is on");
	}
	else{
		printf("\n\t unable to init semaphore exiting ");
		exit(1);
	}
	
    day_interval = atoi(argv[2]);							// Set the day interval to argv[2]
	slot_interval = atoi(argv[3]);							// SEt the slot interval to argv[3]
	my_cwd = (char *)malloc(sizeof(char) * 1000);			// Used to keep track of current working directory
	getcwd(my_cwd,1000);									// Get current working directory
	
 	if(pthread_create(&thread2, NULL, do_smth_periodically, (void *)NULL)==0)
   		printf("\n\tcreated thread succesfully");			// Create separate thread to handle changing of slots after interval
	
	pfring_enable_ring(handle);								// Start PF_RING instance
	
	wait_parse = 1;
	do{
		while(wait_parse){									// Continuously capture packets via PF_RING
			if(pfring_recv(handle,&packet,0,&hdr,1) > 0){
				sem_wait(&sem);
				parse_packet(&hdr,packet);					// Parse the captured packet
				sem_post(&sem);
			}
		}
	}while(1);
	
	if(pthread_join(thread2,NULL)==0)						// Terminate threads peacefully
		printf("\n\t joined succesfully");
	
  	free(my_cwd);											// Release resources

	fclose(fp);	

	return 0;
}
