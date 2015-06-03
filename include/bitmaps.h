#define NO_FLOWS 128					//Since 100/8 is approx. equal to 13. 16 is closest to 13 which is multiple of 4 and 8.
#define FOLDER ""
#define WORDSIZE u_int32_t
#define BYTES_IN_WORD 4
#define BITS_IN_WORD 32

#define TPROTO_TCP 0
#define TPROTO_UDP 1

/*
Structure of bitmap on IP address - both source and destination.
One member of each octet of IP.
In each octet, one row corresponds to one possible value of that octet
and columns give the flow record no. in which that value of octet is present 
*/
typedef struct IP_bitmap {
	u_char octet1[256][NO_FLOWS];     
	u_char octet2[256][NO_FLOWS];
	u_char octet3[256][NO_FLOWS];
	u_char octet4[256][NO_FLOWS];
}IP_bitmap;

/*
Structure of bitmap on port numbers - both source and destination.
One row corresponds to one possible value of port number.
Columns give the flow record no. in which that value of port no is present
*/
typedef struct port_bitmap {
	u_char port[65536][NO_FLOWS];
}port_bitmap;

/*
Structure of bitmap on transport protocol.
0th row - TCP
1st row - UDP
2nd row - Future use
Columns give the flow record no. in which that transport protocol is present
*/
typedef struct tproto_bitmap {
	u_char tproto[3][NO_FLOWS]; //TCP, UDP and future use = 3
}tproto_bitmap;

//Function to check whether given word is literal (for compression)
int isLiteral(WORDSIZE);

//Function to check whether given word is fill type and if it can be compressed
int isFill(WORDSIZE);

/* Bitmaps are big endian by default and machines are little endian. This function converts little endian words to big endian.
Works only for 32 bit word size. */
WORDSIZE little_to_big(WORDSIZE);

/* Accept an IP address, its corresponding flow number, and enter it into IP bitmap pointed to by first argument - ipbm */
void add_IP_bitmap(IP_bitmap *ipbm, u_int8_t *IP, int);

/* Accept a port number, its corresponding flow number, and enter it into port bitmap pointed to by first argument - prbm */
void add_port_bitmap(port_bitmap *prbm, u_int16_t portno, int flowID);

/* Accept a transport protocol ID (0 - TCP, 1 - UDP, 2 -Future use), the belonging flow number and enter into bitmap for
transport protocol pointed to by first argument - tpbm */
void add_tproto_bitmap(tproto_bitmap *tpbm, u_int8_t tprotonum, int flowID);

/* Compresses one single bit vector pointed to by 2nd argument and the result is stored in location pointed by first argument.
Uses WAH scheme for compression. */
int compress_bitvector(u_char *dstbitvector, u_char *srcbitvector);	

/* Accepts an IP bitmap pointed to by first argument, compresses it with the help of multiple calls to compress_bitvector,
and the resulting compressed bitmap is stored in file whose name is given as 2nd argument. */
void compress_IP_bitmap(IP_bitmap *ipbm, const char *filename);

/* Accepts a port bitmap pointed to by first argument, compresses it with the help of multiple calls to compress_bitvector,
and the resulting compressed bitmap is stored in file whose name is given as 2nd argument. */
void compress_port_bitmap(port_bitmap *prbm, const char *filename);

/* Accepts a transport protocol bitmap pointed to by first argument, compresses it with the help of multiple calls to compress_bitvector,
and the resulting compressed bitmap is stored in file whose name is given as 2nd argument. */
void compress_tproto_bitmap(tproto_bitmap *tpbm, const char *filename);

/* Accepts an IP bitmap and directly stores it in the file whose name is given by 2nd argument. No compression is done.*/
void save_IP_bitmap(IP_bitmap *ipbm, char *filename);

/* Accepts a port bitmap and directly stores it in the file whose name is given by 2nd argument. No compression is done. */
void save_port_bitmap(port_bitmap *prbm, char *filename);

/*
Accepts a transport protocol bitmap and directly stores it in the file whose name is given
by 2nd argument. No compression is done.
*/
void save_tproto_bitmap(tproto_bitmap *tpbm, char *filename);

/*
Displays an uncompressed IP bitmap pointed by first argument.
The number of flows in that bitmap to be displayed are given in 2nd argument.
*/
void display_IP_bitmap(IP_bitmap *ipbm, int totalFlow);

/*
Displays an uncompressed port bitmap pointed by first argument.
The number of flows in that bitmap to be displayed are given in 2nd argument.
*/
void display_port_bitmap(port_bitmap *prbm, int totalFlow);

/*
Displays an uncompressed transport protocol bitmap pointed by first argument.
The number of flows in that bitmap to be displayed are given in 2nd argument.
*/
void display_tproto_bitmap(tproto_bitmap *tpbm, int totalFlow);
