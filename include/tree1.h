/**************************************************************
This header file contains all the code related to tree
This tree is used for chaining packets


**************************************************************/

#include<stdio.h>
#include<stdlib.h>
#include<inttypes.h>
#define TIMEOUT 5
typedef struct tree tree;

typedef struct node
{
	int8_t properties;
	u_int32_t next_off;
	int ports,portd;
	int ips1,ips2,ips3,ips4;
	int ipd1,ipd2,ipd3,ipd4;
	tree *node_src;
	tree *node_dst;
	u_int8_t dir;
	int time,new;
}node;

typedef struct tree
{
	struct tree **child;
	int number_child;
	int data;
	struct node **packet;
}tree;

node *allo_node();

tree *allo_tree();

tree *insert_tree(tree *root,int port,int ip1,int ip2,int ip3,int ip4);

u_int32_t check_make_node(long ,u_int8_t *,tree *roots,int,int,int ,int ,int ,tree *rootd,int,int,int,int,int);

void check_delete_node(tree *roots,int,int,int ,int ,int ,tree *rootd,int,int,int,int,int);

void substract_one(tree *root);

void display_tree(tree *root);

int check_ipsrc(node *root,int port,int ip1,int ip2,int ip3,int ip4);

int check_ipdst(node *root,int port,int ip1,int ip2,int ip3,int ip4);

void take_back(tree *root,int i);

void delete_node(node *packet);
