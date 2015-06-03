

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
/*


*/
typedef struct tree
{
	struct tree **child;
	int number_child;
	int data;
	struct node **packet;
}tree;

node *allo_node()
{
	node *temp;
	temp=(node *)malloc(sizeof(node));
	temp->properties=0;
	temp->next_off=0;
	temp->node_src=NULL;
	temp->node_dst=NULL;
	temp->time = TIMEOUT * 2;
	temp->new=1;
	temp->dir=0;
	return temp;
}

tree *allo_tree()
{
	tree *temp;
	temp=(tree *)malloc(sizeof(tree));
	temp->number_child=0;
	temp->packet=NULL;
	temp->data=0;
	temp->child=(tree **)malloc(sizeof(tree *));

	return temp;
}

tree *insert_tree(tree *root,int port,int ip1,int ip2,int ip3,int ip4);
u_int32_t check_make_node(long ,u_int8_t *,tree *roots,int,int,int ,int ,int ,tree *rootd,int,int,int,int,int);
void check_delete_node(tree *roots,int,int,int ,int ,int ,tree *rootd,int,int,int,int,int);
void substract_one(tree *root);
void display_tree(tree *root);
void make_all_offset_zero(tree *root);
tree *delete_whole_tree(tree *);

/*
int main()
{
	tree *root =allo_tree();
	tree *roots,*rootd;
	node *packet;
	int ports,portd,ips1,ips2,ips3,ips4,ipd1,ipd2,ipd3,ipd4;
	long offset;
	u_int8_t dir;
	while(1){
		printf("\n\tEnter source port and IP ");
		scanf("%d%d%d%d%d",&ports,&ips1,&ips2,&ips3,&ips4);
		roots=insert_tree(root,ports,ips1,ips2,ips3,ips4);
		printf("\n\tEnter desti port and IP ");
		scanf("%d%d%d%d%d",&portd,&ipd1,&ipd2,&ipd3,&ipd4);
		rootd=insert_tree(root,portd,ipd1,ipd2,ipd3,ipd4);
		offset=check_make_node(offset,&dir,roots,ports,ips1,ips2,ips3,ips4,rootd,portd,ipd1,ipd2,ipd3,ipd4);
		printf("\n\twant to delete :: ");
		scanf("%d",&ips1);
		if(ips1==1){
			printf("\n\tEnter source port and IP ");
		scanf("%d%d%d%d%d",&ports,&ips1,&ips2,&ips3,&ips4);
		roots=insert_tree(root,ports,ips1,ips2,ips3,ips4);
		printf("\n\tEnter desti port and IP ");
		scanf("%d%d%d%d%d",&portd,&ipd1,&ipd2,&ipd3,&ipd4);
		rootd=insert_tree(root,portd,ipd1,ipd2,ipd3,ipd4);
		check_delete_node(roots,ports,ips1,ips2,ips3,ips4,rootd,portd,ipd1,ipd2,ipd3,ipd4);


		}
		if(ips1==2){
			root=delete_whole_tree(root);
			root = allo_tree();
			//	rootd=delete_whole_tree(rootd);
		}
		//substract_one(root);
	}
	return 0;
}
*/
tree *insert_tree(tree *root,int port,int ip1,int ip2,int ip3,int ip4)
{
	int i,j,check,new,skip;
	tree *temp;
	i=j=check=new=skip=0;
	temp=root;
//****************PORT******************************************
	while(i<root->number_child){
		if(port==root->child[i]->data){
			root=root->child[i];
			check=1;
			break;
		}
		i++;
	}
	if(check==0){
		new=1;
		root->number_child++;
		temp=allo_tree();
		temp->data=port;
		root->child=(tree **)realloc(root->child,sizeof(tree *)*root->number_child);
		root->child[root->number_child-1]=temp;
		root=root->child[root->number_child-1];
		skip=1;
	}
//	else
//		printf("\n\tI got same or created %d  %d",port,skip);
	i=0;
	check=0;
//****************IP1*******************************************
	if(skip==0){
  
		while(i<root->number_child){
			if(ip1==root->child[i]->data){
				root=root->child[i];
				check=1;
				break;
			}
			i++;
		}
	}
	if(check==0){
   		new=1;
	   	root->number_child++;
   		temp=allo_tree();
   		temp->data=ip1;
   		root->child=(tree **)realloc(root->child,sizeof(tree *)*root->number_child);
   		root->child[root->number_child-1]=temp;
   		root=root->child[root->number_child-1];
   		skip=1;
   	}	
//	else
//		printf("\n\tI got same %d ",ip1);
	i=0;	
	check=0;
//****************IP2*****************************************
	if(skip==0){
  
		while(i<root->number_child){
			if(ip2==root->child[i]->data){
				root=root->child[i];
				check=1;
				break;
			}
			i++;
		}
	}
   	if(check==0){
   		new=1;
   		root->number_child++;
   		temp=allo_tree();
   		temp->data=ip2;
   		root->child=(tree **)realloc(root->child,sizeof(tree *)*root->number_child);
   		root->child[root->number_child-1]=temp;
   		root=root->child[root->number_child-1];
   		skip=1;
   	}
//	else
//		printf("\n\tI got same %d ",ip2);
	i=0;
	check=0;
//*****************IP3***************************************
	
	if(skip==0){
  
		while(i<root->number_child){
			if(ip3==root->child[i]->data){
				root=root->child[i];
				check=1;
				break;
			}
			i++;
		}
	}
   	if(check==0){
   		new=1;
   		root->number_child++;
   		temp=allo_tree();
   		temp->data=ip3;
   		root->child=(tree **)realloc(root->child,sizeof(tree *)*root->number_child);
   		root->child[root->number_child-1]=temp;
   		root=root->child[root->number_child-1];
   		skip=1;
   	}
//	else
//		printf("\n\tI got same %d ",ip3);	
	i=0;	
	check=0;
//********************IP4***************************************	
	if(skip==0){
  
		while(i<root->number_child){
			if(ip4==root->child[i]->data){
				root=root->child[i];
				check=1;
				break;
			}
			i++;
		}
	}
   	if(check==0){
   		new=1;
   		root->number_child++;
   		temp=allo_tree();
   		temp->data=ip4;
   		root->child=(tree **)realloc(root->child,sizeof(tree *)*root->number_child);
   		root->child[root->number_child-1]=temp;
   		root=root->child[root->number_child-1];
		root->packet = (node **)malloc(sizeof(node *));
   		skip=1;
   	}	
	else
		printf("\n\tI got same %d %d %d %d ",ip1,ip2,ip3,ip4);
	return root;
}


int check_ipsrc(node *root,int port,int ip1,int ip2,int ip3,int ip4)
{
   
		if(root->ips1==ip1 && root->ports==port && root->ips2==ip2 && root->ips3==ip3 && root->ips4==ip4)
			return 1;
		else
			return 0;
}
int check_ipdst(node *root,int port,int ip1,int ip2,int ip3,int ip4)
{
   
		if(root->ipd1==ip1 && root->portd==port && root->ipd2==ip2 && root->ipd3==ip3 && root->ipd4==ip4)
			return 1;
		else
			return 0;
}

u_int32_t check_make_node(long offset,u_int8_t *direction,tree *roots,int ports,int ips1,int ips2,int ips3,int ips4,tree *rootd,int portd,int ipd1,int ipd2,int ipd3,int ipd4)
{
	node *temp;
	int gots,gotd,dir,i;
	static int cnt=0;
	long ret_val;
	i=0;
	
//	printf("\n\ti got %d%d%d%d%d %d%d%d%d%d",ports,ips1,ips2,ips3,ips4,portd,ipd1,ipd2,ipd3,ipd4);
	if(roots->number_child <= rootd->number_child)
		dir=1;
	else
		dir=0;
	if(dir == 1){
		while(i<roots->number_child){
			if(roots->packet[i]!=NULL){
				gots = check_ipsrc(roots->packet[i],ports,ips1,ips2,ips3,ips4);
				if(gots){
					gotd=check_ipdst(roots->packet[i],portd,ipd1,ipd2,ipd3,ipd4);
					
					if(gotd){
						*direction = roots->packet[i]->dir;
						ret_val = roots->packet[i]->next_off;
						roots->packet[i]->new = 0;
						roots->packet[i]->next_off = offset;
						roots->packet[i]->time=TIMEOUT * 2;
						roots->packet[i]->dir = 0;
						return ret_val;
					}
				}
				else{
					gotd=check_ipsrc(roots->packet[i],portd,ipd1,ipd2,ipd3,ipd4);
					*direction=1;
					if(gotd){
						*direction = roots->packet[i]->dir;
						ret_val=roots->packet[i]->next_off;
						roots->packet[i]->new = 0;
						roots->packet[i]->next_off = offset;
						roots->packet[i]->time=TIMEOUT * 2;
						roots->packet[i]->dir = 1;
						return ret_val;
					}
				}
			}
			i++;
		}
	}
	else{
		while(i<rootd->number_child){
			if(rootd->packet[i]!=NULL){
				gotd = check_ipsrc(rootd->packet[i],portd,ipd1,ipd2,ipd3,ipd4);
				if(gotd){
					gots=check_ipdst(rootd->packet[i],ports,ips1,ips2,ips3,ips4);
					*direction = 1;
					if(gots){
						*direction = rootd->packet[i]->dir;
						ret_val=rootd->packet[i]->next_off;
						rootd->packet[i]->new = 0;
						rootd->packet[i]->next_off = offset;
						rootd->packet[i]->time=TIMEOUT * 2;
						rootd->packet[i]->dir = 1;
						return ret_val;
					}
				}
				else{
					gots=check_ipsrc(rootd->packet[i],ports,ips1,ips2,ips3,ips4);
					*direction = 0;
					if(gots){
						*direction=rootd->packet[i]->dir;
						ret_val = rootd->packet[i]->next_off;
						rootd->packet[i]->new = 0;
						rootd->packet[i]->next_off = offset;
						rootd->packet[i]->time=TIMEOUT * 2;
						rootd->packet[i]->dir = 0;
						return ret_val;
					}
				}
			}
			i++;
		}
		
	}
	*direction = 0;
	printf("\n\tnew[%d] %d:%d.%d.%d.%d <---> %d:%d.%d.%d.%d",cnt,ports,ips1,ips2,ips3,ips4,portd,ipd1,ipd2,ipd3,ipd4);
	temp=allo_node();
	temp->ips1=ips1;
	temp->ips2=ips2;
	temp->ips3=ips3;
	temp->ips4=ips4;
	temp->ipd1=ipd1;
	temp->ipd2=ipd2;
	temp->ipd3=ipd3;
	temp->ipd4=ipd4;
	temp->ports=ports;
	temp->portd=portd;
	temp->next_off=offset;
	temp->node_src = roots;
	temp->node_dst = rootd;
	temp->dir=0;
	temp->new = 1;
	roots->packet=(node **)realloc(roots->packet,sizeof(node *) * (roots->number_child+1));
	rootd->packet=(node **)realloc(rootd->packet,sizeof(node *) * (rootd->number_child+1));
	roots->packet[roots->number_child]=temp;
	rootd->packet[rootd->number_child]=temp;
	rootd->packet[rootd->number_child]->time=TIMEOUT * 2;
				
	roots->number_child++;
	rootd->number_child++;
	cnt++;
	
	return 0;
}

void take_back(tree *root,int i)
{
	while(i<root->number_child-1){
		root->packet[i]=root->packet[i+1];
		i++;
	}
	root->number_child--;
	root->packet=(node **)realloc(root->packet,sizeof(node *)*(root->number_child));
}
void check_delete_node(tree *roots,int ports,int ips1,int ips2,int ips3,int ips4,tree *rootd,int portd,int ipd1,int ipd2,int ipd3,int ipd4)
{
	node *temp;
	int gots,gotd,dir,i;
	static int cnt=0;
	i=0;

		while(i<roots->number_child){
			if(roots->packet[i]!=NULL){
			gots = check_ipsrc(roots->packet[i],ports,ips1,ips2,ips3,ips4);
			if(gots){
			    gotd=check_ipdst(roots->packet[i],portd,ipd1,ipd2,ipd3,ipd4);
				if(gotd){
					printf("\n\tDeleteing packet at [%d] ",i);
					roots->packet[i]->next_off = 0;
					free(roots->packet[i]);
					roots->packet[i]=NULL;
					//take_back(roots,i);
					break;
				}
			}
			else{
				gotd=check_ipsrc(roots->packet[i],portd,ipd1,ipd2,ipd3,ipd4);
				if(gotd){
					printf("\n\tDeleteing packet at [%d] ",i);
					roots->packet[i]->next_off = 0;
					free(roots->packet[i]);
					roots->packet[i]=NULL;					
					//take_back(roots,i);
					break;
				}
			}
			}
			i++;
		}
		i=0;
 
		while(i<rootd->number_child){
			if(rootd->packet[i]!=NULL){			
			gotd = check_ipsrc(rootd->packet[i],portd,ipd1,ipd2,ipd3,ipd4);
			if(gotd){
			    gots=check_ipdst(rootd->packet[i],ports,ips1,ips2,ips3,ips4);
				if(gots){
					printf("\n\tDeleteing packet at [%d] ",i);
					//free(rootd->packet[i]);
					rootd->packet[i]=NULL;
					//take_back(rootd,i);
					break;
				}
			}
			else{
				gots=check_ipsrc(rootd->packet[i],ports,ips1,ips2,ips3,ips4);
				if(gots){
					printf("\n\tDeleteing packet at [%d] ",i);
					//free(rootd->packet[i]);
					rootd->packet[i]=NULL;
					//take_back(rootd,i);
					break;
				}
			}
			}
			i++;
		}

}

void delete_node(node *packet)
{
	tree *roots,*rootd;
	roots=packet->node_src;
	rootd=packet->node_dst;
	check_delete_node(roots,packet->ports,packet->ips1,packet->ips2,packet->ips3,packet->ips4,rootd,packet->portd,packet->ipd1,packet->ipd2,packet->ipd3,packet->ipd4);
}

void substract_one(tree *root)
{
	int i,j,k,l,m,n;
	tree *tempp,*temp1,*temp2,*temp3,*temp4;
	node *packet;
	i=j=k=l=m=n=0;
	while(i<root->number_child){
		tempp=root->child[i];
		j=0;
		while(j<tempp->number_child){
			temp1=tempp->child[j];
			k=0;
			while(k<temp1->number_child){
				temp2=temp1->child[k];
				l=0;
				while(l<temp2->number_child){
					temp3=temp2->child[l];
					m=0;
					while(m<temp3->number_child){
						temp4=temp3->child[m];
						n=0;
						while(n<temp4->number_child){
							packet=temp4->packet[n];
							packet->time--;
							if(packet->time==0){
								printf("time out packet ");
								delete_node(packet);
							}
							n++;
						}
						m++;
					}
					l++;
				}
				k++;
			}
			j++;
		}
		i++;
	}
}

void make_all_offset_zero(tree *root)
{
	int i,j,k,l,m,n;
	tree *tempp,*temp1,*temp2,*temp3,*temp4;
	node *packet;
	i=j=k=l=m=n=0;
	while(i<root->number_child){
		tempp=root->child[i];
		j=0;
		while(j<tempp->number_child){
			temp1=tempp->child[j];
			k=0;
			while(k<temp1->number_child){
				temp2=temp1->child[k];
				l=0;
				while(l<temp2->number_child){
					temp3=temp2->child[l];
					m=0;
					while(m<temp3->number_child){
						temp4=temp3->child[m];
						n=0;
						while(n<temp4->number_child){
							packet=temp4->packet[n];
							packet->next_off = 0;
							
							n++;
						}
						m++;
					}
					l++;
				}	
				k++;	
			}
			j++;
		}
		i++;
	}
}

/*
  this function is going to delete the
  whole tree, and is called by handle_now()
  function
 */
tree *delete_whole_tree(tree *root)
{
	int i,j,k,l,m,n;
	tree *tempp,*temp1,*temp2,*temp3,*temp4,*temps,*tempd;
	node *packet;
	i=j=k=l=m=n=0;
	while(i<root->number_child){
		tempp=root->child[i];
		j=0;
		while(j<tempp->number_child){
			temp1=tempp->child[j];
			k=0;
			while(k<temp1->number_child){
				temp2=temp1->child[k];
				l=0;
				while(l<temp2->number_child){
					temp3=temp2->child[l];
					m=0;
					while(m<temp3->number_child){
						temp4=temp3->child[m];
						n=0;
						while(n<temp4->number_child){
							packet=temp4->packet[n];
							if(packet!=NULL)
							delete_node(packet);
							n++;
						}
						free(temp4->packet);
						free(temp4);
						m++;
					}
					free(temp3->child);
					free(temp3);
					l++;
				}	
				free(temp2->child);
				free(temp2);
				k++;	
			}
			free(temp1->child);
			free(temp1);
			j++;
		}
		free(tempp->child);
		free(tempp);
		i++;
	}
	free(root);
	return NULL;
}
