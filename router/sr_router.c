/**********************************************************************
* file:  sr_router.c
* date:  Mon Feb 18 12:50:42 PST 2002
* Contact: casado@stanford.edu
*
* Description:
*
* This file contains all the functions that interact directly
* with the routing table, as well as the main entry method
* for routing.
*
**********************************************************************/

#include <stdio.h>
#include <assert.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>

/*---------------------------------------------------------------------
* Method: sr_init(void)
* Scope:  Global
*
* Initialize the routing subsystem
*
*---------------------------------------------------------------------*/

void send_arp_reply(struct sr_instance* sr,
	uint8_t * packet/* lent */,
	unsigned int len,
	char* interface/* lent */)
{

	uint8_t buf[len];
	int i;
	
	for (i = 0; i<len; i++)
		buf[i] = packet[i];
	for (i = 0; i<6; i++)
		buf[i] = packet[i + 6];
	struct sr_if *a = sr->if_list;

	if (packet[38] == 10) {
		for (i = 0; i<6; i++) {
			buf[i + 6] = a->addr[i];
		}
	}
	else if (packet[38] == 172) {
		a = a->next;
		for (i = 0; i<6; i++) {
			buf[i + 6] = a->addr[i];
		}
	}
	else if (packet[38] == 192) {
		a = a->next->next;
		for (i = 0; i<6; i++) {
			buf[i + 6] = a->addr[i];
		}
	}

	buf[21]++;
	for (i = 0; i<6; i++) {
		buf[22 + i] = buf[6 + i];
		buf[32 + i] = buf[i];
	}
	for (i = 0; i<4; i++) {
		buf[28 + i] = packet[38 + i];
		buf[38 + i] = packet[28 + i];
	}


	printf("%d",sr_send_packet(sr, buf, len, interface));
}



void send_icmp_reply(struct sr_instance* sr,
	uint8_t * packet/* lent */,
	unsigned int len,
	char* interface/* lent */)
{
	uint8_t buf[len];
	int i;
	
	for (i = 0; i<len; i++)
		buf[i] = packet[i];
	for (i = 0; i<6; i++)
		buf[i] = packet[i + 6];
	struct sr_if *a = sr->if_list;

	if (packet[30] == 10) {
		for (i = 0; i<6; i++) {
			buf[i + 6] = a->addr[i];
		}
	}
	else if (packet[30] == 172) {
		a = a->next;
		for (i = 0; i<6; i++) {
			buf[i + 6] = a->addr[i];
		}
	}
	else if (packet[30] == 192) {
		a = a->next->next;
		for (i = 0; i<6; i++) {
			buf[i + 6] = a->addr[i];
		}
	}

	
	
	for (i = 0; i<4; i++) {
		buf[26 + i] = packet[30 + i];
		buf[30 + i] = packet[26 + i];
	}
	buf[34]=0;

/*ICMP checksum*/
	buf[36]=0;
	buf[37]=0;
	int cks_icmp=cksum(&buf[34],len-34);
	buf[37]=cks_icmp/256;
	buf[36]=cks_icmp%256;




/*IP checksum*/
	buf[24]=0;
	buf[25]=0;
	int cks_ip=cksum(&buf[14],20);
	buf[25]=cks_ip/256;
	buf[24]=cks_ip%256;

	printf("%d",sr_send_packet(sr, buf, len, interface));
}



void sr_init(struct sr_instance* sr)
{
	/* REQUIRES */
	assert(sr);

	/* Initialize cache and cache cleanup thread */
	sr_arpcache_init(&(sr->cache));

	pthread_attr_init(&(sr->attr));
	pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
	pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
	pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
	pthread_t thread;

	pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);

	/* Add initialization code here! */

} /* -- sr_init -- */

  /*---------------------------------------------------------------------
  * Method: sr_handlepacket(uint8_t* p,char* interface)
  * Scope:  Global
  *
  * This method is called each time the router receives a packet on the
  * interface.  The packet buffer, the packet length and the receiving
  * interface are passed in as parameters. The packet is complete with
  * ethernet headers.
  *
  * Note: Both the packet buffer and the character's memory are handled
  * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
  * packet instead if you intend to keep it around beyond the scope of
  * the method call.
  *
  *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
	uint8_t * packet/* lent */,
	unsigned int len,
	char* interface/* lent */)
{
	/* REQUIRES */
	assert(sr);
	assert(packet);
	assert(interface);

	printf("*** -> Received packet of length %d \n", len);

	/* fill in code here */	

if(packet[13] == 6) 
	send_arp_reply(sr,packet,len,interface);
if(packet[13] == 0)
	send_icmp_reply(sr,packet,len,interface);



}/* end sr_ForwardPacket */

