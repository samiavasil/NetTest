/*
 * socket_helper.h
 *
 *  Created on: Jul 6, 2019
 *      Author: vvasilev
 */

#ifndef SOCKET_HELPER_H_
#define SOCKET_HELPER_H_

#include <netdb.h>
#include <net/if.h>

#define MAC_ADDR_LEN (6)

typedef enum {
	SOCK_STREAM_AF_UNSPEC, /*Stream use IPv4 or IPv6*/
	SOCK_STREAM_AF_IP4,    /*Stream use IPv4*/
	SOCK_STREAM_AF_IP6,    /*Stream use IPv4*/
	SOCK_DGRAM_AF_UNSPEC,  /*Datagram use IPv4 or IPv6*/
	SOCK_DGRAM_AF_IP4,     /*Datagram use IPv4*/
	SOCK_DGRAM_AF_IP6,     /*Datagram use IPv4*/
	SOCK_SNIF_ROW_ETH,     /*Row Ethernet packets*/
}net_sock_cfg_t;

typedef union {
	uint64_t mac;
	char mac_arrea[6];
}mac_addr_t;

const char* protocol_name(uint16_t type);
short int set_promiscuous(char *enterface,int *sock, int enbl);
void dump_addr_info(struct addrinfo *info);
int get_addrinfo(char* addr, char* port, struct addrinfo **res, net_sock_cfg_t type);

void *get_in_addr(struct sockaddr *sa);

#define SOCKET_NON_BLOCKING (1 << 0)
#define SOCKET_BIND         (1 << 1)
int init_socket(char* addr, char* port,  net_sock_cfg_t type, int options);

#define BLOCKING     0
#define NON_BLOCKING 1
int set_socket_blocking_mode(int fd, int mode);

#endif /* SOCKET_HELPER_H_ */
