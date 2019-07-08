/*
 * socket_helper.c
 *
 *  Created on: Jul 6, 2019
 *      Author: vvasilev
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>

#include "socket_helper.h"

#include <net/ethernet.h>



typedef struct {
    const char* name;
    uint16_t type;
} prot_types_t;

#define STR(x) #x
#define EXPAND_TYPE(x)  {#x, x}

static const prot_types_t _prot_types[] = {
    EXPAND_TYPE(ETHERTYPE_PUP),       /* Xerox PUP */
    EXPAND_TYPE(ETHERTYPE_SPRITE),	  /* Sprite */
    EXPAND_TYPE(ETHERTYPE_IP),		  /* IP */
    EXPAND_TYPE(ETHERTYPE_ARP),		  /* Address resolution */
    EXPAND_TYPE(ETHERTYPE_REVARP),	  /* Reverse ARP */
    EXPAND_TYPE(ETHERTYPE_AT),		  /* AppleTalk protocol */
    EXPAND_TYPE(ETHERTYPE_AARP),	  /* AppleTalk ARP */
    EXPAND_TYPE(ETHERTYPE_VLAN),	  /* IEEE 802.1Q VLAN tagging */
    EXPAND_TYPE(ETHERTYPE_IPX),		  /* IPX */
    EXPAND_TYPE(ETHERTYPE_IPV6),	  /* IP protocol version 6 */
    EXPAND_TYPE(ETHERTYPE_LOOPBACK),  /* used to test interfaces */
};

const char*
protocol_name(uint16_t type)
{
    const char* res = "UNCKNOWN";
    for (int i = 0; i < sizeof(_prot_types) / sizeof(_prot_types[0]); i++) {
	if (_prot_types[i].type == type) {
	    res = _prot_types[i].name;
	}
    }
    return res;
}

short int
set_promiscuous(char* enterface, int* sock, int enbl)
{
    struct ifreq ifr;
    short int old_mode = -1;

    strcpy(ifr.ifr_name, enterface);

    if (ioctl(*sock, SIOCGIFFLAGS, &ifr) == -1) {
	printf("get '%s' current promiscuous mode failed!\n", enterface);
	exit(1);
    }

    old_mode = ifr.ifr_flags;

    if (enbl) {
	printf("'%s' enable promiscuous mode!\n", enterface);
	ifr.ifr_flags |= IFF_PROMISC;
    } else {
	printf("'%s' disable promiscuous mode!\n", enterface);
	ifr.ifr_flags &= (~IFF_PROMISC);
    }

    if (old_mode != ifr.ifr_flags) {

	if (ioctl(*sock, SIOCSIFFLAGS, &ifr) == -1) {
	    printf("set '%s' to promiscuous model failed\n",
		   enterface); //cant write  '%s',enterface  why?
	    exit(1);
	}
	printf("'%s' successfully %s promiscuous mode!\n", enterface,
	       (ifr.ifr_flags & IFF_PROMISC) ? "enabled" : "disabled");
    } else {
	printf("'%s' promiscuous mode is already %s!\n", enterface,
	       (ifr.ifr_flags & IFF_PROMISC) ? "enabled" : "disabled");
    }

    return old_mode;
}

    void
dump_addr_info(struct addrinfo* info)
{

    struct addrinfo*  p;
    char ipstr[INET6_ADDRSTRLEN];

    if (NULL == info) {
	fprintf(stderr, "adrrinfo is NULL");
	return;
    }

    for (p = info; p != NULL; p = p->ai_next) {
	void* addr;
	char* ipver;
	// get the pointer to the address itself,
	// different fields in IPv4 and IPv6:
	if (p->ai_family == AF_INET) { // IPv4
	    struct sockaddr_in* ipv4 = (struct sockaddr_in*)p->ai_addr;
	    addr = &(ipv4->sin_addr);
	    ipver = "IPv4";
	} else { // IPv6
	    struct sockaddr_in6* ipv6 = (struct sockaddr_in6*)p->ai_addr;
	    addr = &(ipv6->sin6_addr);
	    ipver = "IPv6";
	}

	// convert the IP to a string and print it:
	inet_ntop(p->ai_family, addr, ipstr, sizeof ipstr);
	printf("  %s: %s\n", ipver, ipstr);
    }
}

int
get_addrinfo(char* addr, char* port, struct addrinfo** res,
	     net_sock_cfg_t type)
{

    struct addrinfo hints;
    int status = 0;

    memset(&hints, 0, sizeof hints);

    switch (type) {
    case SOCK_STREAM_AF_UNSPEC: {
	hints.ai_family = AF_UNSPEC;  // use IPv4 or IPv6, whichever
	hints.ai_socktype = SOCK_STREAM;
	break;
    }
    default: {
	fprintf(stderr, "getaddrinfo: wrong type %d\n", type);
	status = -1;
    }
    }

    if (0 == status) {

	if (NULL == addr) {
	    hints.ai_flags = AI_PASSIVE; // fill my local IP, when the addr is NULL
	}

	status = getaddrinfo(addr, port, &hints, res);

	if (0 != status) {
	    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(status));
	}
    }

    return status;
}

    // get sockaddr, IPv4 or IPv6:
    void*
get_in_addr(struct sockaddr* sa)
{
    if (sa->sa_family == AF_INET) {
	return &(((struct sockaddr_in*)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

    /** Returns 0 on success, or -1 if there was an error */
int
set_socket_blocking_mode(int fd, int mode)
{
    if (fd < 0) return -1;
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) return -1;
    flags = (mode == BLOCKING) ? (flags & ~O_NONBLOCK) : (flags | O_NONBLOCK);
    return (fcntl(fd, F_SETFL, flags) == 0) ? 0 : -1;
}

int
init_socket(char* addr, char* port,  net_sock_cfg_t type, int options)
{

    struct addrinfo hints;
    int sockfd = -1;
    int status = 0;
    struct addrinfo* add_info = NULL;

    memset(&hints, 0, sizeof hints);

    switch (type) {
    case SOCK_STREAM_AF_UNSPEC: {

	hints.ai_family = AF_UNSPEC;  // use IPv4 or IPv6, whichever
	hints.ai_socktype = SOCK_STREAM;
	break;
    }
    case SOCK_STREAM_AF_IP4: {

	hints.ai_family = AF_INET;  // use IPv4 or IPv6, whichever
	hints.ai_socktype = SOCK_STREAM;
	break;
    }
    case SOCK_STREAM_AF_IP6: {

	hints.ai_family = AF_INET6;  // use IPv4 or IPv6, whichever
	hints.ai_socktype = SOCK_STREAM;
	break;
    }
    case SOCK_DGRAM_AF_UNSPEC: {

	hints.ai_family = AF_UNSPEC;  // use IPv4 or IPv6, whichever
	hints.ai_socktype = SOCK_DGRAM;
	break;
    }
    case SOCK_DGRAM_AF_IP4: {

	hints.ai_family = AF_INET;  // use IPv4 or IPv6, whichever
	hints.ai_socktype = SOCK_DGRAM;
	break;
    }
    case SOCK_DGRAM_AF_IP6: {

	hints.ai_family = AF_INET6;  // use IPv4 or IPv6, whichever
	hints.ai_socktype = SOCK_DGRAM;
	break;
    }
    case SOCK_SNIF_ROW_ETH: { // use row socket to sniff

	hints.ai_family = AF_PACKET;
	hints.ai_socktype = SOCK_RAW;
	hints.ai_protocol = htons(ETH_P_ALL);
	break;
    }
    default: {

	fprintf(stderr, "getaddrinfo: wrong type %d\n", type);
	status = -1;
    }
    }

    if (0 == status) {

	if (SOCK_SNIF_ROW_ETH == type) {

	    sockfd = socket(hints.ai_family, hints.ai_socktype, hints.ai_protocol);
	} else {

	    if (NULL == addr) {

		hints.ai_flags = AI_PASSIVE; // fill my local IP, when the addr is NULL
	    }

	    if ((status = getaddrinfo(addr, port, &hints, &add_info)) == 0) {
		struct addrinfo* p;
		// make a socket:

		for (p = add_info; p != NULL; p = p->ai_next) {

		    if ((sockfd = socket(p->ai_family, p->ai_socktype,
					 p->ai_protocol)) == -1) {
			perror("server: socket");
			continue;
		    }

		    if (options & SOCKET_BIND) {
			int yes = 1;

			if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes,
				       sizeof(int)) == -1) {
			    perror("setsockopt");
			    close(sockfd);
			    sockfd = -1;
			    continue;
			}

			if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
			    perror("server: bind");
			    close(sockfd);
			    sockfd = -1;
			    continue;
			}
		    }
		    break;
		}


	    } else {

		fprintf(stderr, "getaddrinfo: %d %s\n", status, gai_strerror(status));
	    }
	}

    }

    if ((sockfd > 0) && (options & SOCKET_NON_BLOCKING)) {

	if (set_socket_blocking_mode(sockfd, NON_BLOCKING) < 0) {
	    perror("Can't set nonblocking: ioctl() failed");
	    sockfd = -1;
	}

    }

    if (NULL != add_info) {
	freeaddrinfo(add_info);
    }
    return sockfd;
}
