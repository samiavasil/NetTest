#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>



typedef enum {
    SOCK_STREAM_AF_UNSPEC,
}_net_sock_cfg_t;

int init_socket(char* addr, char* port, struct addrinfo **res, _net_sock_cfg_t type) {

    struct addrinfo hints;
    int sockfd = -1;
    int status = 0;


    memset(&hints, 0, sizeof hints);
    switch(type) {
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
    if(0 == status) {
	if(NULL == addr) {
	    hints.ai_flags = AI_PASSIVE; // fill my local IP, when the addr is NULL
	}

	if ((status = getaddrinfo(addr, port, &hints, res)) == 0) {
		// make a socket:
	    sockfd = socket((*res)->ai_family, (*res)->ai_socktype, (*res)->ai_protocol);
	}
	else {
	    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(status));
	}
    }
    return sockfd;
}

void dump_addr_info(struct addrinfo *info) {

	struct addrinfo  *p;
	char ipstr[INET6_ADDRSTRLEN];

	if(NULL == info) {
		fprintf(stderr, "adrrinfo is NULL");
		return;
	}

	for(p = info;p != NULL; p = p->ai_next) {
        void *addr;
        char *ipver;
        // get the pointer to the address itself,
        // different fields in IPv4 and IPv6:
        if (p->ai_family == AF_INET) { // IPv4
            struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
            addr = &(ipv4->sin_addr);
            ipver = "IPv4";
        } else { // IPv6
            struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)p->ai_addr;
            addr = &(ipv6->sin6_addr);
            ipver = "IPv6";
        }

        // convert the IP to a string and print it:
        inet_ntop(p->ai_family, addr, ipstr, sizeof ipstr);
        printf("  %s: %s\n", ipver, ipstr);
    }
}

int main(int argc, char *argv[])
{

	struct addrinfo *res = NULL;
    int sockfd;
    char* name = NULL;
    char* port = NULL;

    if (argc < 2) {
        fprintf(stderr,"usage: showip hostname\n");
        return 1;
    }
    if (strcmp(argv[1], "NULL")) {
    	name = argv[1];
    }
    if (argc == 3) {
	    port = argv[2];
    }

    sockfd = init_socket(name, port, &res, SOCK_STREAM_AF_UNSPEC);

    printf("IP addresses for %s:\n\n", argv[1]);

    dump_addr_info(res);

    if(sockfd < 0) {
	printf("Socket init error: %s %s:\n\n", argv[1], port);
	return 1;
    }
    // bind it to the port we passed in to getaddrinfo():

    if (bind(sockfd, res->ai_addr, res->ai_addrlen) < 0) {
	fprintf(stderr, "bind error: %s\n", strerror(errno));
    }
    close(sockfd);

    freeaddrinfo(res); // free the linked list




    return 0;
}
