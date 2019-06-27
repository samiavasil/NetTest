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

#include <sys/ioctl.h>
#include <sys/poll.h>
#include <sys/time.h>

#define TRUE             1
#define FALSE            0
#define MAX_PORT_CHARS 6
#define MASTER_PORT    "23232"
#define MAX_CONNECTIONS 20
#define BLOCKING (0)
#define NON_BLOCKING (1)

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

int get_addrinfo(char* addr, char* port, struct addrinfo **res, _net_sock_cfg_t type) {

	struct addrinfo hints;
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

		status = getaddrinfo(addr, port, &hints, res);

		if (0 != status) {
			fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(status));
		}
	}

	return status;
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

#include <fcntl.h>

/** Returns 0 on success, or -1 if there was an error */
int set_socket_blocking_mode(int fd, int mode)
{
	if (fd < 0) return -1;
	int flags = fcntl(fd, F_GETFL, 0);
	if (flags == -1) return -1;
	flags = (mode == BLOCKING) ? (flags & ~O_NONBLOCK) : (flags | O_NONBLOCK);
	return (fcntl(fd, F_SETFL, flags) == 0) ? 0 : -1;
}

int init_bind_socket(char* name, char* port, int mode) {

	int sockfd = -1;
	int yes=1;
	struct addrinfo *servinfo = NULL, *p = NULL;

	if (0 == get_addrinfo(name, port, &servinfo, SOCK_STREAM_AF_UNSPEC)) {
		// loop through all the results and bind to the first we can
		for(p = servinfo; p != NULL; p = p->ai_next) {
			if ((sockfd = socket(p->ai_family, p->ai_socktype,
					p->ai_protocol)) == -1) {
				perror("server: socket");
				continue;
			}

			if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes,
					sizeof(int)) == -1) {
				perror("setsockopt");
				close(sockfd);
				sockfd = -1;
				continue;
			}

			if (mode == NON_BLOCKING) {

				if (set_socket_blocking_mode(sockfd, NON_BLOCKING) < 0)
				{
					perror("Can't set nonblocking: ioctl() failed");
					sockfd = -1;
					continue;
				}

			}

			if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
				perror("server: bind");
				close(sockfd);
				sockfd = -1;
				continue;
			}

			break;
		}
	}

	freeaddrinfo(servinfo);

	return sockfd;
}

// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
	if (sa->sa_family == AF_INET) {
		return &(((struct sockaddr_in*)sa)->sin_addr);
	}

	return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

void chld_handler(int s)
{
	// waitpid() might overwrite errno, so we save and restore it:
	int saved_errno = errno;
	fprintf(stderr, "chld_handler\n");
	while(waitpid(-1, NULL, WNOHANG) > 0);

	errno = saved_errno;
	fprintf(stderr, "exit-->chld_handler\n");
	exit(0);
}

#define BACKLOG 10     // how many pending connections queue will hold

void test_server(char* name, char* port) {
	int sockfd = init_bind_socket(name, port, BLOCKING);
	struct sockaddr_storage their_addr; // connector's address information
	socklen_t sin_size;
	struct sigaction sa;
	int new_fd;
	char s[INET6_ADDRSTRLEN];

	if (listen(sockfd, BACKLOG) == -1) {
		perror("listen");
		exit(1);
	}
#if 1
	sa.sa_handler = chld_handler; // reap all dead processes
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;
	if (sigaction(SIGINT, &sa, NULL) == -1) {
		perror("sigaction");
		exit(1);
	}


#endif
	printf("server: waiting for connections...\n");

	while(1) {  // main accept() loop
		sin_size = sizeof their_addr;
		new_fd = accept(sockfd, (struct sockaddr *)&their_addr, &sin_size);
		if (new_fd == -1) {
			perror("accept");
			continue;
		}

		inet_ntop(their_addr.ss_family,
				get_in_addr((struct sockaddr *)&their_addr),
				s, sizeof s);
		printf("server: got connection from %s\n", s);

		if (!fork()) { // this is the child process
			close(sockfd); // child doesn't need the listener
			static int run = 1;
#if 1
			void end_handler(int s)
			{
				sleep(10);
				fprintf(stderr, "exit-->\n");

				run = 0;
			}
			perror("start new proc");
			sa.sa_handler = end_handler;
			sigemptyset(&sa.sa_mask);
			sa.sa_flags = SA_RESTART;
			if (sigaction(SIGINT, &sa, NULL) == -1) {
				perror("sigaction");
				exit(1);
			}
#endif

			while(run) {
				if (send(new_fd, "Hello, world!", 13, 0) == -1)
					perror("send");
				sleep(2);
			}
			close(new_fd);
			exit(0);
		}
		close(new_fd);  // parent doesn't need this
	}
}

void test_client() {

}

typedef struct{
	char ip_addr[INET6_ADDRSTRLEN];
	char port[MAX_PORT_CHARS];
}reg_info_t;

typedef struct {

}result_t;

typedef union {
	reg_info_t reg;
	result_t result;
}ctrl_data_packet_t;

typedef enum {
	STOP,
	RUN_PING = 0x5,
	REGISTER_CLIENT,
	START_MULTICAST_SERVER,
	START_MULTICAST_CLIENT,
	ACCEPT,
	REJECT,
	RESULT
}ctrl_commands_t;

typedef struct {
	uint32_t packet_len;
	uint16_t command;
	ctrl_data_packet_t data;
}ctr_packet_t;

typedef enum{
	INITIAL,
	WAIT_CONNECTIONS,
	RUN_TEST,
	TEST_FINISHED
}master_state_t;

typedef enum{
	INITIALIZATION,
	BUSSY,
	ERROR,
	FINISHED
}test_state_t;

typedef struct {
	int t_id;
	int* nodes;
	int required_nodes;
	const char* desc;
	test_state_t state;
}test_context_t;

typedef test_state_t (*test_hndl)(test_context_t* desc);

typedef struct {
	test_context_t context;
	test_hndl hndl;
} test_descriptor_t;



test_state_t test1(test_context_t* desc){
	switch(desc->state){
	case INITIALIZATION:{
		desc->state = BUSSY;
		break;
	}
	case BUSSY:{
		desc->state = ERROR;
		break;
	}
	case ERROR:{
		desc->state = FINISHED;
		break;
	}
	case FINISHED:{
		desc->state = FINISHED;
		break;
	}
	}
	printf("%s  state %d\n", __func__, desc->state);
	return desc->state;
}

test_state_t test2(test_context_t* desc){
	switch(desc->state){
	case INITIALIZATION:{
		desc->state = BUSSY;
		break;
	}
	case BUSSY:{
		desc->state = ERROR;
		break;
	}
	case ERROR:{
		desc->state = FINISHED;
		break;
	}
	case FINISHED:{
		desc->state = FINISHED;
		break;
	}
	}
	printf("%s  state %d\n", __func__, desc->state);
	return desc->state;
}

test_state_t test3(test_context_t* desc){
	switch(desc->state){
	case INITIALIZATION:{
		desc->state = BUSSY;
		break;
	}
	case BUSSY:{
		desc->state = ERROR;
		break;
	}
	case ERROR:{
		desc->state = FINISHED;
		break;
	}
	case FINISHED:{
		desc->state = FINISHED;
		break;
	}
	}
	printf("%s  state %d\n", __func__, desc->state);
	return desc->state;
}

test_state_t test4(test_context_t* desc){
	switch(desc->state){
	case INITIALIZATION:{
		desc->state = BUSSY;
		break;
	}
	case BUSSY:{
		desc->state = ERROR;
		break;
	}
	case ERROR:{
		desc->state = FINISHED;
		break;
	}
	case FINISHED:{
		desc->state = FINISHED;
		break;
	}
	}
	printf("%s  state %d\n", __func__, desc->state);
	return desc->state;
}

#define CONTEXT_CREATION
#include"test_cfg.h"

test_descriptor_t test_descs[] = {
#define TEST_DESCRIPTORS
#include"test_cfg.h"
};


#define INITIAL_TIMEOUT         (0)
#define TESTS_BEGIN_TIMEOUT

void test_master ()
{
	int    len, rc, rc_poll;
	int    listen_sd = -1, new_sd = -1;
	int    end_server = FALSE, compress_array = FALSE;
	int    close_conn;
	char   buffer[80];
	int    timeout;
	struct pollfd fds[MAX_CONNECTIONS];
	int    nfds = 1, current_size = 0, i, j;
	static uint32_t state = INITIAL;
	int test_counter = 0;

	/* Create an socket to receive incoming connections          */
	listen_sd = init_bind_socket(NULL, MASTER_PORT, NON_BLOCKING);

	if (listen_sd < 0)
	{
		perror("socket() failed");
		exit(-1);
	}

	rc = listen(listen_sd, 32);
	if (rc < 0)
	{
		perror("listen() failed");
		close(listen_sd);
		exit(-1);
	}

	memset(fds, 0 , sizeof(fds));

	/* Set up the initial listening socket                        */
	fds[0].fd = listen_sd;
	fds[0].events = POLLIN;

	/* Initialize the timeout*/
	timeout = INITIAL_TIMEOUT;

	/* Loop waiting for incoming connects or for incoming data */
	do
	{
		/* Call poll() with timeout */
		printf("Waiting on poll()...\n");
		rc_poll = poll(fds, nfds, timeout);

		/* Check to see if the poll call failed. */
		if (rc_poll < 0)
		{
			perror("  poll() failed");
			break;
		}

		/* Check to see if the time out expired. */
		if (rc_poll != 0) {

			/* One or more descriptors are readable.  Need to          */
			/* determine which ones they are.                          */
			current_size = nfds;
			for (i = 0; i < current_size; i++)
			{
				/* Loop through to find the descriptors that returned    */
				/* POLLIN and determine whether it's the listening       */
				/* or the active connection.                             */
				if(fds[i].revents == 0)
					continue;

				/* If revents is not POLLIN, it's an unexpected result,  */
				/* log and end the server.                               */
				if(fds[i].revents != POLLIN)
				{
					printf("  Error! revents = %d\n", fds[i].revents);
					end_server = TRUE;
					break;

				}
				if (fds[i].fd == listen_sd)
				{
					/* Listening descriptor is readable.                   */
					printf("  Listening socket is readable\n");

					/* Accept all incoming connections that are            */
					/* queued up on the listening socket before we         */
					/* loop back and call poll again.                      */
					do
					{
						/* Accept each incoming connection. */
						new_sd = accept(listen_sd, NULL, NULL);
						if (new_sd < 0)
						{
							if (errno != EWOULDBLOCK)
							{
								perror("  accept() failed");
								end_server = TRUE;
							}
							break;
						}

						if(nfds >= MAX_CONNECTIONS) {
							perror("Can't  accept() connection: maximum allowed reached");
							close(new_sd);
							continue;
						}

						set_socket_blocking_mode(new_sd, NON_BLOCKING);

						/* Add descriptor to poll*/
						printf("  New incoming connection - %d\n", new_sd);
						fds[nfds].fd = new_sd;
						fds[nfds].events = POLLIN;
						nfds++;

					} while (new_sd != -1);

				}
				/* This is not the listening socket, therefore an        */
				/* existing connection must be readable                  */
				else
				{
					printf("  Descriptor %d is readable\n", fds[i].fd);
					close_conn = FALSE;

					/* Receive all incoming data on this socket            */
					/* before we loop back and call poll again.            */
					do
					{
						/* Receive data on this connection until the         */
						/* recv fails with EWOULDBLOCK. If any other         */
						/* failure occurs, we will close the                 */
						/* connection.                                       */
						rc = recv(fds[i].fd, buffer, sizeof(buffer), 0);
						if (rc < 0)
						{
							if (errno != EWOULDBLOCK)
							{
								perror("  recv() failed");
								close_conn = TRUE;
							}
							break;
						}

						/* Check to see if the connection has been           */
						/* closed by the client                              */
						if (rc == 0)
						{
							printf("  Connection closed\n");
							close_conn = TRUE;
							break;
						}

						/* Data was received                                 */
						len = rc;
						printf("  %d bytes received\n", len);


						rc = send(fds[i].fd, buffer, len, 0);
						if (rc < 0)
						{
							perror("  send() failed");
							close_conn = TRUE;
							break;
						}

					} while(TRUE);

					/*******************************************************/
					/* If the close_conn flag was turned on, we need       */
					/* to clean up this active connection. This            */
					/* clean up process includes removing the              */
					/* descriptor.                                         */
					/*******************************************************/
					if (close_conn)
					{
						close(fds[i].fd);
						fds[i].fd = -1;
						compress_array = TRUE;
					}


				}  /* End of existing connection is readable             */
			} /* End of loop through pollable descriptors              */
		}

		switch(state) {

		case INITIAL: {

			if (test_counter >= sizeof(test_descs)/sizeof(test_descs[0])) {
				printf("All test are executed. End program.\n");
				end_server = TRUE;
			}
			else {
				timeout = 10000;
				if(nfds >= test_descs[test_counter].context.required_nodes) {
					int i;
					//set test context
					for (i=0; i < test_descs[test_counter].context.required_nodes; i++) {
						test_descs[test_counter].context.nodes[i] = fds[i + 1].fd;
						//		assert(test_descs[test_counter].context.nodes[i] != -1);
					}
					state = RUN_TEST;
				}
				else {
					state = WAIT_CONNECTIONS;
				}
			}
			break;
		}
		case WAIT_CONNECTIONS: {
			if (rc_poll == 0) {
				printf("  poll() timed out in state %d test id %d.  End program.\n",
									   state, test_descs[test_counter].context.t_id);
				end_server = TRUE;
				break;
			}
			if(nfds >= test_descs[test_counter].context.required_nodes) {
				int i;
				//set test context
				for (i=0; i < test_descs[test_counter].context.required_nodes; i++) {
					test_descs[test_counter].context.nodes[i] = fds[i + 1].fd;
					//		assert(test_descs[test_counter].context.nodes[i] != -1);
				}
				state = RUN_TEST;
			}
			break;
		}
		case RUN_TEST:{
			if (rc_poll == 0) {
				printf("  poll() timed out in state %d test id %d.  End program.\n",
					   state, test_descs[test_counter].context.t_id);
				end_server = TRUE;
				break;
			}
			if( FINISHED == test_descs[test_counter].hndl(&test_descs[test_counter].context) ){
				timeout = INITIAL_TIMEOUT;
				test_counter++;
				state = TEST_FINISHED;
			}
			break;
		}
		case TEST_FINISHED:{
			state   = INITIAL;
			timeout = INITIAL_TIMEOUT;
			break;
		}

		default: {
			printf("Error: Wrong state %d.  End program.\n", state);
			end_server = TRUE;
		}
		}

		printf(" state %d\n", state);

		/* If the compress_array flag was turned on, we need       */
		/* to squeeze together the array and decrement the number  */
		/* of file descriptors. We do not need to move back the    */
		/* events and revents fields because the events will always*/
		/* be POLLIN in this case, and revents is output.          */
		if (compress_array)
		{
			compress_array = FALSE;
			for (i = 0; i < nfds; i++)
			{
				if (fds[i].fd == -1)
				{
					for(j = i; j < nfds; j++)
					{
						fds[j].fd = fds[j+1].fd;
					}
					i--;
					nfds--;
				}
			}
		}

	} while (end_server == FALSE); /* End of serving running.    */

	/*************************************************************/
	/* Clean up all of the sockets that are open                 */
	/*************************************************************/
	for (i = 0; i < nfds; i++)
	{
		if(fds[i].fd >= 0)
			close(fds[i].fd);
	}
}

int main(int argc, char *argv[])
{
	if(argc > 2) {
		test_client();
	}
	else {
		test_master();
	}
	return 0;
}
